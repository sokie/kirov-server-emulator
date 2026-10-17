"""
Query Master Parsing and Response Building.

Handles parsing of TCP query requests and building responses for
room lists and game lists in the GameSpy master server protocol.
"""

import re
import socket
import struct
from dataclasses import dataclass, field

from app.util.logging_helper import get_logger

logger = get_logger(__name__)


# =============================================================================
# Constants
# =============================================================================

ROOM_MARKER = 0x40  # '@' - room entry marker
END_MARKER = b"\xff\xff\xff\xff"

# Server list request options.
SEND_FIELDS_FOR_ALL = 0x01
NO_SERVER_LIST = 0x02
PUSH_UPDATES = 0x04
LIMIT_RESULT_COUNT = 0x80

# Client to master messages on the query connection.
SERVER_LIST_REQUEST = 0
SERVER_INFO_REQUEST = 1
SEND_MESSAGE_REQUEST = 2
KEEPALIVE_REPLY = 3

# Master to client messages after the first list.
PUSH_KEYS_MESSAGE = 1
PUSH_SERVER_MESSAGE = 2
KEEPALIVE_MESSAGE = 3
DELETE_SERVER_MESSAGE = 4

# The client drops the connection on a longer message.
MAX_PUSH_MESSAGE = 0x1000

# Server entry flags.
PRIVATE_IP_FLAG = 0x02
CONNECT_NEGOTIATE_FLAG = 0x04
ICMP_IP_FLAG = 0x08
NONSTANDARD_PORT_FLAG = 0x10
NONSTANDARD_PRIVATE_PORT_FLAG = 0x20
HAS_KEYS_FLAG = 0x40
HAS_FULL_RULES_FLAG = 0x80
ADDRESS_FLAGS = (
    PRIVATE_IP_FLAG | CONNECT_NEGOTIATE_FLAG | ICMP_IP_FLAG | NONSTANDARD_PORT_FLAG | NONSTANDARD_PRIVATE_PORT_FLAG
)

# Heartbeat keys that stay out of a full-rules entry.
HIDDEN_RULES = frozenset({"statechanged"})

# Default master server IP (will be overridden by actual server IP)
DEFAULT_MASTER_IP = "0.0.0.0"
DEFAULT_MASTER_PORT = 0


# =============================================================================
# Data Classes
# =============================================================================


@dataclass
class QueryRequest:
    """Parsed TCP query request from a game client."""

    length: int = 0
    header: bytes = b""
    game_name: str = ""
    game_name2: str = ""
    validate_token: bytes = b""
    filter_string: str = ""
    fields: list = field(default_factory=list)
    options: int = 0
    tail: bytes = b""
    raw_data: bytes = b""


@dataclass
class RoomEntry:
    """Represents a room/lobby in the room list."""

    room_id: int
    hostname: str
    numwaiting: int = 0
    maxwaiting: int = 200
    numservers: int = 0
    numplayers: int = 0
    room_type: int = 1

    def get_field_value(self, field_name: str) -> str:
        """Get field value as string for wire format."""
        field_map = {
            "hostname": self.hostname,
            "numwaiting": str(self.numwaiting),
            "maxwaiting": str(self.maxwaiting),
            "numservers": str(self.numservers),
            "numplayers": str(self.numplayers),
            "roomType": str(self.room_type),
        }
        return field_map.get(field_name, "")


@dataclass
class GameEntry:
    """Represents a game session in the game list."""

    public_ip: str
    public_port: int
    private_ip: str
    private_port: int
    traced_ip: str | None = None
    traced_port: int | None = None
    fields: dict = field(default_factory=dict)

    def __post_init__(self):
        if self.traced_ip is None:
            self.traced_ip = self.public_ip
        if self.traced_port is None:
            self.traced_port = self.public_port

    def get_field_value(self, field_name: str) -> str:
        """Get field value as string for wire format."""
        return str(self.fields.get(field_name, ""))


# =============================================================================
# Filter Parsing
# =============================================================================


def parse_filter_string(filter_str: str):
    """
    Parses a filter string like "(key=value) AND (key2 != 'value2') OR (key3=3)" into a
    structured list of conditions, supporting both AND and OR (flat, not nested).

    Args:
        filter_str: The filter string to parse.

    Returns:
        A list of dictionaries, where each dictionary represents a condition and its logic operator.
        Example: [
            {'field': 'groupid', 'operator': '=', 'value': 2166, 'logic': None},
            {'field': 'gamemode', 'operator': '!=', 'value': 'closedplaying', 'logic': 'AND'},
            {'field': 'foo', 'operator': '=', 'value': 1, 'logic': 'OR'}
        ]
    """
    if not filter_str:
        return []

    conditions = []
    # Improved regex: handles quoted and unquoted values, and ignores parentheses
    condition_pattern = re.compile(r"\(?\s*(\w+)\s*(!=|==|=|<|>|<=|>=)\s*'?(.*?)'?\s*\)?$")

    # Split by AND/OR, keeping the operators
    tokens = re.split(r"\)\s*(AND|OR)\s*\(", filter_str.strip())
    # tokens will be like: [cond1, op1, cond2, op2, cond3, ...]

    logic = None
    for i, token in enumerate(tokens):
        if i % 2 == 0:  # condition
            part = token.strip().lstrip("(").rstrip(")")
            if not part:
                continue
            match = condition_pattern.search(part)
            if match:
                key, operator, value = match.groups()
                # Attempt to convert value to a number (int or float)
                try:
                    if "." in value:
                        parsed_value = float(value)
                    else:
                        parsed_value = int(value)
                except ValueError:
                    parsed_value = value.strip("'")
                conditions.append(
                    {
                        "field": key,
                        "operator": operator,
                        "value": parsed_value,
                        "logic": logic,
                    }
                )
        else:  # logic operator
            logic = token.strip().upper()
    return conditions


def generate_sql_where_clause(filters: list):
    """
    Generates a SQL WHERE clause from the parsed filter conditions with logic operators.

    Args:
        filters: A list of filter conditions from parse_filter_string with logic operators.

    Returns:
        A string containing the SQL WHERE clause.

    NOTE: This is for demonstration and is NOT safe from SQL injection.
          Use parameterized queries in a real application.
    """
    if not filters:
        return ""

    clauses = []
    for f in filters:
        field = f["field"]
        op = f["operator"]
        value = f["value"]
        logic = f.get("logic", None)

        # Quote string values for SQL, leave numbers as-is
        sql_value = f"'{value}'" if isinstance(value, str) else str(value)

        # Build the condition clause
        condition_clause = f"`{field}` {op} {sql_value}"

        # Add logic operator if present
        if logic:
            clauses.append(f"{logic} {condition_clause}")
        else:
            clauses.append(condition_clause)

    return "WHERE " + " ".join(clauses)


def apply_filters_to_dict(servers: list, filters: list):
    """
    Filters a list of dictionaries (representing servers) based on the
    parsed filter conditions.

    Args:
        servers: A list of dictionaries to filter.
        filters: A list of filter conditions from parse_filter_string.

    Returns:
        A new list containing only the servers that match the filters.
    """
    if not filters:
        return servers

    filtered_list = []
    for server in servers:
        matches_all_conditions = True
        for f in filters:
            field = f["field"]
            op = f["operator"]
            value = f["value"]

            # If the server doesn't have the field, it's not a match.
            if field not in server:
                matches_all_conditions = False
                break

            server_value = server[field]

            # Check the condition based on the operator
            is_match = False
            if op == "=" and server_value == value or op == "!=" and server_value != value:
                is_match = True
            # Note: More operators like '>', '<', etc. could be added here.

            if not is_match:
                matches_all_conditions = False
                break

        if matches_all_conditions:
            filtered_list.append(server)

    return filtered_list


# =============================================================================
# TCP Request Parser
# =============================================================================


def parse_tcp_query(data: bytes) -> QueryRequest:
    """
    Parse a TCP query request from a game client.

    TCP request structure:
        u16be  length
        6B     unknown header
        u8     0x00 (separator)
        str0   gameName
        str0   gameName2 (often same as gameName)
        8B     validate token
        str0   request string (filter, e.g., "(groupid=2167) AND ...")
        str0   fields string (e.g., "\\hostname\\mapname\\numplayers")
        u32be  options (PUSH_UPDATES and others)
        bytes  tail

    Args:
        data: Raw TCP data from client

    Returns:
        QueryRequest object with parsed fields
    """
    request = QueryRequest(raw_data=data)

    if len(data) < 2:
        logger.warning("TCP query too short: %d bytes", len(data))
        return request

    # Parse length (first 2 bytes, big-endian)
    request.length = struct.unpack("!H", data[0:2])[0]

    # Extract header (bytes 2-7, 6 bytes)
    if len(data) >= 8:
        request.header = data[2:8]

    # Find null-terminated strings after header
    # Skip header (8 bytes) and separator (1 byte = 0x00)
    pos = 8
    if len(data) > pos and data[pos] == 0x00:
        pos += 1

    # Parse first game name (null-terminated)
    game_name_end = data.find(b"\x00", pos)
    if game_name_end != -1:
        request.game_name = data[pos:game_name_end].decode("utf-8", errors="ignore")
        pos = game_name_end + 1

    # Parse second game name (null-terminated)
    game_name2_end = data.find(b"\x00", pos)
    if game_name2_end != -1:
        request.game_name2 = data[pos:game_name2_end].decode("utf-8", errors="ignore")
        pos = game_name2_end + 1

    # Parse validate token (8 bytes)
    if len(data) >= pos + 8:
        request.validate_token = data[pos : pos + 8]
        pos += 8

    # Parse filter string (null-terminated)
    filter_end = data.find(b"\x00", pos)
    if filter_end != -1:
        request.filter_string = data[pos:filter_end].decode("utf-8", errors="ignore")
        pos = filter_end + 1

    # Parse fields string (null-terminated, backslash-delimited)
    fields_end = data.find(b"\x00", pos)
    if fields_end != -1:
        fields_str = data[pos:fields_end].decode("utf-8", errors="ignore")
        # Parse backslash-delimited fields like "\hostname\mapname\numplayers"
        request.fields = [f for f in fields_str.split("\\") if f]
        pos = fields_end + 1

    if len(data) >= pos + 4:
        request.options = struct.unpack("!I", data[pos : pos + 4])[0]
        pos += 4

    # Remaining bytes are tail
    request.tail = data[pos:]

    logger.debug(
        "Parsed TCP query: game=%s, filter=%s, fields=%s, options=0x%x",
        request.game_name,
        request.filter_string,
        request.fields,
        request.options,
    )

    return request


def is_room_list_request(request: QueryRequest) -> bool:
    """
    Determine if a request is for the room list (lobbies) or game list (matches).

    Room list requests have fields like: hostname, numwaiting, maxwaiting, numservers, numplayers, roomType
    Game list requests have fields like: hostname, gamemode, mapname, vCRC, iCRC, etc.

    The key differentiator is that room list requests include 'numwaiting' and 'roomType' fields.
    """
    # Room list specific fields that don't appear in game list requests
    room_specific_fields = {"numwaiting", "maxwaiting", "roomType"}
    return bool(room_specific_fields & set(request.fields))


# =============================================================================
# Binary Encoding Helpers
# =============================================================================


def ip_to_bytes(ip: str) -> bytes:
    """Convert IP address string to 4 bytes."""
    return socket.inet_aton(ip)


def bytes_to_ip(data: bytes) -> str:
    """Convert 4 bytes to IP address string."""
    return socket.inet_ntoa(data)


def make_field_list(fields: list, field_types: dict | None = None) -> bytes:
    """
    Build a field list for the response header.

    Format:
        u8     fieldCount
        repeat fieldCount times:
            u8    fieldType (0=string, 1=u8 immediate)
            str0  fieldName

    Args:
        fields: List of field names
        field_types: Optional dict mapping field name to type (0 or 1)

    Returns:
        Encoded field list bytes
    """
    if field_types is None:
        field_types = {}

    result = struct.pack("B", len(fields))

    for field_name in fields:
        field_type = field_types.get(field_name, 0)  # Default to string type
        result += struct.pack("B", field_type)
        result += field_name.encode("utf-8") + b"\x00"

    return result


def encode_field_value_classic(value: str) -> bytes:
    """
    Encode a field value in classic format: 0xFF + value bytes + 0x00

    Args:
        value: String value to encode

    Returns:
        Encoded bytes
    """
    return b"\xff" + value.encode("utf-8") + b"\x00"


# =============================================================================
# Room List Response Builder
# =============================================================================


def build_room_list_response(
    rooms: list,
    fields: list,
    client_ip: str = DEFAULT_MASTER_IP,
) -> bytes:
    """
    Build a classic-format room list response.

    Response structure:
        ip4     clientIp (echoed back to client)
        u16be   0x0000 (port 0 for room list)
        fieldList
        u8      0x00
        [roomEntryClassic]...
        u8      0x00
        u8x4    0xFF 0xFF 0xFF 0xFF (end marker)

    Room entry structure:
        u8      0x40 '@' (room marker)
        u32be   roomId
        repeat for each field:
            u8 0xFF + str bytes + u8 0x00

    Args:
        rooms: List of RoomEntry objects
        fields: List of field names to include
        client_ip: Client's IP address (echoed back in response)

    Returns:
        Complete response bytes
    """
    response = b""

    # Client IP echoed back (4 bytes)
    response += ip_to_bytes(client_ip)

    # Port 0 for room list (2 bytes big-endian)
    response += struct.pack("!H", 0)

    # Field list
    response += make_field_list(fields)

    # Separator
    response += b"\x00"

    # Room entries
    for room in rooms:
        # Room marker '@'
        response += struct.pack("B", ROOM_MARKER)

        # Room ID (4 bytes big-endian)
        response += struct.pack("!I", room.room_id)

        # Field values
        for field_name in fields:
            value = room.get_field_value(field_name)
            response += encode_field_value_classic(value)

    # End marker
    response += b"\x00"
    response += END_MARKER

    logger.debug("Built room list response: %d bytes, %d rooms", len(response), len(rooms))
    return response


# =============================================================================
# Game List Response Builder
# =============================================================================


def _compute_query_key(validate_token: bytes) -> bytes:
    """
    Compute the 2-byte query key from the validate token.

    The real GameSpy server derives bytes 4-5 of the response from the
    validate token using XOR operations. Based on observed traffic:
    - byte0 = validate[0] XOR 0xFC
    - byte1 = validate[1] XOR 0xC9

    Args:
        validate_token: 8-byte validate token from request

    Returns:
        2-byte query key
    """
    if len(validate_token) >= 2:
        key0 = validate_token[0] ^ 0xFC
        key1 = validate_token[1] ^ 0xC9
        return bytes([key0, key1])
    return b"\x00\x00"


def server_rules(game: GameEntry) -> list[tuple[str, str]]:
    """Lists the key/value pairs of a full-rules entry: the server keys, then each player's keys as key_N."""
    rules = [(k, str(v)) for k, v in game.fields.items() if not k.startswith("_") and k not in HIDDEN_RULES]
    for index, player in enumerate(game.fields.get("_players") or []):
        rules.extend((f"{key}_{index}", str(value)) for key, value in player.items())
    return rules


def build_server_entry(game: GameEntry, fields: list, full_rules: bool = False, popular_index: bool = True) -> bytes:
    """
    Builds one server entry: flags, the address tuples, the values of `fields`, then the full rules.

    A list entry puts a popular-string index (0xFF = inline) before each string value; a pushed entry does not.
    """
    flags = ADDRESS_FLAGS | (HAS_KEYS_FLAG if fields else 0) | (HAS_FULL_RULES_FLAG if full_rules else 0)
    entry = struct.pack("B", flags)
    entry += ip_to_bytes(game.public_ip) + struct.pack("!H", game.public_port)
    entry += ip_to_bytes(game.private_ip) + struct.pack("!H", game.private_port)
    entry += ip_to_bytes(game.traced_ip)
    for field_name in fields:
        value = game.get_field_value(field_name).encode("utf-8") + b"\x00"
        entry += b"\xff" + value if popular_index else value
    if full_rules:
        for key, value in server_rules(game):
            entry += key.encode("utf-8") + b"\x00" + value.encode("utf-8") + b"\x00"
        entry += b"\x00"
    return entry


def build_game_list_response(
    games: list,
    fields: list,
    client_ip: str = DEFAULT_MASTER_IP,
    client_port: int = 0,
    full_rules: bool = False,
) -> bytes:
    """
    Build a game list response.

    Response structure:
        ip4     clientIp (echoed back to client)
        u16be   clientPort (echoed back to client)
        fieldList  (all fields declared as type 0 / string)
        u8      number of popular strings (0)
        [server entry]...
        u8      0x00, u8x4 0xFF 0xFF 0xFF 0xFF (end entry)

    Args:
        games: List of GameEntry objects
        fields: List of field names to include
        client_ip: Client's IP address (echoed back in response)
        client_port: Client's source port (echoed back in response)
        full_rules: Add every key of each server, for a request that names no fields

    Returns:
        Complete response bytes
    """
    response = ip_to_bytes(client_ip) + struct.pack("!H", client_port)
    response += make_field_list(fields)
    response += b"\x00"
    for game in games:
        response += build_server_entry(game, fields, full_rules)
    response += b"\x00" + END_MARKER

    logger.debug("Built game list response: %d bytes, %d games, full_rules=%s", len(response), len(games), full_rules)
    return response


def _push_message(msg_type: int, payload: bytes) -> bytes:
    """Frames a master-to-client message: u16be length (with this header), u8 type, payload."""
    message = struct.pack("!HB", len(payload) + 3, msg_type) + payload
    if len(message) > MAX_PUSH_MESSAGE:
        logger.warning("Push message type %d is %d bytes; the client drops longer than 4096", msg_type, len(message))
    return message


def build_push_server_message(game: GameEntry, fields: list, full_rules: bool = False) -> bytes:
    """Builds a PUSH_SERVER message: a server that was added or changed."""
    return _push_message(PUSH_SERVER_MESSAGE, build_server_entry(game, fields, full_rules, popular_index=False))


def build_delete_server_message(game: GameEntry) -> bytes:
    """Builds a DELETE_SERVER message for the server at the entry's public address."""
    return _push_message(DELETE_SERVER_MESSAGE, ip_to_bytes(game.public_ip) + struct.pack("!H", game.public_port))


def build_keepalive_message() -> bytes:
    """Builds a KEEPALIVE message; the client sends it back."""
    return _push_message(KEEPALIVE_MESSAGE, b"")


# =============================================================================
# Per-game room definitions
# =============================================================================
def _create_generals_rooms() -> list:
    return [
        RoomEntry(room_id=392, hostname="QuickMatch", room_type=0),
        RoomEntry(room_id=389, hostname="GroupRoom1", room_type=0),
        RoomEntry(room_id=390, hostname="GroupRoom2", room_type=0),
        RoomEntry(room_id=391, hostname="GroupRoom3", room_type=0),
        RoomEntry(room_id=496, hostname="GroupRoom4", room_type=0),
        RoomEntry(room_id=497, hostname="GroupRoom5", room_type=0),
        RoomEntry(room_id=498, hostname="GroupRoom6", room_type=0),
        RoomEntry(room_id=499, hostname="GroupRoom7", room_type=0),
        RoomEntry(room_id=500, hostname="GroupRoom8", room_type=0),
        RoomEntry(room_id=501, hostname="GroupRoom9", room_type=0),
        RoomEntry(room_id=502, hostname="GroupRoom10", room_type=0),
        RoomEntry(room_id=503, hostname="GroupRoom11", room_type=0),
        RoomEntry(room_id=504, hostname="GroupRoom12", room_type=0),
    ]


def _create_zerohour_rooms() -> list:
    return [
        RoomEntry(room_id=597, hostname="QuickMatch", room_type=0),
        RoomEntry(room_id=571, hostname="GroupRoom1", room_type=0),
        RoomEntry(room_id=586, hostname="GroupRoom2", room_type=0),
        RoomEntry(room_id=587, hostname="GroupRoom3", room_type=0),
        RoomEntry(room_id=588, hostname="GroupRoom4", room_type=0),
        RoomEntry(room_id=589, hostname="GroupRoom5", room_type=0),
        RoomEntry(room_id=590, hostname="GroupRoom6", room_type=0),
        RoomEntry(room_id=591, hostname="GroupRoom7", room_type=0),
        RoomEntry(room_id=592, hostname="GroupRoom8", room_type=0),
        RoomEntry(room_id=593, hostname="GroupRoom9", room_type=0),
        RoomEntry(room_id=594, hostname="GroupRoom10", room_type=0),
        RoomEntry(room_id=595, hostname="GroupRoom11", room_type=0),
        RoomEntry(room_id=596, hostname="GroupRoom12", room_type=0),
        RoomEntry(room_id=598, hostname="GroupRoom13", room_type=0),
        RoomEntry(room_id=602, hostname="GroupRoom14", room_type=0),
    ]


def _create_cnc3_rooms() -> list:
    return [
        RoomEntry(room_id=1901, hostname="QuickMatch", room_type=0),
        RoomEntry(room_id=1902, hostname="ChatRoom1", room_type=2),
        RoomEntry(room_id=2059, hostname="LobbyRoom:1", room_type=1),
        RoomEntry(room_id=2060, hostname="LobbyRoom:2", room_type=1),
        RoomEntry(room_id=2061, hostname="LobbyRoom:3", room_type=1),
        RoomEntry(room_id=2062, hostname="LobbyRoom:4", room_type=1),
        RoomEntry(room_id=2063, hostname="LobbyRoom:5", room_type=1),
        RoomEntry(room_id=2064, hostname="LobbyRoom:6", room_type=1),
        RoomEntry(room_id=2065, hostname="LobbyRoom:7", room_type=1),
        RoomEntry(room_id=2066, hostname="LobbyRoom:8", room_type=1),
        RoomEntry(room_id=2067, hostname="LobbyRoom:9", room_type=1),
        RoomEntry(room_id=2068, hostname="LobbyRoom:10", room_type=1),
        RoomEntry(room_id=2069, hostname="LobbyRoom:11", room_type=1),
        RoomEntry(room_id=2070, hostname="LobbyRoom:12", room_type=1),
        RoomEntry(room_id=2071, hostname="LobbyRoom:13", room_type=1),
        RoomEntry(room_id=2072, hostname="LobbyRoom:14", room_type=1),
        RoomEntry(room_id=2073, hostname="LobbyRoom:15", room_type=1),
        RoomEntry(room_id=2074, hostname="LobbyRoom:16", room_type=1),
        RoomEntry(room_id=2081, hostname="LobbyBattlecast:1", room_type=1),
        RoomEntry(room_id=2075, hostname="LobbyBeginners:1", room_type=1),
        RoomEntry(room_id=2077, hostname="LobbyClan:1", room_type=1),
        RoomEntry(room_id=2078, hostname="LobbyClan:2", room_type=1),
        RoomEntry(room_id=2084, hostname="LobbyCompStomp:1", room_type=1),
        RoomEntry(room_id=2082, hostname="LobbyCustomMap:1", room_type=1),
        RoomEntry(room_id=2083, hostname="LobbyCustomMap:2", room_type=1),
        RoomEntry(room_id=2076, hostname="LobbyHardcore:1", room_type=1),
        RoomEntry(room_id=2079, hostname="LobbyTournaments:1", room_type=1),
        RoomEntry(room_id=2080, hostname="LobbyTournaments:2", room_type=1),
        RoomEntry(room_id=2088, hostname="LobbyFrench:1", room_type=1),
        RoomEntry(room_id=2085, hostname="LobbyGerman:1", room_type=1),
        RoomEntry(room_id=2086, hostname="LobbyGerman:2", room_type=1),
        RoomEntry(room_id=2087, hostname="LobbyKorean:1", room_type=1),
    ]


def _create_kw_rooms() -> list:
    return [
        RoomEntry(room_id=2156, hostname="QuickMatch", room_type=0),
        RoomEntry(room_id=2157, hostname="LobbyRoom:1", room_type=1),
        RoomEntry(room_id=2158, hostname="ChatRoom1", room_type=2),
        RoomEntry(room_id=2265, hostname="Russia:1", room_type=1),
    ]


def _create_ra3_rooms() -> list:
    return [
        RoomEntry(room_id=2177, hostname="ChatRoom1", room_type=1),
        RoomEntry(room_id=2198, hostname="ChatRoom1", room_type=2),
        RoomEntry(room_id=2166, hostname="LobbyRoom:1", room_type=1),
        RoomEntry(room_id=2167, hostname="LobbyRoom:2", room_type=1),
        RoomEntry(room_id=2168, hostname="LobbyRoom:3", room_type=1),
        RoomEntry(room_id=2169, hostname="LobbyRoom:4", room_type=1),
        RoomEntry(room_id=2170, hostname="LobbyRoom:5", room_type=1),
        RoomEntry(room_id=2176, hostname="LobbyRoom:6", room_type=1),
        RoomEntry(room_id=2180, hostname="LobbyRoom:7", room_type=1),
        RoomEntry(room_id=2178, hostname="LobbyRoom:8", room_type=1),
        RoomEntry(room_id=2181, hostname="LobbyRoom:9", room_type=1),
        RoomEntry(room_id=2183, hostname="LobbyRoom:10", room_type=1),
        RoomEntry(room_id=2179, hostname="LobbyRoom:11", room_type=1),
        RoomEntry(room_id=2182, hostname="LobbyRoom:12", room_type=1),
        RoomEntry(room_id=2185, hostname="LobbyRoom:13", room_type=1),
        RoomEntry(room_id=2187, hostname="LobbyRoom:14", room_type=1),
        RoomEntry(room_id=2189, hostname="LobbyRoom:15", room_type=1),
        RoomEntry(room_id=2188, hostname="LobbyRoom:16", room_type=1),
        RoomEntry(room_id=2339, hostname="LobbyRoom:17", room_type=1),
        RoomEntry(room_id=2340, hostname="LobbyRoom:18", room_type=1),
        RoomEntry(room_id=2341, hostname="LobbyRoom:19", room_type=1),
        RoomEntry(room_id=2342, hostname="LobbyRoom:20", room_type=1),
        RoomEntry(room_id=2343, hostname="LobbyRoom:21", room_type=1),
        RoomEntry(room_id=2344, hostname="LobbyCoop:1", room_type=1),
        RoomEntry(room_id=2345, hostname="LobbyCoop:2", room_type=1),
        RoomEntry(room_id=2346, hostname="LobbyCoop:3", room_type=1),
        RoomEntry(room_id=2347, hostname="LobbyCoop:4", room_type=1),
        RoomEntry(room_id=2348, hostname="LobbyCoop:5", room_type=1),
        RoomEntry(room_id=2184, hostname="LobbyClan:1", room_type=1),
        RoomEntry(room_id=2186, hostname="LobbyClan:2", room_type=1),
        RoomEntry(room_id=2191, hostname="LobbyTournaments:1", room_type=1),
        RoomEntry(room_id=2196, hostname="LobbyTournaments:2", room_type=1),
        RoomEntry(room_id=2192, hostname="LobbyCompStomp:1", room_type=1),
        RoomEntry(room_id=2194, hostname="LobbyCustomMap:1", room_type=1),
        RoomEntry(room_id=2195, hostname="LobbyCustomMap:2", room_type=1),
        RoomEntry(room_id=2190, hostname="LobbyBeginners:1", room_type=1),
        RoomEntry(room_id=2193, hostname="LobbyHardcore:1", room_type=1),
        RoomEntry(room_id=2175, hostname="LobbyBattlecast:1", room_type=1),
        RoomEntry(room_id=2174, hostname="LobbyGerman:1", room_type=1),
        RoomEntry(room_id=2173, hostname="LobbyGerman:2", room_type=1),
        RoomEntry(room_id=2172, hostname="LobbyFrench:1", room_type=1),
        RoomEntry(room_id=2171, hostname="LobbyKorean:1", room_type=1),
        RoomEntry(room_id=2349, hostname="LobbyRussian:1", room_type=1),
        RoomEntry(room_id=2350, hostname="LobbyTaiwan:1", room_type=1),
        RoomEntry(room_id=2357, hostname="LobbySpanish:1", room_type=1),
    ]


def create_rooms_by_game() -> dict[str, list]:
    """
    Create room lists for all games, keyed by GameSpy game name.

    Returns:
        Dict mapping GameSpy game name to list of RoomEntry objects.
    """
    return {
        "ccgenerals": _create_generals_rooms(),
        "ccgenzh": _create_zerohour_rooms(),
        "cc3tibwars": _create_cnc3_rooms(),
        "cc3xp1": _create_kw_rooms(),
        "redalert3pc": _create_ra3_rooms(),
    }


def create_default_rooms() -> list:
    """Create default room list for Red Alert 3 (backward compatibility)."""
    return _create_ra3_rooms()
