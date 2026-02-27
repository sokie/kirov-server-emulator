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

RESULT_TYPE_FULL = 0x7E  # '~' - full result with all IP tuples
ROOM_MARKER = 0x40  # '@' - room entry marker
END_MARKER = b"\xff\xff\xff\xff"

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

    # Remaining bytes are tail
    request.tail = data[pos:]

    logger.debug(
        "Parsed TCP query: game=%s, filter=%s, fields=%s",
        request.game_name,
        request.filter_string,
        request.fields,
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


def build_game_list_response(
    games: list,
    fields: list,
    client_ip: str = DEFAULT_MASTER_IP,
    validate_token: bytes = b"",
    field_types: dict | None = None,
) -> bytes:
    """
    Build a classic-format game list response.

    Response structure:
        ip4     clientIp (echoed back to client)
        u16be   queryKey (derived from validate token)
        fieldList
        u8      0x00
        [gameEntryClassic]...
        u8x4    0xFF 0xFF 0xFF 0xFF (end marker)

    Game entry structure:
        u8      '~' (0x7E) resultType
        ip4     publicIp
        u16be   publicPort
        ip4     privateIp
        u16be   privatePort
        ip4     tracedIp
        repeat for each field:
            u8 0xFF + str bytes + u8 0x00
        u8      0x00 (end of entry)

    Args:
        games: List of GameEntry objects
        fields: List of field names to include
        client_ip: Client's IP address (echoed back in response)
        validate_token: 8-byte validate token from request (used to derive query key)
        field_types: Optional dict mapping field name to type (0=string, 1=binary)

    Returns:
        Complete response bytes
    """
    response = b""

    # Client IP echoed back (4 bytes)
    response += ip_to_bytes(client_ip)

    # Query key derived from validate token (2 bytes)
    response += _compute_query_key(validate_token)

    # Field list with per-game types
    response += make_field_list(fields, field_types)

    # Separator
    response += b"\x00"

    # Game entries
    for game in games:
        # Result type '~' for full entry
        response += struct.pack("B", RESULT_TYPE_FULL)

        # Public IP/port
        response += ip_to_bytes(game.public_ip)
        response += struct.pack("!H", game.public_port)

        # Private IP/port
        response += ip_to_bytes(game.private_ip)
        response += struct.pack("!H", game.private_port)

        # Traced IP/port (same as public if not specified)
        response += ip_to_bytes(game.traced_ip)

        # Field values
        for field_name in fields:
            value = game.get_field_value(field_name)
            response += encode_field_value_classic(value)

        # End of entry marker
        response += b"\x00"

    # End marker
    response += b"\x00"
    response += END_MARKER

    logger.debug("Built game list response: %d bytes, %d games", len(response), len(games))
    return response


# =============================================================================
# New Format Response Builders (length-prefixed)
# =============================================================================


def build_value_map_message(fields: list, field_types: dict | None = None) -> bytes:
    """
    Build a VALUE_MAP message (type 0x01) in new format.

    Message structure:
        u16be   length (including these 2 bytes)
        u8      0x01 (VALUE_MAP type)
        fieldList

    Args:
        fields: List of field names
        field_types: Optional dict mapping field name to type (0=string, 1=u8)

    Returns:
        Complete VALUE_MAP message bytes
    """
    payload = struct.pack("B", 0x01)  # Message type
    payload += make_field_list(fields, field_types)

    # Length includes the 2-byte length field itself
    length = len(payload) + 2
    return struct.pack("!H", length) + payload


def build_game_result_message(
    game: GameEntry,
    fields: list,
    field_types: dict | None = None,
) -> bytes:
    """
    Build a GAME_RESULT message (type 0x02) in new format.

    Message structure:
        u16be   length (including these 2 bytes)
        u8      0x02 (GAME_RESULT type)
        u8      resultType ('~')
        ip4     publicIp
        u16be   publicPort
        ip4     privateIp
        u16be   privatePort
        ip4     tracedIp
        repeat for each VALUE_MAP field:
            if type == 0: str0 (null-terminated string)
            if type == 1: u8 (one byte integer)

    Args:
        game: GameEntry object
        fields: List of field names (must match VALUE_MAP order)
        field_types: Dict mapping field name to type

    Returns:
        Complete GAME_RESULT message bytes
    """
    if field_types is None:
        field_types = {}

    payload = b""
    payload += struct.pack("B", 0x02)  # Message type
    payload += struct.pack("B", RESULT_TYPE_FULL)  # Result type '~'

    # IP/port tuples
    payload += ip_to_bytes(game.public_ip)
    payload += struct.pack("!H", game.public_port)
    payload += ip_to_bytes(game.private_ip)
    payload += struct.pack("!H", game.private_port)
    payload += ip_to_bytes(game.traced_ip)

    # Field values based on type
    for field_name in fields:
        value = game.get_field_value(field_name)
        field_type = field_types.get(field_name, 0)

        if field_type == 1:
            # u8 immediate value
            try:
                payload += struct.pack("B", int(value) if value else 0)
            except ValueError:
                payload += struct.pack("B", 0)
        else:
            # Null-terminated string
            payload += value.encode("utf-8") + b"\x00"

    # Length includes the 2-byte length field itself
    length = len(payload) + 2
    return struct.pack("!H", length) + payload


# =============================================================================
# Per-game field types for game list responses
# Maps GameSpy game name -> field_name -> type (0=string, 1=binary)
# =============================================================================

GAME_FIELD_TYPES: dict[str, dict[str, int]] = {
    "cc3tibwars": {
        "cCRC": 0, "gamemode": 0, "hostname": 0, "iCRC": 0, "mID": 0,
        "mapname": 0, "maxRPlyr": 1, "maxplayers": 1, "mod": 0, "modv": 0,
        "name": 0, "numObs": 1, "numRPlyr": 1, "numplayers": 1, "obs": 1,
        "pings": 0, "pw": 1, "rules": 0, "vCRC": 0,
    },
    "cc3xp1": {
        "cCRC": 0, "gamemode": 0, "hostname": 0, "iCRC": 0, "mID": 0,
        "mapname": 0, "maxRPlyr": 1, "maxplayers": 1, "mod": 0, "modv": 0,
        "name": 0, "numObs": 1, "numRPlyr": 1, "numplayers": 1, "obs": 1,
        "pings": 0, "pw": 1, "rules": 0, "vCRC": 0,
    },
    "redalert3pc": {
        "cCRC": 0, "gamemode": 0, "hostname": 0, "iCRC": 0, "mID": 0,
        "joinable": 1, "mapname": 0, "maxRPlyr": 1, "maxplayers": 1,
        "mod": 0, "modv": 0, "name": 0, "numObs": 1, "numRPlyr": 1,
        "numplayers": 1, "obs": 1, "pings": 0, "pw": 1, "rules": 0,
        "teamAuto": 1, "vCRC": 0,
    },
    "ccgenerals": {
        "country": 0, "gamemode": 0, "gametype": 0, "hostname": 0,
        "mapname": 0, "maxplayers": 1, "maxRealPlayers": 1,
        "numObservers": 1, "numplayers": 1, "numRealPlayers": 1,
    },
    "ccgenzh": {
        "country": 0, "gamemode": 0, "gametype": 0, "hostname": 0,
        "mapname": 0, "maxplayers": 1, "numplayers": 1, "password": 1,
    },
}

def get_field_types_for_game(game_name: str) -> dict[str, int]:
    """Get the field type mapping for a given GameSpy game name."""
    return GAME_FIELD_TYPES.get(game_name, {})


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
