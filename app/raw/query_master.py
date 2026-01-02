import asyncio
import base64
import re
import socket
import struct
from dataclasses import dataclass, field
from typing import Optional, Tuple, Dict

from app.config.app_settings import app_config
from app.util.cipher import EncTypeX
from app.util.logging_helper import get_logger, format_hex

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
# UDP Heartbeat Message Types
# =============================================================================

class HeartbeatMsg:
    """Message types for UDP heartbeat protocol."""
    CHALLENGE_RESPONSE = 0x01  # Server sends challenge to client
    HEARTBEAT = 0x03  # Client sends game session info
    KEEPALIVE = 0x08  # Client keepalive
    AVAILABLE = 0x09  # Client checks if server is available
    RESPONSE_CORRECT = 0x0A  # Server confirms challenge response


class HeartbeatState:
    """
    State values sent in heartbeat 'statechanged' field.

    These indicate why the heartbeat is being sent.
    Reference: GameSpy QR2 SDK (qr2.c)
    """
    NORMAL = "0"  # Normal periodic heartbeat
    STATECHANGED = "1"  # Game state changed (mode, players, etc.)
    EXITING = "2"  # Server shutting down, remove from list
    INITIAL = "3"  # Initial registration heartbeat


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
    traced_ip: Optional[str] = None
    traced_port: Optional[int] = None
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
# Shared Game Session Registry
# =============================================================================


class GameSessionRegistry:
    """
    Shared registry for game sessions.

    This connects the UDP heartbeat server (where games register)
    with the TCP query server (where clients request game lists).
    """

    _instance: Optional["GameSessionRegistry"] = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._sessions: Dict[int, GameEntry] = {}  # client_id -> GameEntry
        return cls._instance

    @classmethod
    def get_instance(cls) -> "GameSessionRegistry":
        """Get the singleton instance."""
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    def register_game(self, client_id: int, host: str, port: int, info: dict):
        """
        Register or update a game session from heartbeat data.

        Args:
            client_id: Unique client ID from heartbeat
            host: Public IP address of the game host
            port: Public port of the game host
            info: Key-value pairs from heartbeat (hostname, gamemode, etc.)
        """
        # Parse public IP from heartbeat info (it's sent as a signed int)
        public_ip = host  # Default to connection source IP
        if "publicip" in info and info["publicip"] != "0":
            try:
                # publicip is sent as a little-endian signed int
                ip_int = int(info["publicip"])
                # Convert to unsigned and then to IP string
                if ip_int < 0:
                    ip_int = ip_int & 0xFFFFFFFF
                public_ip = socket.inet_ntoa(struct.pack("<I", ip_int))
            except (ValueError, struct.error):
                pass

        # Parse ports
        public_port = int(info.get("hostport", port))
        private_ip = info.get("localip0", host)
        private_port = int(info.get("localport", public_port))

        # Create or update GameEntry
        game = GameEntry(
            public_ip=public_ip,
            public_port=public_port,
            private_ip=private_ip,
            private_port=private_port,
            traced_ip=host,  # The IP we actually received the packet from
            traced_port=port,
            fields=info,
        )

        self._sessions[client_id] = game
        logger.info(
            "Registered game: client_id=%d, host=%s:%d, hostname=%s",
            client_id, public_ip, public_port, info.get("hostname", "unknown")
        )

    def unregister_game(self, client_id: int):
        """Remove a game session."""
        if client_id in self._sessions:
            del self._sessions[client_id]
            logger.info("Unregistered game: client_id=%d", client_id)

    def get_games(self) -> list:
        """Get all registered games as a list of GameEntry objects."""
        return list(self._sessions.values())

    def get_game(self, client_id: int) -> Optional[GameEntry]:
        """Get a specific game by client ID."""
        return self._sessions.get(client_id)

    def clear(self):
        """Clear all sessions."""
        self._sessions.clear()


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
    condition_pattern = re.compile(
        r"\(?\s*(\w+)\s*(!=|==|=|<|>|<=|>=)\s*'?(.*?)'?\s*\)?$"
    )

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
            if op == "=" and server_value == value:
                is_match = True
            elif op == "!=" and server_value != value:
                is_match = True
            # Note: More operators like '>', '<', etc. could be added here.

            if not is_match:
                matches_all_conditions = False
                break

        if matches_all_conditions:
            filtered_list.append(server)

    return filtered_list


def parse_server_query_data(data: bytes):
    """
    Parses a raw byte string from a game server query, likely based on the
    GameSpy protocol.

    The data is primarily delimited by null bytes ('\\x00').

    Args:
        data: The raw byte string to parse.
    """
    logger.debug("Starting Data Parse")
    logger.debug("Raw Data (as bytes): %s", data)

    parts = [part for part in data.split(b"\x00") if part]
    parsed_data = {}

    if not parts:
        logger.debug("No parsable parts found.")
        return

    # Debug: Show all parts
    logger.debug("All Parts After Splitting:")
    for i, part in enumerate(parts):
        try:
            decoded = part.decode("utf-8", errors="ignore")
            logger.debug("Part %d: %s -> '%s'", i, part, decoded)
        except:
            logger.debug("Part %d: %s -> [Could not decode]", i, part)

    # --- Interpretation of the Parts ---
    if len(parts) > 3:
        parsed_data["game_name"] = parts[3].decode("utf-8", errors="ignore")
        logger.debug("Game Name: %s", parsed_data['game_name'])

    if len(parts) > 5:
        filter_string = parts[5].decode("utf-8", errors="ignore").split("%", 1)[-1]
        parsed_data["filter_raw"] = filter_string
        logger.debug("Raw Filter String: %s", parsed_data['filter_raw'])

        # Parse the filter string into a structured format
        parsed_conditions = parse_filter_string(filter_string)
        parsed_data["filter_conditions"] = parsed_conditions
        logger.debug("Parsed Filter Conditions: %s", parsed_conditions)

        # Generate SQL WHERE clause
        sql_clause = generate_sql_where_clause(parsed_conditions)
        logger.debug("Generated SQL Clause: %s", sql_clause)

    if len(parts) > 6:
        keys_string = parts[6].decode("utf-8", errors="ignore")
        parsed_data["keys"] = [key for key in keys_string.split("\\") if key]
        logger.debug("Server Info Keys: %s", parsed_data["keys"])

    logger.debug("End of Parse")


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


def make_field_list(fields: list, field_types: Optional[dict] = None) -> bytes:
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
    master_ip: str = DEFAULT_MASTER_IP,
) -> bytes:
    """
    Build a classic-format room list response.

    Response structure:
        ip4     masterIp
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
        master_ip: Master server IP address

    Returns:
        Complete response bytes
    """
    response = b""

    # Master IP (4 bytes)
    response += ip_to_bytes(master_ip)

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


def build_game_list_response(
    games: list,
    fields: list,
    master_ip: str = DEFAULT_MASTER_IP,
    master_port: int = DEFAULT_MASTER_PORT,
) -> bytes:
    """
    Build a classic-format game list response.

    Response structure:
        ip4     masterIp
        u16be   masterPort
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
        u16be   tracedPort
        repeat for each field:
            u8 0xFF + str bytes + u8 0x00
        u8      0x00 (end of entry)

    Args:
        games: List of GameEntry objects
        fields: List of field names to include
        master_ip: Master server IP address
        master_port: Master server port

    Returns:
        Complete response bytes
    """
    response = b""

    # Master IP (4 bytes)
    response += ip_to_bytes(master_ip)

    # Master port (2 bytes big-endian)
    response += struct.pack("!H", master_port)

    # Field list
    response += make_field_list(fields)

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
        response += struct.pack("!H", game.traced_port)

        # Field values
        for field_name in fields:
            value = game.get_field_value(field_name)
            response += encode_field_value_classic(value)

        # End of entry marker
        response += b"\x00"

    # End marker
    response += END_MARKER

    logger.debug("Built game list response: %d bytes, %d games", len(response), len(games))
    return response


# =============================================================================
# New Format Response Builders (length-prefixed)
# =============================================================================


def build_value_map_message(fields: list, field_types: Optional[dict] = None) -> bytes:
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
    field_types: Optional[dict] = None,
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
        u16be   tracedPort
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
    payload += struct.pack("!H", game.traced_port)

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
# Main TCP Query Handler
# =============================================================================


class QueryMasterHandler:
    """
    Handler for GameSpy master server TCP queries.

    This handler parses incoming queries and generates appropriate responses
    for room lists and game lists. Responses are encrypted using EncTypeX.
    """

    def __init__(
        self,
        master_ip: str = DEFAULT_MASTER_IP,
        master_port: int = DEFAULT_MASTER_PORT,
        gamekey: Optional[str] = None,
    ):
        self.master_ip = master_ip
        self.master_port = master_port
        self.gamekey = gamekey or app_config.game.gamekey
        self.rooms: list = []  # List of RoomEntry
        self.games: list = []  # List of GameEntry

    def set_rooms(self, rooms: list):
        """Set the list of available rooms."""
        self.rooms = rooms

    def set_games(self, games: list):
        """Set the list of available game sessions."""
        self.games = games

    def handle_query(self, data: bytes, encrypt: bool = True) -> bytes:
        """
        Handle an incoming TCP query and return the appropriate response.

        Args:
            data: Raw TCP data from client
            encrypt: Whether to encrypt the response (default True)

        Returns:
            Response bytes to send back to client (encrypted if encrypt=True)
        """
        request = parse_tcp_query(data)

        if not request.game_name:
            logger.warning("Invalid query: no game name found")
            return b""

        # Determine if this is a room list or game list request
        if is_room_list_request(request):
            response = self._handle_room_list_request(request)
        else:
            response = self._handle_game_list_request(request)

        # Encrypt the response if requested
        if encrypt and response and request.validate_token:
            response = self._encrypt_response(response, request.validate_token)

        return response

    def _encrypt_response(self, response: bytes, validate_token: bytes) -> bytes:
        """
        Encrypt response data using EncTypeX cipher.

        Args:
            response: Plaintext response data
            validate_token: The validate token from the client request

        Returns:
            Encrypted response with header
        """
        try:
            cipher = EncTypeX(key=self.gamekey, validate=validate_token)
            encrypted = cipher.encode(response)
            logger.debug(
                "Encrypted response: plaintext=%d bytes, encrypted=%d bytes",
                len(response),
                len(encrypted),
            )
            return encrypted
        except Exception as e:
            logger.exception("Failed to encrypt response: %s", e)
            # Fall back to unencrypted response
            return response

    def _handle_room_list_request(self, request: QueryRequest) -> bytes:
        """Handle a room list request."""
        logger.info("Handling room list request for %s", request.game_name)

        # Use requested fields or defaults
        fields = request.fields if request.fields else [
            "hostname",
            "numwaiting",
            "maxwaiting",
            "numservers",
            "numplayers",
            "roomType",
        ]

        return build_room_list_response(
            rooms=self.rooms,
            fields=fields,
            master_ip=self.master_ip,
        )

    def _handle_game_list_request(self, request: QueryRequest) -> bytes:
        """Handle a game list request."""
        logger.info("Handling game list request for %s", request.game_name)

        # Parse filter conditions
        filter_conditions = parse_filter_string(request.filter_string)

        # Get games from shared registry (populated by UDP heartbeats)
        # Also include any manually added games
        registry = GameSessionRegistry.get_instance()
        all_games = registry.get_games() + self.games

        # Filter games based on conditions
        filtered_games = self._filter_games(all_games, filter_conditions)

        logger.info(
            "Game list: %d total, %d after filter",
            len(all_games), len(filtered_games)
        )

        # Use requested fields
        fields = request.fields if request.fields else []

        return build_game_list_response(
            games=filtered_games,
            fields=fields,
            master_ip=self.master_ip,
            master_port=self.master_port,
        )

    def _filter_games(self, games: list, filter_conditions: list) -> list:
        """
        Filter games based on parsed filter conditions.

        Args:
            games: List of GameEntry objects to filter
            filter_conditions: List of filter conditions from parse_filter_string

        Returns:
            Filtered list of GameEntry objects
        """
        if not filter_conditions:
            return games

        filtered = []
        for game in games:
            if self._game_matches_filters(game, filter_conditions):
                filtered.append(game)

        return filtered

    def _game_matches_filters(self, game: GameEntry, filters: list) -> bool:
        """Check if a game matches all filter conditions."""
        for f in filters:
            field_name = f["field"]
            operator = f["operator"]
            expected = f["value"]

            actual = game.fields.get(field_name)
            if actual is None:
                return False

            # Normalize types for comparison
            if isinstance(expected, int):
                try:
                    actual = int(actual)
                except (ValueError, TypeError):
                    return False

            if operator == "=" or operator == "==":
                if actual != expected:
                    return False
            elif operator == "!=":
                if actual == expected:
                    return False
            elif operator == "<":
                if actual >= expected:
                    return False
            elif operator == ">":
                if actual <= expected:
                    return False
            elif operator == "<=":
                if actual > expected:
                    return False
            elif operator == ">=":
                if actual < expected:
                    return False

        return True


# =============================================================================
# TCP Server (asyncio.Protocol)
# =============================================================================


class QueryMasterServer(asyncio.Protocol):
    """
    GameSpy Master Server TCP Protocol handler.

    This server handles TCP queries from game clients requesting:
    - Room/lobby lists (groupid=2167)
    - Game session lists (groupid=2166)

    Protocol:
    - Client sends a length-prefixed query packet
    - Server responds with room/game list in classic GameSpy format
    """

    # Shared handler instance with room/game data
    _handler: Optional[QueryMasterHandler] = None

    @classmethod
    def set_handler(cls, handler: QueryMasterHandler):
        """Set the shared handler instance."""
        cls._handler = handler

    @classmethod
    def get_handler(cls) -> QueryMasterHandler:
        """Get or create the shared handler instance."""
        if cls._handler is None:
            cls._handler = QueryMasterHandler()
            cls._handler.set_rooms(create_default_rooms())
        return cls._handler

    def __init__(self):
        self.transport = None
        self.peername = None
        self.buffer = b""

    def connection_made(self, transport):
        self.transport = transport
        self.peername = transport.get_extra_info("peername")
        logger.debug("Master server: new connection from %s", self.peername)

    def data_received(self, data: bytes):
        """Handle incoming data from client."""
        logger.debug("Master server: received %d bytes from %s", len(data), self.peername)
        logger.debug("RX hex: %s", format_hex(data))

        # Append to buffer (in case of fragmented packets)
        self.buffer += data

        # Process complete packets
        while self._process_packet():
            pass

    def _process_packet(self) -> bool:
        """
        Process a single packet from the buffer.

        Returns True if a packet was processed, False otherwise.
        """
        if len(self.buffer) < 2:
            return False

        # Read packet length (first 2 bytes, big-endian)
        packet_length = struct.unpack("!H", self.buffer[0:2])[0]

        # Check if we have the complete packet
        if len(self.buffer) < packet_length:
            logger.debug("Waiting for more data: have %d, need %d", len(self.buffer), packet_length)
            return False

        # Extract the complete packet
        packet = self.buffer[:packet_length]
        self.buffer = self.buffer[packet_length:]

        logger.debug("Processing packet: %d bytes", len(packet))

        try:
            # Get the handler and process the query
            handler = self.get_handler()

            # Update handler's master IP based on actual server IP if possible
            if self.peername:
                sock = self.transport.get_extra_info("socket")
                if sock:
                    local_addr = sock.getsockname()
                    if local_addr[0] != "0.0.0.0":
                        handler.master_ip = local_addr[0]

            # Process the query
            response = handler.handle_query(packet)

            if response:
                logger.debug("Sending response: %d bytes", len(response))
                logger.debug("TX hex (first 100): %s", format_hex(response[:100]))
                self.transport.write(response)
            else:
                logger.warning("No response generated for query")

        except Exception as e:
            logger.exception("Error processing master server query: %s", e)

        return True

    def connection_lost(self, exc):
        logger.debug("Master server: connection closed for %s", self.peername)
        self.buffer = b""


# =============================================================================
# UDP Heartbeat Server (asyncio.DatagramProtocol)
# =============================================================================


class HeartbeatMaster(asyncio.DatagramProtocol):
    """
    GameSpy Heartbeat Master Server (UDP).

    This handles UDP heartbeats from game hosts registering their sessions.
    Runs on UDP port 27900.

    Protocol:
    - AVAILABLE (0x09): Client checks if master is up
    - HEARTBEAT (0x03): Game host sends session info (key=value pairs)
    - CHALLENGE_RESPONSE (0x01): Server sends challenge when publicip=0
    - KEEPALIVE (0x08): Client keepalive ping
    - RESPONSE_CORRECT (0x0A): Server confirms challenge accepted

    UDP packet format:
        u8     msgId
        u32be  clientId
        bytes  body
    """

    def __init__(self, game_sessions: Optional[Dict[int, dict]] = None):
        """
        Initialize the heartbeat server.

        Args:
            game_sessions: Optional dict to store game sessions (clientId -> session info)
        """
        self.transport = None
        self.game_sessions: Dict[int, dict] = game_sessions if game_sessions is not None else {}

    def connection_made(self, transport):
        self.transport = transport
        logger.info("Heartbeat UDP server started")

    def datagram_received(self, data: bytes, addr: Tuple[str, int]):
        """Handle incoming UDP datagram."""
        host, port = addr

        logger.debug("UDP from %s:%d - %d bytes", host, port, len(data))
        logger.debug("UDP RX hex: %s", format_hex(data))

        if len(data) < 5:
            logger.warning("UDP packet too short from %s:%d: %d bytes", host, port, len(data))
            return

        # Parse packet header
        msg_id = data[0]
        client_id = struct.unpack("!I", data[1:5])[0]
        body = data[5:]

        logger.debug(
            "UDP msg_id=0x%02X, client_id=%d, body_len=%d from %s:%d",
            msg_id, client_id, len(body), host, port
        )

        if msg_id == HeartbeatMsg.AVAILABLE:
            self._handle_available(body, addr, client_id)
        elif msg_id == HeartbeatMsg.HEARTBEAT:
            self._handle_heartbeat(body, addr, client_id)
        elif msg_id == HeartbeatMsg.CHALLENGE_RESPONSE:
            self._handle_challenge_response(body, addr, client_id)
        elif msg_id == HeartbeatMsg.KEEPALIVE:
            self._handle_keepalive(body, addr, client_id)
        else:
            logger.warning(
                "UDP unhandled msg_id=0x%02X from %s:%d: %s",
                msg_id, host, port, format_hex(data)
            )

    def _handle_available(self, body: bytes, addr: Tuple[str, int], client_id: int):
        """
        Handle AVAILABLE message - client checking if master is up.

        Body is a null-terminated game name.
        Response is a fixed acknowledgment.
        """
        host, port = addr
        game_name = body.rstrip(b"\x00").decode("utf-8", errors="ignore")

        logger.info("UDP AVAILABLE: game=%s from %s:%d (client_id=%d)", game_name, host, port, client_id)

        # Send acknowledgment: 4-byte magic + 3 null bytes
        response = struct.pack("<I", 0x0009FDFE) + b"\x00\x00\x00"
        self._send(response, addr)

    def _handle_heartbeat(self, body: bytes, addr: Tuple[str, int], client_id: int):
        """
        Handle HEARTBEAT message - game host sending session info.

        Body is null-delimited key=value pairs.
        If publicip=0, server sends a challenge with the client's actual IP.
        If statechanged=2 (EXITING), unregister the game session.
        """
        host, port = addr

        # Parse key-value pairs from body
        info = self._parse_heartbeat_body(body)

        logger.info(
            "UDP HEARTBEAT from %s:%d (client_id=%d): %s",
            host, port, client_id, info
        )

        # Check if game is shutting down (statechanged=2 means EXITING)
        statechanged = info.get("statechanged", HeartbeatState.NORMAL)
        if statechanged == HeartbeatState.EXITING:
            logger.info(
                "Game session exiting: client_id=%d from %s:%d",
                client_id, host, port
            )
            # Remove from local sessions
            if client_id in self.game_sessions:
                del self.game_sessions[client_id]
            # Unregister from shared registry
            registry = GameSessionRegistry.get_instance()
            registry.unregister_game(client_id)
            return

        # Store session info locally
        self.game_sessions[client_id] = {
            "host": host,
            "port": port,
            "info": info,
        }

        # Register game in shared registry (for TCP query responses)
        registry = GameSessionRegistry.get_instance()
        registry.register_game(client_id, host, port, info)

        # If publicip is "0", send challenge with actual IP/port
        public_ip = info.get("publicip", "")
        if public_ip == "0":
            self._send_challenge(addr, client_id)

    def _handle_challenge_response(self, body: bytes, addr: Tuple[str, int], client_id: int):
        """
        Handle CHALLENGE_RESPONSE from client.

        For now, always accept the response.
        """
        host, port = addr

        logger.info(
            "UDP CHALLENGE_RESPONSE from %s:%d (client_id=%d): %s",
            host, port, client_id, format_hex(body)
        )

        # Send RESPONSE_CORRECT
        response = b"\xfe\xfd" + bytes([HeartbeatMsg.RESPONSE_CORRECT]) + struct.pack("!I", client_id)
        self._send(response, addr)

    def _handle_keepalive(self, body: bytes, addr: Tuple[str, int], client_id: int):
        """Handle KEEPALIVE message."""
        host, port = addr

        logger.debug("UDP KEEPALIVE from %s:%d (client_id=%d)", host, port, client_id)

        # Update session timestamp if exists
        if client_id in self.game_sessions:
            self.game_sessions[client_id]["last_keepalive"] = True

    def _send_challenge(self, addr: Tuple[str, int], client_id: int):
        """
        Send challenge response with client's actual IP/port.

        Format:
            0xFE 0xFD
            0x01 (CHALLENGE_RESPONSE)
            u32be clientId
            <challenge bytes>
            <hex-encoded: 0x00 + ip4 + u16be port>
            0x00
        """
        host, port = addr

        # Generate a simple challenge (could be random)
        challenge = b"CHALLENGE"

        # Encode IP and port as hex string
        ip_bytes = socket.inet_aton(host)
        port_bytes = struct.pack("!H", port)
        ip_port_hex = base64.b16encode(b"\x00" + ip_bytes + port_bytes)

        response = (
            b"\xfe\xfd"
            + bytes([HeartbeatMsg.CHALLENGE_RESPONSE])
            + struct.pack("!I", client_id)
            + challenge
            + ip_port_hex
            + b"\x00"
        )

        logger.debug(
            "UDP sending challenge to %s:%d (client_id=%d): %s",
            host, port, client_id, format_hex(response)
        )

        self._send(response, addr)

    def _parse_heartbeat_body(self, body: bytes) -> dict:
        """
        Parse heartbeat body into key-value dict.

        Format: key\0value\0key\0value\0...\0\0
        """
        info = {}
        tokens = body.split(b"\x00")

        i = 0
        while i < len(tokens) - 1:
            key = tokens[i]
            if not key:
                break
            value = tokens[i + 1] if i + 1 < len(tokens) else b""
            try:
                info[key.decode("utf-8", errors="ignore")] = value.decode("utf-8", errors="ignore")
            except Exception:
                pass
            i += 2

        return info

    def _send(self, data: bytes, addr: Tuple[str, int]):
        """Send UDP response."""
        if self.transport:
            logger.debug("UDP TX to %s:%d - %d bytes: %s", addr[0], addr[1], len(data), format_hex(data))
            self.transport.sendto(data, addr)

    def error_received(self, exc):
        logger.error("UDP error: %s", exc)

    def connection_lost(self, exc):
        logger.info("Heartbeat UDP server stopped")


async def start_heartbeat_server(
    host: str = "0.0.0.0",
    port: int = 27900,
) -> Tuple[asyncio.DatagramTransport, HeartbeatMaster]:
    """
    Start the GameSpy Heartbeat UDP Server.

    Args:
        host: Host address to bind to
        port: UDP port to listen on (default 27900)

    Returns:
        Tuple of (transport, protocol)
    """
    loop = asyncio.get_running_loop()

    transport, protocol = await loop.create_datagram_endpoint(
        HeartbeatMaster,
        local_addr=(host, port),
    )

    logger.info("Heartbeat UDP server listening on %s:%d", host, port)

    return transport, protocol


async def start_master_server(
    host: str = "0.0.0.0",
    port: int = 28910,
    master_ip: Optional[str] = None,
    gamekey: Optional[str] = None,
) -> asyncio.AbstractServer:
    """
    Start the GameSpy Master Server.

    Args:
        host: Host address to bind to
        port: Port to listen on
        master_ip: IP address to report in responses (uses host if not specified)
        gamekey: Game-specific encryption key (defaults to app_config.game.gamekey)

    Returns:
        The asyncio server instance
    """
    # Initialize the shared handler with default rooms
    handler = QueryMasterHandler(
        master_ip=master_ip or host if host != "0.0.0.0" else "127.0.0.1",
        master_port=port,
        gamekey=gamekey,
    )
    handler.set_rooms(create_default_rooms())
    QueryMasterServer.set_handler(handler)

    logger.info("Master server using gamekey: %s", handler.gamekey)

    loop = asyncio.get_running_loop()
    server = await loop.create_server(QueryMasterServer, host, port)

    return server


def create_default_rooms() -> list:
    """Create default room list for Red Alert 3."""
    rooms = [
        # Chat rooms
        RoomEntry(room_id=0x1337, hostname="ChatRoom1", room_type=1),
        RoomEntry(room_id=0x1338, hostname="ChatRoom1", room_type=2),
        # Lobby rooms
        RoomEntry(room_id=0x1339, hostname="LobbyRoom:1", room_type=1),
        RoomEntry(room_id=0x1340, hostname="LobbyRoom:2", room_type=1),
        # Coop rooms
        RoomEntry(room_id=0x1341, hostname="LobbyCoop:1", room_type=1),
        RoomEntry(room_id=0x1342, hostname="LobbyCoop:2", room_type=1),
        # Clan rooms
        RoomEntry(room_id=0x1343, hostname="LobbyClan:1", room_type=1),
        RoomEntry(room_id=0x1344, hostname="LobbyClan:2", room_type=1),
        # Tournament rooms
        RoomEntry(room_id=0x1345, hostname="LobbyTournaments:1", room_type=1),
        RoomEntry(room_id=0x1346, hostname="LobbyTournaments:2", room_type=1)
    ]
    return rooms