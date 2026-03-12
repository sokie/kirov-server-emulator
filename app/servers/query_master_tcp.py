"""
Query Master TCP Server.

Handles TCP queries from game clients requesting room lists and game lists.
"""

import asyncio
import socket
import struct

from app.config.app_settings import app_config
from app.models.fesl_types import GAMESPY_GAME_KEY_MAP
from app.servers.query_master_parsing import (
    DEFAULT_MASTER_IP,
    DEFAULT_MASTER_PORT,
    GameEntry,
    QueryRequest,
    build_game_list_response,
    build_room_list_response,
    build_server_info_message,
    create_default_rooms,
    create_rooms_by_game,
    is_room_list_request,
    parse_filter_string,
    parse_tcp_query,
)
from app.servers.sessions import GameSessionRegistry
from app.util.cipher import EncTypeX
from app.util.logging_helper import format_hex, get_logger

logger = get_logger(__name__)

# Fields managed internally by the GameSpy ServerBrowser SDK.
# Including these in the server response can confuse the SDK's parser.
_SDK_INTERNAL_FIELDS = frozenset({
    "publicip", "publicport",
    "localip0", "localip1", "localip2", "localip3",
    "localport",
    "natneg",
    "statechanged",
    "gamename",
})


# =============================================================================
# Query Handler
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
        gamekeys: dict[str, str] | None = None,
    ):
        self.master_ip = master_ip
        self.master_port = master_port
        self.gamekeys = gamekeys or app_config.game.gamekeys
        self.rooms: list = []  # List of RoomEntry (legacy, RA3 default)
        self.rooms_by_game: dict[str, list] = {}  # GameSpy game name -> rooms
        self.games: list = []  # List of GameEntry

    def set_rooms(self, rooms: list):
        """Set the list of available rooms (legacy, used as fallback)."""
        self.rooms = rooms

    def set_rooms_by_game(self, rooms_by_game: dict[str, list]):
        """Set per-game room lists keyed by GameSpy game name."""
        self.rooms_by_game = rooms_by_game

    def set_games(self, games: list):
        """Set the list of available game sessions."""
        self.games = games

    def handle_query(
        self, data: bytes, client_ip: str = "0.0.0.0", client_port: int = 0
    ) -> tuple[bytes, QueryRequest | None]:
        """
        Handle an incoming TCP query and return the plaintext response.

        Encryption is handled by the per-connection protocol handler, NOT here,
        because the GameSpy SDK uses a persistent stream cipher across the
        entire TCP connection.

        Returns:
            (plaintext_response, parsed_request_or_None)
        """
        request = parse_tcp_query(data)

        if not request.game_name:
            logger.warning("Invalid query: no game name found")
            return b"", None

        # Determine if this is a room list or game list request
        if is_room_list_request(request):
            response = self._handle_room_list_request(request, client_ip)
        else:
            response = self._handle_game_list_request(request, client_ip, client_port)

        return response, request

    def handle_server_info(self, data: bytes, field_table: list[str]) -> bytes:
        """
        Handle a server info request (msg_type 0x01).

        Format: length(2) + 0x01(1) + server_ip(4) + server_port(2).
        Returns the response as a length-prefixed msg_type 0x01 message
        (NOT the classic server list format).
        """
        server_ip = socket.inet_ntoa(data[3:7])
        server_port = struct.unpack("!H", data[7:9])[0]
        logger.info("Server info request for %s:%d", server_ip, server_port)

        # Look up the game in the registry by matching IP:port
        registry = GameSessionRegistry.get_instance()
        game = None
        for g in registry.get_games():
            if (g.public_ip == server_ip or g.private_ip == server_ip or g.traced_ip == server_ip) \
                    and (g.public_port == server_port or g.private_port == server_port):
                game = g
                break

        if not game:
            logger.warning("Server info request: no game found for %s:%d", server_ip, server_port)
            return b""

        logger.info(
            "Server info response for %s:%d: %d fields in table",
            server_ip, server_port, len(field_table),
        )

        return build_server_info_message(game, field_table)

    def _handle_room_list_request(self, request: QueryRequest, client_ip: str) -> bytes:
        """Handle a room list request, returning game-specific rooms."""
        logger.info("Handling room list request for %s", request.game_name)

        # Look up rooms for this specific game, fall back to legacy list
        game_name = request.game_name.lower()
        rooms = self.rooms_by_game.get(game_name, self.rooms)
        logger.debug("Returning %d rooms for game %s", len(rooms), game_name)

        # Use requested fields or defaults
        fields = (
            request.fields
            if request.fields
            else [
                "hostname",
                "numwaiting",
                "maxwaiting",
                "numservers",
                "numplayers",
                "roomType",
            ]
        )

        return build_room_list_response(
            rooms=rooms,
            fields=fields,
            client_ip=client_ip,
        )

    def _handle_game_list_request(self, request: QueryRequest, client_ip: str, client_port: int = 0) -> bytes:
        """Handle a game list request (classic Type 1 format — all string fields)."""
        logger.info("Handling game list request for %s", request.game_name)

        # Parse filter conditions
        filter_conditions = parse_filter_string(request.filter_string)

        # Get games from shared registry (populated by UDP heartbeats)
        # Filter by gamename so e.g. cc3xp1am queries only return automatch games
        registry = GameSessionRegistry.get_instance()
        all_games = registry.get_games(gamename=request.game_name) + self.games

        # Filter games based on conditions
        filtered_games = self._filter_games(all_games, filter_conditions)

        logger.info("Game list: %d total, %d after filter", len(all_games), len(filtered_games))

        # Use requested fields; if none, derive from game heartbeat data so the
        # SDK gets complete server info in the initial response (avoiding the
        # need for individual msg_type 0x01 follow-up queries).
        # Exclude SDK-internal fields that the ServerBrowser manages itself.
        fields = request.fields
        if not fields and filtered_games:
            field_set: set[str] = set()
            for game in filtered_games:
                for k in (game.fields or {}):
                    if not k.startswith("_") and k not in _SDK_INTERNAL_FIELDS:
                        field_set.add(k)
            fields = sorted(field_set)
            logger.info("Derived %d fields from game data: %s", len(fields), fields)

        return build_game_list_response(
            games=filtered_games,
            fields=fields,
            client_ip=client_ip,
            client_port=client_port,
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
                # Game doesn't have this field — skip this condition
                # (heartbeat-registered games may not have all filterable fields)
                continue

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
            elif operator == ">=" and actual < expected:
                return False

        return True


# =============================================================================
# TCP Server (asyncio.Protocol)
# =============================================================================


class QueryMasterServer(asyncio.Protocol):
    """
    GameSpy Master Server TCP Protocol handler.

    Manages per-connection EncTypeX cipher state.  The GameSpy SDK uses a
    persistent stream cipher for the entire TCP session: the initial server
    list response is encrypted with ``cipher.encode()`` (which prepends the
    cipher challenge header), and all subsequent messages (e.g. msg_type 0x01
    server-info responses) are encrypted with ``cipher.encrypt()`` continuing
    the same cipher stream.
    """

    # Shared handler instance with room/game data
    _handler: QueryMasterHandler | None = None

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
            cls._handler.set_rooms_by_game(create_rooms_by_game())
        return cls._handler

    def __init__(self):
        self.transport = None
        self.peername = None
        self.buffer = b""
        # Per-connection cipher state (initialized on first response)
        self.cipher: EncTypeX | None = None
        # Field table declared in the initial response — msg_type 0x01 responses
        # reference fields by index into this table.
        self.field_table: list[str] = []

    def connection_made(self, transport):
        self.transport = transport
        self.peername = transport.get_extra_info("peername")
        logger.info("Master server: new TCP connection from %s", self.peername)

    def data_received(self, data: bytes):
        """Handle incoming data from client."""
        logger.debug("Master server: received %d bytes from %s", len(data), self.peername)
        logger.debug("RX hex: %s", format_hex(data))

        # Append to buffer (in case of fragmented packets)
        self.buffer += data

        # Process complete packets
        while self._process_packet():
            pass

    def _create_cipher(self, validate_token: bytes, game_name: str) -> EncTypeX:
        """Create an EncTypeX cipher for this connection."""
        handler = self.get_handler()
        config_key = GAMESPY_GAME_KEY_MAP.get(game_name.lower(), "")
        gamekey = handler.gamekeys.get(config_key, "")
        if not gamekey:
            logger.warning("No gamekey for game %s, trying first available", game_name)
            gamekey = next(iter(handler.gamekeys.values()), "")
        return EncTypeX(key=gamekey, validate=validate_token)

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
            handler = self.get_handler()
            client_ip = "0.0.0.0"
            client_port = 0
            if self.peername:
                client_ip = self.peername[0]
                client_port = self.peername[1]

            # Check for msg_type 0x01 (server info request)
            if len(packet) >= 9 and packet[2] == 0x01:
                logger.info(
                    "Server info request raw hex (%d bytes): %s",
                    len(packet),
                    " ".join(f"{b:02x}" for b in packet),
                )
                self._handle_server_info(handler, packet)
            else:
                self._handle_initial_query(handler, packet, client_ip, client_port)

        except Exception as e:
            logger.exception("Error processing master server query: %s", e)

        return True

    def _handle_initial_query(
        self, handler: QueryMasterHandler, packet: bytes, client_ip: str, client_port: int
    ):
        """Handle the initial server-list / room-list query."""
        response, request = handler.handle_query(packet, client_ip=client_ip, client_port=client_port)

        if not response:
            logger.warning("No response generated for query")
            return

        # Remember the field table so msg_type 0x01 can reference it
        if request and request.fields:
            self.field_table = list(request.fields)
        else:
            # We derived fields from game data — extract them from the response.
            # The field list is at offset 6 in the plaintext response:
            # clientIP(4) + clientPort(2) + fieldCount(1) + fields...
            if len(response) > 6:
                field_count = response[6]
                self.field_table = self._extract_field_names(response[7:], field_count)

        # Encrypt with EncTypeX (encode = header + encrypted data)
        if request and request.validate_token:
            logger.info(
                "Cipher init: validate=%s, game=%s",
                " ".join(f"{b:02x}" for b in request.validate_token),
                request.game_name,
            )
            self.cipher = self._create_cipher(request.validate_token, request.game_name)
            encrypted = self.cipher.encode(response)
            logger.info(
                "Sending initial response for %s to %s: plaintext=%d, encrypted=%d, fields=%s",
                request.game_name, self.peername,
                len(response), len(encrypted), self.field_table,
            )
            logger.info(
                "Encrypted first 40 bytes: %s",
                " ".join(f"{b:02x}" for b in encrypted[:40]),
            )
            self.transport.write(encrypted)
        else:
            # No validate token — send plaintext (shouldn't happen normally)
            self.transport.write(response)

    @staticmethod
    def _extract_field_names(data: bytes, count: int) -> list[str]:
        """Extract field names from the field list section of a response."""
        names = []
        pos = 0
        for _ in range(count):
            if pos >= len(data):
                break
            pos += 1  # skip field type byte
            end = data.find(b"\x00", pos)
            if end == -1:
                break
            names.append(data[pos:end].decode("utf-8", errors="ignore"))
            pos = end + 1
        return names

    def _handle_server_info(self, handler: QueryMasterHandler, packet: bytes):
        """Handle msg_type 0x01 (server info request) with continuing cipher."""
        response = handler.handle_server_info(packet, self.field_table)

        if not response:
            logger.warning("No server info response generated")
            return

        if self.cipher:
            encrypted = self.cipher.encrypt(response)
            logger.debug(
                "Encrypted server info response: plaintext=%d, encrypted=%d",
                len(response), len(encrypted),
            )
            self.transport.write(encrypted)
        else:
            logger.warning("No cipher for server info response — sending plaintext")
            self.transport.write(response)

    def connection_lost(self, exc):
        logger.info("Master server: TCP connection closed for %s (exc=%s)", self.peername, exc)
        self.buffer = b""
        self.cipher = None
        self.field_table = []


# =============================================================================
# Server Startup
# =============================================================================


async def start_master_server(
    host: str = "0.0.0.0",
    port: int = 28910,
    master_ip: str | None = None,
    gamekeys: dict[str, str] | None = None,
) -> asyncio.AbstractServer:
    """
    Start the GameSpy Master Server.

    Args:
        host: Host address to bind to
        port: Port to listen on
        master_ip: IP address to report in responses (uses host if not specified)
        gamekeys: Per-game encryption keys dict (defaults to app_config.game.gamekeys)

    Returns:
        The asyncio server instance
    """
    # Initialize the shared handler with default rooms
    handler = QueryMasterHandler(
        master_ip=master_ip or host if host != "0.0.0.0" else "127.0.0.1",
        master_port=port,
        gamekeys=gamekeys,
    )
    handler.set_rooms(create_default_rooms())
    handler.set_rooms_by_game(create_rooms_by_game())
    QueryMasterServer.set_handler(handler)

    logger.info("Master server using gamekeys for %d games", len(handler.gamekeys))

    loop = asyncio.get_running_loop()
    server = await loop.create_server(QueryMasterServer, host, port)

    return server
