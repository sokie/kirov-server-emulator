"""
Query Master TCP Server.

Handles TCP queries from game clients requesting room lists and game lists.
"""

import asyncio
import struct

from app.config.app_settings import app_config
from app.servers.query_master_parsing import (
    DEFAULT_MASTER_IP,
    DEFAULT_MASTER_PORT,
    GameEntry,
    QueryRequest,
    build_game_list_response,
    build_room_list_response,
    create_default_rooms,
    is_room_list_request,
    parse_filter_string,
    parse_tcp_query,
)
from app.servers.sessions import GameSessionRegistry
from app.util.cipher import EncTypeX
from app.util.logging_helper import format_hex, get_logger

logger = get_logger(__name__)


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
        gamekey: str | None = None,
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

    def handle_query(self, data: bytes, client_ip: str = "0.0.0.0", encrypt: bool = True) -> bytes:
        """
        Handle an incoming TCP query and return the appropriate response.

        Args:
            data: Raw TCP data from client
            client_ip: Client's IP address (echoed back in response header)
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
            response = self._handle_room_list_request(request, client_ip)
        else:
            response = self._handle_game_list_request(request, client_ip)

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

    def _handle_room_list_request(self, request: QueryRequest, client_ip: str) -> bytes:
        """Handle a room list request."""
        logger.info("Handling room list request for %s", request.game_name)

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
            rooms=self.rooms,
            fields=fields,
            client_ip=client_ip,
        )

    def _handle_game_list_request(self, request: QueryRequest, client_ip: str) -> bytes:
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

        logger.info("Game list: %d total, %d after filter", len(all_games), len(filtered_games))

        # Use requested fields
        fields = request.fields if request.fields else []

        return build_game_list_response(
            games=filtered_games,
            fields=fields,
            client_ip=client_ip,
            validate_token=request.validate_token,
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
            elif operator == ">=" and actual < expected:
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

            # Get client IP from connection
            client_ip = "0.0.0.0"
            if self.peername:
                client_ip = self.peername[0]

            # Process the query with client IP
            response = handler.handle_query(packet, client_ip=client_ip)

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
# Server Startup
# =============================================================================


async def start_master_server(
    host: str = "0.0.0.0",
    port: int = 28910,
    master_ip: str | None = None,
    gamekey: str | None = None,
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
