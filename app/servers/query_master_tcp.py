"""
Query Master TCP Server.

Answers server list queries for rooms and games. A query with PUSH_UPDATES keeps its connection open, and every
game that is added, changed or removed later is pushed to it.
"""

import asyncio
import socket
import struct

from app.config.app_settings import app_config
from app.models.fesl_types import GAMESPY_GAME_KEY_MAP
from app.servers.query_master_parsing import (
    DEFAULT_MASTER_IP,
    DEFAULT_MASTER_PORT,
    KEEPALIVE_REPLY,
    PUSH_UPDATES,
    SEND_MESSAGE_REQUEST,
    SERVER_INFO_REQUEST,
    SERVER_LIST_REQUEST,
    GameEntry,
    QueryRequest,
    build_delete_server_message,
    build_game_list_response,
    build_keepalive_message,
    build_push_server_message,
    build_room_list_response,
    create_default_rooms,
    create_rooms_by_game,
    is_room_list_request,
    parse_filter_string,
    parse_tcp_query,
)
from app.servers.sessions import GAME_REMOVED, GameSessionRegistry
from app.util.cipher import EncTypeX
from app.util.logging_helper import format_hex, get_logger

logger = get_logger(__name__)

# A game that sends no heartbeat or keepalive for this long is removed and its deletion pushed.
STALE_GAME_SECONDS = 180.0
MAINTENANCE_INTERVAL = 30.0
KEEPALIVE_EVERY = 2  # maintenance ticks

_maintenance_task: asyncio.Task | None = None


def game_matches_filters(game: GameEntry, filters: list) -> bool:
    """Checks a game against parsed filter conditions. A condition on a key the game lacks is skipped."""
    for f in filters:
        expected = f["value"]
        actual = game.fields.get(f["field"])
        if actual is None:
            continue
        if isinstance(expected, int):
            try:
                actual = int(actual)
            except (ValueError, TypeError):
                return False
        operator = f["operator"]
        if operator in ("=", "==") and actual != expected:
            return False
        if operator == "!=" and actual == expected:
            return False
        if operator == "<" and actual >= expected:
            return False
        if operator == ">" and actual <= expected:
            return False
        if operator == "<=" and actual > expected:
            return False
        if operator == ">=" and actual < expected:
            return False
    return True


# =============================================================================
# Query Handler
# =============================================================================


class QueryMasterHandler:
    """Builds the room and game list responses for parsed queries."""

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
        """Parses a list query and returns the plaintext response with the parsed request."""
        request = parse_tcp_query(data)
        if not request.game_name:
            logger.warning("Invalid query: no game name found")
            return b"", None

        if is_room_list_request(request):
            return self._handle_room_list_request(request, client_ip), request
        return self._handle_game_list_request(request, client_ip, client_port), request

    def list_games(self, request: QueryRequest) -> list:
        """Lists the games of the request's game name that pass its filter."""
        registry = GameSessionRegistry.get_instance()
        filters = parse_filter_string(request.filter_string)
        games = registry.get_games(gamename=request.game_name) + self.games
        return [game for game in games if game_matches_filters(game, filters)]

    def _handle_room_list_request(self, request: QueryRequest, client_ip: str) -> bytes:
        """Handle a room list request, returning game-specific rooms."""
        game_name = request.game_name.lower()
        rooms = self.rooms_by_game.get(game_name, self.rooms)
        logger.info("Room list for %s: %d rooms", game_name, len(rooms))
        fields = request.fields or ["hostname", "numwaiting", "maxwaiting", "numservers", "numplayers", "roomType"]
        return build_room_list_response(rooms=rooms, fields=fields, client_ip=client_ip)

    def _handle_game_list_request(self, request: QueryRequest, client_ip: str, client_port: int = 0) -> bytes:
        """Answers a game list query. A query that names no fields gets the full rules of every game."""
        games = self.list_games(request)
        logger.info(
            "Game list for %s: %d games (filter %r, fields %s)",
            request.game_name,
            len(games),
            request.filter_string,
            request.fields,
        )
        return build_game_list_response(
            games=games,
            fields=request.fields,
            client_ip=client_ip,
            client_port=client_port,
            full_rules=not request.fields,
        )


# =============================================================================
# TCP Server (asyncio.Protocol)
# =============================================================================


class QueryMasterServer(asyncio.Protocol):
    """
    One query connection. The first response is EncTypeX-encoded (cipher header, then data); everything
    sent later on the connection continues the same cipher stream.
    """

    _handler: QueryMasterHandler | None = None
    _subscribers: set["QueryMasterServer"] = set()

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
        self.cipher: EncTypeX | None = None
        self.request: QueryRequest | None = None
        self.subscribed = False
        self.filters: list = []
        self.pushed: set[tuple[str, int]] = set()

    def connection_made(self, transport):
        self.transport = transport
        self.peername = transport.get_extra_info("peername")
        logger.debug("Master server: new TCP connection from %s", self.peername)

    def data_received(self, data: bytes):
        logger.debug("Master server RX from %s: %s", self.peername, format_hex(data))
        self.buffer += data
        while self._process_packet():
            pass

    def connection_lost(self, exc):
        logger.debug("Master server: TCP connection closed for %s (exc=%s)", self.peername, exc)
        self._subscribers.discard(self)
        self.buffer = b""
        self.cipher = None

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
        """Handles one length-prefixed client message; returns False when the buffer holds no whole message."""
        if len(self.buffer) < 2:
            return False
        packet_length = struct.unpack("!H", self.buffer[0:2])[0]
        if packet_length < 3:
            logger.warning("Master server: bad message length %d from %s", packet_length, self.peername)
            self.buffer = b""
            return False
        if len(self.buffer) < packet_length:
            return False
        packet = self.buffer[:packet_length]
        self.buffer = self.buffer[packet_length:]

        try:
            msg_type = packet[2]
            if msg_type == SERVER_LIST_REQUEST:
                self._handle_list_request(packet)
            elif msg_type == SERVER_INFO_REQUEST:
                self._handle_server_info(packet)
            elif msg_type == KEEPALIVE_REPLY:
                pass
            elif msg_type == SEND_MESSAGE_REQUEST:
                logger.info("Master server: SEND_MESSAGE_REQUEST from %s is not supported", self.peername)
            else:
                logger.warning("Master server: unknown message type %d from %s", msg_type, self.peername)
        except Exception as e:
            logger.exception("Error processing master server message: %s", e)
        return True

    def _handle_list_request(self, packet: bytes):
        client_ip, client_port = self.peername[:2] if self.peername else ("0.0.0.0", 0)
        handler = self.get_handler()
        response, request = handler.handle_query(packet, client_ip=client_ip, client_port=client_port)
        if not response or request is None:
            return

        if self.cipher is None:
            if not request.validate_token:
                self.transport.write(response)
                return
            self.cipher = self._create_cipher(request.validate_token, request.game_name)
            self.transport.write(self.cipher.encode(response))
        else:
            self.transport.write(self.cipher.encrypt(response))

        self.request = request
        if request.options & PUSH_UPDATES and not is_room_list_request(request):
            self.filters = parse_filter_string(request.filter_string)
            self.pushed = {(g.public_ip, g.public_port) for g in handler.list_games(request)}
            self.subscribed = True
            self._subscribers.add(self)
            logger.info("Master server: %s follows %s games", self.peername, request.game_name)

    def _handle_server_info(self, packet: bytes):
        """Answers SERVER_INFO_REQUEST (ip, port) with a PUSH_SERVER that carries the full rules."""
        if len(packet) < 9:
            return
        ip = socket.inet_ntoa(packet[3:7])
        port = struct.unpack("!H", packet[7:9])[0]
        game = GameSessionRegistry.get_instance().find_game(ip, port)
        if game is None:
            logger.info("Master server: server info for %s:%d, no such game", ip, port)
            self._send(build_delete_server_message(GameEntry(ip, port, ip, port)))
            return
        fields = self.request.fields if self.request else []
        self._send(build_push_server_message(game, fields, full_rules=True))
        logger.info("Master server: sent the rules of %s:%d to %s", ip, port, self.peername)

    def _send(self, message: bytes):
        if self.transport is None or self.cipher is None:
            return
        self.transport.write(self.cipher.encrypt(message))

    def push(self, event: str, game: GameEntry):
        """Pushes one registry change to a following connection."""
        if not self.subscribed or self.request is None:
            return
        if game.fields.get("gamename", "").lower() != self.request.game_name.lower():
            return
        key = (game.public_ip, game.public_port)
        if event != GAME_REMOVED and game_matches_filters(game, self.filters):
            self._send(build_push_server_message(game, self.request.fields, full_rules=not self.request.fields))
            self.pushed.add(key)
        elif key in self.pushed:
            self._send(build_delete_server_message(game))
            self.pushed.discard(key)

    @classmethod
    def on_registry_change(cls, event: str, game: GameEntry):
        for subscriber in list(cls._subscribers):
            subscriber.push(event, game)

    @classmethod
    def send_keepalives(cls):
        for subscriber in list(cls._subscribers):
            subscriber._send(build_keepalive_message())


async def _maintenance_loop():
    """Removes stale games (pushing their deletion) and keeps following connections alive."""
    tick = 0
    while True:
        await asyncio.sleep(MAINTENANCE_INTERVAL)
        tick += 1
        try:
            GameSessionRegistry.get_instance().prune(STALE_GAME_SECONDS)
            if tick % KEEPALIVE_EVERY == 0:
                QueryMasterServer.send_keepalives()
        except Exception:
            logger.exception("Master server maintenance failed")


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
    global _maintenance_task
    handler = QueryMasterHandler(
        master_ip=master_ip or host if host != "0.0.0.0" else "127.0.0.1",
        master_port=port,
        gamekeys=gamekeys,
    )
    handler.set_rooms(create_default_rooms())
    handler.set_rooms_by_game(create_rooms_by_game())
    QueryMasterServer.set_handler(handler)
    GameSessionRegistry.get_instance().add_listener(QueryMasterServer.on_registry_change)

    logger.info("Master server using gamekeys for %d games", len(handler.gamekeys))

    loop = asyncio.get_running_loop()
    server = await loop.create_server(QueryMasterServer, host, port)
    _maintenance_task = asyncio.create_task(_maintenance_loop())
    return server


async def stop_master_maintenance():
    """Stops the maintenance loop that start_master_server started."""
    global _maintenance_task
    if _maintenance_task is not None:
        _maintenance_task.cancel()
        try:
            await _maintenance_task
        except asyncio.CancelledError:
            pass
        _maintenance_task = None
