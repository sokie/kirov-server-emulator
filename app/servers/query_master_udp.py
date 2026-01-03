"""
Query Master UDP Heartbeat Server.

Handles UDP heartbeats from game hosts registering their sessions.
"""

import asyncio
import base64
import contextlib
import socket
import struct

from app.servers.sessions import GameSessionRegistry
from app.util.logging_helper import format_hex, get_logger

logger = get_logger(__name__)


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

    def __init__(self, game_sessions: dict[int, dict] | None = None):
        """
        Initialize the heartbeat server.

        Args:
            game_sessions: Optional dict to store game sessions (clientId -> session info)
        """
        self.transport = None
        self.game_sessions: dict[int, dict] = game_sessions if game_sessions is not None else {}

    def connection_made(self, transport):
        self.transport = transport
        logger.info("Heartbeat UDP server started")

    def datagram_received(self, data: bytes, addr: tuple[str, int]):
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
            "UDP msg_id=0x%02X, client_id=%d, body_len=%d from %s:%d", msg_id, client_id, len(body), host, port
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
            logger.warning("UDP unhandled msg_id=0x%02X from %s:%d: %s", msg_id, host, port, format_hex(data))

    def _handle_available(self, body: bytes, addr: tuple[str, int], client_id: int):
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

    def _handle_heartbeat(self, body: bytes, addr: tuple[str, int], client_id: int):
        """
        Handle HEARTBEAT message - game host sending session info.

        Body is null-delimited key=value pairs.
        If publicip=0, server sends a challenge with the client's actual IP.
        If statechanged=2 (EXITING), unregister the game session.
        """
        host, port = addr

        # Parse key-value pairs from body
        info = self._parse_heartbeat_body(body)

        logger.info("UDP HEARTBEAT from %s:%d (client_id=%d): %s", host, port, client_id, info)

        # Check if game is shutting down (statechanged=2 means EXITING)
        statechanged = info.get("statechanged", HeartbeatState.NORMAL)
        if statechanged == HeartbeatState.EXITING:
            logger.info("Game session exiting: client_id=%d from %s:%d", client_id, host, port)
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

    def _handle_challenge_response(self, body: bytes, addr: tuple[str, int], client_id: int):
        """
        Handle CHALLENGE_RESPONSE from client.

        For now, always accept the response.
        """
        host, port = addr

        logger.info("UDP CHALLENGE_RESPONSE from %s:%d (client_id=%d): %s", host, port, client_id, format_hex(body))

        # Send RESPONSE_CORRECT
        response = b"\xfe\xfd" + bytes([HeartbeatMsg.RESPONSE_CORRECT]) + struct.pack("!I", client_id)
        self._send(response, addr)

    def _handle_keepalive(self, body: bytes, addr: tuple[str, int], client_id: int):
        """Handle KEEPALIVE message."""
        host, port = addr

        logger.debug("UDP KEEPALIVE from %s:%d (client_id=%d)", host, port, client_id)

        # Update session timestamp if exists
        if client_id in self.game_sessions:
            self.game_sessions[client_id]["last_keepalive"] = True

    def _send_challenge(self, addr: tuple[str, int], client_id: int):
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

        logger.debug("UDP sending challenge to %s:%d (client_id=%d): %s", host, port, client_id, format_hex(response))

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
            with contextlib.suppress(Exception):
                info[key.decode("utf-8", errors="ignore")] = value.decode("utf-8", errors="ignore")
            i += 2

        return info

    def _send(self, data: bytes, addr: tuple[str, int]):
        """Send UDP response."""
        if self.transport:
            logger.debug("UDP TX to %s:%d - %d bytes: %s", addr[0], addr[1], len(data), format_hex(data))
            self.transport.sendto(data, addr)

    def error_received(self, exc):
        logger.error("UDP error: %s", exc)

    def connection_lost(self, exc):
        logger.info("Heartbeat UDP server stopped")


# =============================================================================
# Server Startup
# =============================================================================


async def start_heartbeat_server(
    host: str = "0.0.0.0",
    port: int = 27900,
) -> tuple[asyncio.DatagramTransport, HeartbeatMaster]:
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
