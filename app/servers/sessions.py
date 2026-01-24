"""
Session Management for Red Alert 3 Server Emulator.

This module contains session managers for different server types:
- SessionManager: Generic session tracking for GP server connections
- NatNegSessionManager: NAT negotiation session management
- GameSessionRegistry: Shared registry for game sessions
"""

import asyncio
import socket
import struct
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Optional

from app.models.natneg_types import (
    NatNegClient,
    NatNegClientConnection,
    NatNegClientIndex,
    NatNegPortType,
    NatNegSession,
)
from app.models.relay_types import PairAttemptInfo
from app.servers.query_master_parsing import GameEntry
from app.util.logging_helper import get_logger

logger = get_logger(__name__)


# =============================================================================
# Constants
# =============================================================================

# Session timeout in seconds (how long to wait for both clients)
SESSION_TIMEOUT = 30.0

# Delay before sending CONNECT after both clients register (allows late packets)
CONNECT_DELAY = 0.1  # 100ms to ensure all INIT packets are processed


# =============================================================================
# SessionManager - Generic session tracking for GP server
# =============================================================================


class SessionManager:
    """
    Generic session manager for GP server connections.

    Tracks active users by session key and persona ID for buddy lookups.
    """

    def __init__(self):
        # Maps sesskey -> protocol_instance
        self.active_users: dict[str, asyncio.Protocol] = {}
        # Maps persona_id -> protocol_instance (for buddy lookups)
        self.users_by_persona: dict[int, asyncio.Protocol] = {}
        logger.debug("Session Manager initialized")

    def register_user(self, sesskey: str, protocol_instance: asyncio.Protocol):
        """Registers a user's protocol instance upon successful login."""
        self.active_users[sesskey] = protocol_instance

        # Also register by persona_id if available
        if hasattr(protocol_instance, "persona_id") and protocol_instance.persona_id:
            self.users_by_persona[protocol_instance.persona_id] = protocol_instance

        logger.debug("User '%s' registered. Total active users: %d", sesskey, len(self.active_users))

    def unregister_user(self, sesskey: str):
        """Unregisters a user, typically on disconnect."""
        protocol_instance = self.active_users.get(sesskey)
        if protocol_instance:
            # Remove from persona mapping
            if hasattr(protocol_instance, "persona_id") and protocol_instance.persona_id:
                self.users_by_persona.pop(protocol_instance.persona_id, None)

            del self.active_users[sesskey]
            logger.debug("User '%s' unregistered. Total active users: %d", sesskey, len(self.active_users))

    def get_user_by_persona_id(self, persona_id: int) -> asyncio.Protocol | None:
        """Gets a user's protocol instance by their persona ID."""
        return self.users_by_persona.get(persona_id)

    def is_user_online(self, persona_id: int) -> bool:
        """Checks if a user is online by their persona ID."""
        return persona_id in self.users_by_persona

    async def send_to_user(self, sesskey: str, message: str) -> bool:
        """Sends a message to a specific user if they are online."""
        protocol_instance = self.active_users.get(sesskey)
        if protocol_instance:
            # The transport object is used to write data to the socket
            protocol_instance.transport.write(message.encode("utf-8"))
            logger.debug("Sent message to '%s': %s", sesskey, message.strip())
            return True
        else:
            logger.debug("Failed to send message: User '%s' not found.", sesskey)
            return False

    async def send_to_persona(self, persona_id: int, message: str) -> bool:
        """Sends a message to a user by their persona ID."""
        protocol_instance = self.users_by_persona.get(persona_id)
        if protocol_instance and hasattr(protocol_instance, "transport"):
            protocol_instance.transport.write(message.encode("utf-8"))
            return True
        return False


# =============================================================================
# NatNegSessionManager - NAT negotiation session management
# =============================================================================


@dataclass
class ClientEndpoint:
    """Represents a client's network endpoint."""

    ip: str
    port: int

    def __hash__(self):
        return hash((self.ip, self.port))

    def __eq__(self, other):
        if not isinstance(other, ClientEndpoint):
            return False
        return self.ip == other.ip and self.port == other.port


class NatNegSessionManager:
    """
    Manages NAT negotiation sessions.

    Sessions are created when a client sends an INIT packet. The session
    is keyed by the session_id (cookie). When both host and guest have
    registered with the same cookie, the manager triggers CONNECT packets
    to be sent to both clients.

    Pair tracking: Tracks connection attempts by (host_ip, guest_ip) pair
    to implement progressive fallback (WAN -> LAN -> Relay). Session IDs
    change on retry, but the IP pair remains constant.
    """

    def __init__(self):
        # Session ID -> NatNegSession
        self._sessions: dict[int, NatNegSession] = {}

        # Client endpoint -> (session_id, client_index) for reverse lookup
        self._client_endpoints: dict[ClientEndpoint, tuple[int, NatNegClientIndex]] = {}

        # Host IP -> session count (for alternating LAN/WAN on port_type 1)
        # Tracks how many sessions we've processed per host IP
        self._host_session_counter: dict[str, int] = {}

        # (host_ip, guest_ip) -> PairAttemptInfo for tracking retry attempts
        # This is used to determine WAN/LAN/Relay mode across session retries
        self._pair_attempts: dict[tuple[str, str], PairAttemptInfo] = {}

        # Lock for thread safety
        self._lock = asyncio.Lock()

        # Callback for when session is ready (both clients registered)
        self._on_session_ready: Callable[[NatNegSession], Awaitable[None]] | None = None

    def set_on_session_ready(self, callback: Callable[[NatNegSession], Awaitable[None]]):
        """Set callback to be called when a session has both clients ready."""
        self._on_session_ready = callback

    async def register_client(
        self,
        session_id: int,
        client_index: NatNegClientIndex,
        port_type: NatNegPortType,
        public_ip: str,
        public_port: int,
        local_ip: str,
        local_port: int,
        game_name: str,
    ) -> NatNegSession:
        """
        Register a client connection for NAT negotiation.

        Clients send multiple INIT packets with different port_types (0-3).
        This method tracks all connections per client.

        Args:
            session_id: Session cookie (shared between host and guest)
            client_index: GUEST (0) or HOST (1)
            port_type: Port type from INIT packet (0-3)
            public_ip: Client's public IP (as seen by server)
            public_port: Client's public port (as seen by server)
            local_ip: Client's local IP (from INIT packet)
            local_port: Client's local port (from INIT packet)
            game_name: Game name from INIT packet

        Returns:
            The session object
        """
        async with self._lock:
            # Create connection object for this port_type
            connection = NatNegClientConnection(
                public_ip=public_ip,
                public_port=public_port,
                local_ip=local_ip,
                local_port=local_port,
                port_type=port_type,
            )

            endpoint = ClientEndpoint(public_ip, public_port)

            # Get or create session
            if session_id not in self._sessions:
                session = NatNegSession(session_id=session_id, game_name=game_name, created_at=time.time())
                self._sessions[session_id] = session
                logger.info("Created new NAT session %08X for game %s", session_id, game_name)
            else:
                session = self._sessions[session_id]

            # Get or create client for this role (host/guest)
            if client_index == NatNegClientIndex.HOST:
                if session.host is None:
                    session.host = NatNegClient(session_id=session_id, client_index=client_index, game_name=game_name)
                client = session.host
            else:
                if session.guest is None:
                    session.guest = NatNegClient(session_id=session_id, client_index=client_index, game_name=game_name)
                client = session.guest

            # Add this connection to the client
            client.add_connection(connection)

            logger.debug(
                "Session %08X %s port_type=%d: %s:%d (local: %s:%d)",
                session_id,
                client_index.name,
                port_type,
                public_ip,
                public_port,
                local_ip,
                local_port,
            )

            # Track endpoint for reverse lookup
            self._client_endpoints[endpoint] = (session_id, client_index)

            # Check if session is ready (both clients have valid connections)
            if session.is_ready() and not session.connect_sent:
                # Assign session order based on host IP
                # This is used to alternate LAN/WAN on port_type 1
                host_ip = session.host.public_ip
                self._host_session_counter[host_ip] = self._host_session_counter.get(host_ip, 0) + 1
                session.session_order = self._host_session_counter[host_ip]

                logger.info(
                    "Session %08X is ready! Both clients registered. Same LAN: %s, session_order=%d for host %s",
                    session_id,
                    session.are_same_lan(),
                    session.session_order,
                    host_ip,
                )
                logger.info(
                    "Session %08X - Host best conn: %s:%d (local: %s:%d)",
                    session_id,
                    session.host.public_ip,
                    session.host.public_port,
                    session.host.local_ip,
                    session.host.local_port,
                )
                logger.info(
                    "Session %08X - Guest best conn: %s:%d (local: %s:%d)",
                    session_id,
                    session.guest.public_ip,
                    session.guest.public_port,
                    session.guest.local_ip,
                    session.guest.local_port,
                )
                session.connect_sent = True

                # Trigger callback after a small delay
                if self._on_session_ready:
                    asyncio.create_task(self._delayed_session_ready(session))

            return session

    async def _delayed_session_ready(self, session: NatNegSession):
        """Call the session ready callback after a small delay."""
        await asyncio.sleep(CONNECT_DELAY)
        if self._on_session_ready:
            await self._on_session_ready(session)

    async def get_session(self, session_id: int) -> NatNegSession | None:
        """Get a session by its ID."""
        async with self._lock:
            return self._sessions.get(session_id)

    async def get_session_by_endpoint(self, ip: str, port: int) -> tuple[NatNegSession, NatNegClientIndex] | None:
        """
        Get a session by client endpoint.

        Returns:
            Tuple of (session, client_index) or None
        """
        async with self._lock:
            endpoint = ClientEndpoint(ip, port)
            result = self._client_endpoints.get(endpoint)
            if result is None:
                return None

            session_id, client_index = result
            session = self._sessions.get(session_id)
            if session is None:
                return None

            return session, client_index

    async def mark_connect_acked(self, session_id: int, client_index: NatNegClientIndex):
        """Mark that a client has acknowledged the CONNECT packet."""
        async with self._lock:
            session = self._sessions.get(session_id)
            if session is None:
                return

            if client_index == NatNegClientIndex.HOST and session.host:
                session.host.connect_acked = True
                logger.debug("Session %08X HOST acknowledged CONNECT", session_id)
            elif client_index == NatNegClientIndex.GUEST and session.guest:
                session.guest.connect_acked = True
                logger.debug("Session %08X GUEST acknowledged CONNECT", session_id)

            # Check if both have acked
            if session.host and session.host.connect_acked and session.guest and session.guest.connect_acked:
                session.completed = True
                logger.info("Session %08X completed successfully", session_id)

    async def remove_session(self, session_id: int):
        """Remove a session and its client endpoints."""
        async with self._lock:
            session = self._sessions.pop(session_id, None)
            if session is None:
                return

            # Remove endpoint mappings
            if session.host:
                endpoint = ClientEndpoint(session.host.public_ip, session.host.public_port)
                self._client_endpoints.pop(endpoint, None)

            if session.guest:
                endpoint = ClientEndpoint(session.guest.public_ip, session.guest.public_port)
                self._client_endpoints.pop(endpoint, None)

            logger.info("Removed session %08X", session_id)

    async def cleanup_expired_sessions(self):
        """Remove sessions that have timed out."""
        async with self._lock:
            now = time.time()
            expired = [
                session_id
                for session_id, session in self._sessions.items()
                if now - session.created_at > SESSION_TIMEOUT and not session.completed
            ]

            for session_id in expired:
                session = self._sessions.pop(session_id, None)
                if session:
                    logger.warning("Session %08X expired (age: %.1fs)", session_id, now - session.created_at)
                    # Clean up endpoint mappings
                    if session.host:
                        endpoint = ClientEndpoint(session.host.public_ip, session.host.public_port)
                        self._client_endpoints.pop(endpoint, None)
                    if session.guest:
                        endpoint = ClientEndpoint(session.guest.public_ip, session.guest.public_port)
                        self._client_endpoints.pop(endpoint, None)

    def get_session_count(self) -> int:
        """Get the number of active sessions."""
        return len(self._sessions)

    def get_client_count(self) -> int:
        """Get the number of registered clients."""
        return len(self._client_endpoints)

    async def get_pair_attempt(self, host_ip: str, guest_ip: str) -> PairAttemptInfo:
        """
        Get or create attempt info for a host-guest pair.

        Increments the attempt counter each time this is called.

        Args:
            host_ip: Host's public IP address.
            guest_ip: Guest's public IP address.

        Returns:
            PairAttemptInfo with incremented attempt count.
        """
        async with self._lock:
            pair = (host_ip, guest_ip)
            if pair not in self._pair_attempts:
                self._pair_attempts[pair] = PairAttemptInfo()
                logger.info("New pair tracking: %s <-> %s", host_ip, guest_ip)

            info = self._pair_attempts[pair]
            attempt = info.increment()
            logger.info(
                "Pair %s <-> %s: attempt #%d",
                host_ip,
                guest_ip,
                attempt,
            )
            return info

    async def update_pair_relay_ports(self, host_ip: str, guest_ip: str, ports: tuple[int, int]):
        """
        Store relay ports for a host-guest pair.

        Args:
            host_ip: Host's public IP address.
            guest_ip: Guest's public IP address.
            ports: Tuple of (port_a, port_b) relay ports.
        """
        async with self._lock:
            pair = (host_ip, guest_ip)
            if pair in self._pair_attempts:
                self._pair_attempts[pair].relay_ports = ports
                logger.info(
                    "Pair %s <-> %s: assigned relay ports %d, %d",
                    host_ip,
                    guest_ip,
                    ports[0],
                    ports[1],
                )

    async def get_pair_info(self, host_ip: str, guest_ip: str) -> PairAttemptInfo | None:
        """
        Get attempt info for a host-guest pair without incrementing.

        Args:
            host_ip: Host's public IP address.
            guest_ip: Guest's public IP address.

        Returns:
            PairAttemptInfo if exists, None otherwise.
        """
        async with self._lock:
            return self._pair_attempts.get((host_ip, guest_ip))

    async def cleanup_stale_pairs(self, ttl_seconds: float = 300.0):
        """
        Remove pair entries older than TTL.

        Args:
            ttl_seconds: Time-to-live in seconds (default 5 minutes).

        Returns:
            List of (host_ip, guest_ip, relay_ports) tuples for released pairs.
        """
        released = []
        async with self._lock:
            stale_pairs = [pair for pair, info in self._pair_attempts.items() if info.is_stale(ttl_seconds)]

            for pair in stale_pairs:
                info = self._pair_attempts.pop(pair)
                host_ip, guest_ip = pair
                logger.info(
                    "Expired pair tracking: %s <-> %s (attempts=%d)",
                    host_ip,
                    guest_ip,
                    info.attempt_count,
                )
                if info.relay_ports:
                    released.append((host_ip, guest_ip, info.relay_ports))

        return released

    def get_pair_count(self) -> int:
        """Get the number of tracked pairs."""
        return len(self._pair_attempts)


# =============================================================================
# GameSessionRegistry - Shared registry for game sessions
# =============================================================================


class GameSessionRegistry:
    """
    Shared registry for game sessions.

    This connects the UDP heartbeat server (where games register)
    with the TCP query server (where clients request game lists).
    Singleton pattern ensures all servers share the same registry.
    """

    _instance: Optional["GameSessionRegistry"] = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._sessions: dict[int, GameEntry] = {}  # client_id -> GameEntry
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

        # Check if session already exists
        existing_game = self._sessions.get(client_id)

        if existing_game:
            # Update existing GameEntry
            existing_game.public_ip = public_ip
            existing_game.public_port = public_port
            existing_game.private_ip = private_ip
            existing_game.private_port = private_port
            existing_game.traced_ip = host
            existing_game.traced_port = port
            existing_game.fields = info
            logger.debug(
                "Updated game: client_id=%d, host=%s:%d, hostname=%s",
                client_id,
                public_ip,
                public_port,
                info.get("hostname", "unknown"),
            )
        else:
            # Create new GameEntry
            game = GameEntry(
                public_ip=public_ip,
                public_port=public_port,
                private_ip=private_ip,
                private_port=private_port,
                traced_ip=host,
                traced_port=port,
                fields=info,
            )
            self._sessions[client_id] = game
            logger.info(
                "Registered game: client_id=%d, host=%s:%d, hostname=%s",
                client_id,
                public_ip,
                public_port,
                info.get("hostname", "unknown"),
            )

    def unregister_game(self, client_id: int):
        """Remove a game session."""
        if client_id in self._sessions:
            del self._sessions[client_id]
            logger.info("Unregistered game: client_id=%d", client_id)

    def get_games(self) -> list:
        """Get all registered games as a list of GameEntry objects."""
        return list(self._sessions.values())

    def get_game(self, client_id: int) -> GameEntry | None:
        """Get a specific game by client ID."""
        return self._sessions.get(client_id)

    def clear(self):
        """Clear all sessions."""
        self._sessions.clear()
