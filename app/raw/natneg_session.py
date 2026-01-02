"""
NAT Negotiation Session Manager.

Tracks NAT negotiation sessions and manages client matching.
Sessions are identified by a shared cookie (session_id) that both
the host and guest use to find each other.
"""

import asyncio
import time
from typing import Dict, Optional, Tuple, Callable, Awaitable
from dataclasses import dataclass, field

from app.models.natneg_types import (
    NatNegSession,
    NatNegClient,
    NatNegClientConnection,
    NatNegClientIndex,
    NatNegPortType,
)
from app.util.logging_helper import get_logger

logger = get_logger(__name__)


# Session timeout in seconds (how long to wait for both clients)
SESSION_TIMEOUT = 30.0

# Delay before sending CONNECT after both clients register (allows late packets)
CONNECT_DELAY = 0.1  # 100ms to ensure all INIT packets are processed


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
    """

    def __init__(self):
        # Session ID -> NatNegSession
        self._sessions: Dict[int, NatNegSession] = {}

        # Client endpoint -> (session_id, client_index) for reverse lookup
        self._client_endpoints: Dict[ClientEndpoint, Tuple[int, NatNegClientIndex]] = {}

        # Lock for thread safety
        self._lock = asyncio.Lock()

        # Callback for when session is ready (both clients registered)
        self._on_session_ready: Optional[Callable[[NatNegSession], Awaitable[None]]] = None

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
        game_name: str
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
                port_type=port_type
            )

            endpoint = ClientEndpoint(public_ip, public_port)

            # Get or create session
            if session_id not in self._sessions:
                session = NatNegSession(
                    session_id=session_id,
                    game_name=game_name,
                    created_at=time.time()
                )
                self._sessions[session_id] = session
                logger.info(
                    "Created new NAT session %08X for game %s",
                    session_id, game_name
                )
            else:
                session = self._sessions[session_id]

            # Get or create client for this role (host/guest)
            if client_index == NatNegClientIndex.HOST:
                if session.host is None:
                    session.host = NatNegClient(
                        session_id=session_id,
                        client_index=client_index,
                        game_name=game_name
                    )
                client = session.host
            else:
                if session.guest is None:
                    session.guest = NatNegClient(
                        session_id=session_id,
                        client_index=client_index,
                        game_name=game_name
                    )
                client = session.guest

            # Add this connection to the client
            client.add_connection(connection)

            logger.debug(
                "Session %08X %s port_type=%d: %s:%d (local: %s:%d)",
                session_id, client_index.name, port_type,
                public_ip, public_port, local_ip, local_port
            )

            # Track endpoint for reverse lookup
            self._client_endpoints[endpoint] = (session_id, client_index)

            # Check if session is ready (both clients have valid connections)
            if session.is_ready() and not session.connect_sent:
                logger.info(
                    "Session %08X is ready! Both clients registered. Same LAN: %s",
                    session_id, session.are_same_lan()
                )
                logger.info(
                    "Session %08X - Host best conn: %s:%d (local: %s:%d)",
                    session_id,
                    session.host.public_ip, session.host.public_port,
                    session.host.local_ip, session.host.local_port
                )
                logger.info(
                    "Session %08X - Guest best conn: %s:%d (local: %s:%d)",
                    session_id,
                    session.guest.public_ip, session.guest.public_port,
                    session.guest.local_ip, session.guest.local_port
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

    async def get_session(self, session_id: int) -> Optional[NatNegSession]:
        """Get a session by its ID."""
        async with self._lock:
            return self._sessions.get(session_id)

    async def get_session_by_endpoint(
        self,
        ip: str,
        port: int
    ) -> Optional[Tuple[NatNegSession, NatNegClientIndex]]:
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

    async def mark_connect_acked(
        self,
        session_id: int,
        client_index: NatNegClientIndex
    ):
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
            if (session.host and session.host.connect_acked and
                session.guest and session.guest.connect_acked):
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
                    logger.warning(
                        "Session %08X expired (age: %.1fs)",
                        session_id, now - session.created_at
                    )
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
