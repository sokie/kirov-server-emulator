"""
NAT Negotiation UDP Server.

Implements the GameSpy NAT negotiation protocol for Red Alert 3.
Listens on UDP port 27901 and facilitates NAT traversal between clients.

The server supports LAN mode where clients on the same public IP
are directed to use their local IP addresses for P2P connections.
"""

import asyncio

from app.config.app_settings import app_config
from app.models.natneg_types import (
    NatNegHeader,
    NatNegRecordType,
    NatNegSession,
)
from app.servers.sessions import NatNegSessionManager
from app.util.logging_helper import format_hex, get_logger
from app.util.natneg_protocol import (
    build_connect_packet,
    build_init_ack_packet,
    build_report_ack_packet,
    is_natneg_packet,
    parse_init_packet,
    parse_natneg_packet,
)

logger = get_logger(__name__)


class NatNegServer(asyncio.DatagramProtocol):
    """
    NAT Negotiation UDP Server Protocol.

    Handles the GameSpy NAT negotiation protocol:
    1. Receives INIT packets from clients
    2. Responds with INIT_ACK
    3. When both host and guest register with same session_id, sends CONNECT to both
    4. For LAN clients (same public IP), uses local IPs in CONNECT packets
    5. Handles CONNECT_ACK and REPORT packets
    """

    def __init__(self, session_manager: NatNegSessionManager | None = None):
        """
        Initialize the NAT negotiation server.

        Args:
            session_manager: Optional session manager. If None, creates a new one.
        """
        self.transport: asyncio.DatagramTransport | None = None
        self.session_manager = session_manager or NatNegSessionManager()

        # Set up the session ready callback
        self.session_manager.set_on_session_ready(self._on_session_ready)

        # Task for cleanup
        self._cleanup_task: asyncio.Task | None = None

    def connection_made(self, transport: asyncio.DatagramTransport):
        """Called when the UDP socket is ready."""
        self.transport = transport
        local_addr = transport.get_extra_info("sockname")
        logger.info("NAT Negotiation server listening on %s:%d", local_addr[0], local_addr[1])

        # Start cleanup task
        self._cleanup_task = asyncio.create_task(self._cleanup_loop())

    def connection_lost(self, exc: Exception | None):
        """Called when the connection is closed."""
        logger.info("NAT Negotiation server stopped")
        if self._cleanup_task:
            self._cleanup_task.cancel()

    def datagram_received(self, data: bytes, addr: tuple[str, int]):
        """
        Handle incoming UDP datagram.

        Args:
            data: Raw packet bytes
            addr: (ip, port) tuple of the sender
        """
        client_ip, client_port = addr

        # Check if this is a natneg packet
        if not is_natneg_packet(data):
            logger.debug("Received non-natneg packet from %s:%d (%d bytes)", client_ip, client_port, len(data))
            return

        # Parse the header
        result = parse_natneg_packet(data)
        if result is None:
            logger.warning("Failed to parse natneg packet from %s:%d", client_ip, client_port)
            return

        header, payload = result

        logger.debug(
            "Received %s from %s:%d (session=%08X, index=%s)",
            header.record_type.name,
            client_ip,
            client_port,
            header.session_id,
            header.client_index.name,
        )

        # Route to appropriate handler
        if header.record_type == NatNegRecordType.INIT:
            asyncio.create_task(self._handle_init(data, addr))
        elif header.record_type == NatNegRecordType.CONNECT_ACK:
            asyncio.create_task(self._handle_connect_ack(header, addr))
        elif header.record_type == NatNegRecordType.REPORT:
            asyncio.create_task(self._handle_report(header, addr))
        elif header.record_type == NatNegRecordType.CONNECT_PING:
            # This is P2P traffic, we just ignore it
            logger.debug("Received CONNECT_PING (P2P) from %s:%d", client_ip, client_port)
        else:
            logger.debug("Unhandled record type %s from %s:%d", header.record_type.name, client_ip, client_port)

    async def _handle_init(self, data: bytes, addr: tuple[str, int]):
        """
        Handle INIT packet from client.

        This registers the client in a session and sends INIT_ACK.
        """
        client_ip, client_port = addr

        # Parse the INIT packet
        init_packet = parse_init_packet(data)
        if init_packet is None:
            logger.warning("Failed to parse INIT packet from %s:%d", client_ip, client_port)
            return

        logger.info(
            "INIT from %s:%d - session=%08X, index=%s, local=%s:%d, game=%s",
            client_ip,
            client_port,
            init_packet.header.session_id,
            init_packet.header.client_index.name,
            init_packet.local_ip,
            init_packet.local_port,
            init_packet.game_name,
        )

        # Register the client
        await self.session_manager.register_client(
            session_id=init_packet.header.session_id,
            client_index=init_packet.header.client_index,
            port_type=init_packet.header.port_type,
            public_ip=client_ip,
            public_port=client_port,
            local_ip=init_packet.local_ip,
            local_port=init_packet.local_port,
            game_name=init_packet.game_name,
        )

        # Send INIT_ACK
        ack_packet = build_init_ack_packet(
            session_id=init_packet.header.session_id,
            port_type=init_packet.header.port_type,
            client_index=init_packet.header.client_index,
        )

        self._send_to(ack_packet, addr)
        logger.debug("Sent INIT_ACK to %s:%d", client_ip, client_port)

    async def _on_session_ready(self, session: NatNegSession):
        """
        Called when a session has both clients registered.

        Sends CONNECT packets to ALL connections of both clients.
        Uses LAN mode by default (local IPs from INIT packets).
        WAN mode (NAT punchthrough) is experimental and requires force_lan_mode=false in config.
        """
        if not session.host or not session.guest:
            logger.error("Session ready but missing client(s)")
            return

        # Determine whether to use LAN or WAN mode
        # Default: force_lan_mode=True (always use local IPs)
        # If force_lan_mode=False, auto-detect based on public IPs
        force_lan = app_config.natneg.force_lan_mode
        if force_lan:
            use_lan_mode = True
        else:
            # Auto-detect: use LAN mode if clients are on same network
            use_lan_mode = session.are_same_lan()

        logger.info(
            "Session %08X ready - sending CONNECT packets (LAN mode: %s, forced: %s)",
            session.session_id,
            use_lan_mode,
            force_lan,
        )

        # Determine addresses to use for P2P connection
        # For LAN, use local addresses from INIT packets (where game listens)
        # For WAN, use public addresses (requires NAT punchthrough - experimental)
        if use_lan_mode:
            # LAN mode: use local IP:port from INIT packet
            host_ip_for_guest = session.host.local_ip
            host_port_for_guest = session.host.local_port
            guest_ip_for_host = session.guest.local_ip
            guest_port_for_host = session.guest.local_port
            logger.info(
                "LAN mode: Host(%s:%d) <-> Guest(%s:%d)",
                host_ip_for_guest,
                host_port_for_guest,
                guest_ip_for_host,
                guest_port_for_host,
            )
        else:
            # WAN mode: use public addresses (experimental - NAT punchthrough may not work)
            host_ip_for_guest = session.host.public_ip
            host_port_for_guest = session.host.public_port
            guest_ip_for_host = session.guest.public_ip
            guest_port_for_host = session.guest.public_port
            logger.warning(
                "WAN mode (experimental): Host(%s:%d) <-> Guest(%s:%d) - NAT punchthrough may fail",
                host_ip_for_guest,
                host_port_for_guest,
                guest_ip_for_host,
                guest_port_for_host,
            )

        # Build CONNECT packet for guest (telling them about host)
        # CONNECT packets don't include port_type/client_index - same packet to all connections
        connect_to_guest = build_connect_packet(
            session_id=session.session_id,
            peer_ip=host_ip_for_guest,
            peer_port=host_port_for_guest,
            got_data=True,
            finished=True,
        )

        # Send CONNECT to ALL guest connections
        for port_type, conn in session.guest.connections.items():
            guest_addr = (conn.public_ip, conn.public_port)
            self._send_to(connect_to_guest, guest_addr)
            logger.debug(
                "Sent CONNECT to GUEST %s:%d (port_type=%d) -> peer %s:%d",
                conn.public_ip,
                conn.public_port,
                port_type,
                host_ip_for_guest,
                host_port_for_guest,
            )

        # Build CONNECT packet for host (telling them about guest)
        connect_to_host = build_connect_packet(
            session_id=session.session_id,
            peer_ip=guest_ip_for_host,
            peer_port=guest_port_for_host,
            got_data=True,
            finished=True,
        )

        # Send CONNECT to ALL host connections
        for port_type, conn in session.host.connections.items():
            host_addr = (conn.public_ip, conn.public_port)
            self._send_to(connect_to_host, host_addr)
            logger.debug(
                "Sent CONNECT to HOST %s:%d (port_type=%d) -> peer %s:%d",
                conn.public_ip,
                conn.public_port,
                port_type,
                guest_ip_for_host,
                guest_port_for_host,
            )

        logger.info(
            "Session %08X: Sent CONNECT to %d guest connections and %d host connections",
            session.session_id,
            len(session.guest.connections),
            len(session.host.connections),
        )

    async def _handle_connect_ack(self, header: NatNegHeader, addr: tuple[str, int]):
        """Handle CONNECT_ACK packet from client."""
        client_ip, client_port = addr

        logger.debug(
            "CONNECT_ACK from %s:%d (session=%08X, index=%s)",
            client_ip,
            client_port,
            header.session_id,
            header.client_index.name,
        )

        await self.session_manager.mark_connect_acked(session_id=header.session_id, client_index=header.client_index)

    async def _handle_report(self, header: NatNegHeader, addr: tuple[str, int]):
        """Handle REPORT packet from client."""
        client_ip, client_port = addr

        logger.info(
            "REPORT from %s:%d (session=%08X, index=%s)",
            client_ip,
            client_port,
            header.session_id,
            header.client_index.name,
        )

        # Send REPORT_ACK
        ack_packet = build_report_ack_packet(
            session_id=header.session_id, port_type=header.port_type, client_index=header.client_index
        )

        self._send_to(ack_packet, addr)
        logger.debug("Sent REPORT_ACK to %s:%d", client_ip, client_port)

    def _send_to(self, data: bytes, addr: tuple[str, int]):
        """Send a packet to the specified address."""
        if self.transport:
            self.transport.sendto(data, addr)
            logger.debug("TX to %s:%d (%d bytes): %s", addr[0], addr[1], len(data), format_hex(data[:20]))

    async def _cleanup_loop(self):
        """Periodically clean up expired sessions."""
        try:
            while True:
                await asyncio.sleep(10.0)  # Run every 10 seconds
                await self.session_manager.cleanup_expired_sessions()
        except asyncio.CancelledError:
            pass

    def error_received(self, exc: Exception):
        """Handle error on the UDP socket."""
        logger.error("UDP error: %s", exc)


async def start_natneg_server(
    host: str = "0.0.0.0", port: int = 27901, session_manager: NatNegSessionManager | None = None
) -> tuple[asyncio.DatagramTransport, NatNegServer]:
    """
    Start the NAT negotiation UDP server.

    Args:
        host: Host to bind to
        port: Port to bind to (default 27901)
        session_manager: Optional shared session manager

    Returns:
        Tuple of (transport, protocol)
    """
    loop = asyncio.get_running_loop()

    transport, protocol = await loop.create_datagram_endpoint(
        lambda: NatNegServer(session_manager), local_addr=(host, port)
    )

    return transport, protocol
