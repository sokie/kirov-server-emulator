"""
NAT Negotiation UDP Server.

Implements the GameSpy NAT negotiation protocol for Red Alert 3.
Listens on UDP port 27901 and facilitates NAT traversal between clients.

Uses dual-mode: sends both LAN and WAN addresses in CONNECT packets.
The game tries all connections, so whichever works will succeed,
enabling seamless LAN and WAN support without configuration.
"""

import asyncio

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
    1. Receives INIT packets from clients (4 per client with different port_types)
    2. Responds with INIT_ACK for each
    3. When both host and guest register, sends CONNECT to all connections
       - port_type 0,1: LAN addresses (local_ip:local_port)
       - port_type 2,3: WAN addresses (public_ip:public_port)
    4. Handles CONNECT_ACK and REPORT packets
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
        Uses dual mode: sends both LAN and WAN addresses across different port_types.
        - port_type 0,1: LAN addresses (local_ip:local_port)
        - port_type 2,3: WAN addresses (public_ip:public_port)

        The game tries all connections, so whichever works will succeed.
        This enables seamless LAN and WAN support without configuration.
        """
        if not session.host or not session.guest:
            logger.error("Session ready but missing client(s)")
            return

        logger.info(
            "Session %08X ready - sending dual-mode CONNECT packets (LAN + WAN)",
            session.session_id,
        )
        logger.info(
            "Session %08X - Host LAN: %s:%d, WAN: %s:%d",
            session.session_id,
            session.host.local_ip,
            session.host.local_port,
            session.host.public_ip,
            session.host.public_port,
        )
        logger.info(
            "Session %08X - Guest LAN: %s:%d, WAN: %s:%d",
            session.session_id,
            session.guest.local_ip,
            session.guest.local_port,
            session.guest.public_ip,
            session.guest.public_port,
        )

        # Build LAN CONNECT packets (using local addresses from INIT packets)
        connect_lan_to_guest = build_connect_packet(
            session_id=session.session_id,
            peer_ip=session.host.local_ip,
            peer_port=session.host.local_port,
            got_data=True,
            finished=True,
        )
        connect_lan_to_host = build_connect_packet(
            session_id=session.session_id,
            peer_ip=session.guest.local_ip,
            peer_port=session.guest.local_port,
            got_data=True,
            finished=True,
        )

        # Build WAN CONNECT packets (using public addresses as seen by server)
        connect_wan_to_guest = build_connect_packet(
            session_id=session.session_id,
            peer_ip=session.host.public_ip,
            peer_port=session.host.public_port,
            got_data=True,
            finished=True,
        )
        connect_wan_to_host = build_connect_packet(
            session_id=session.session_id,
            peer_ip=session.guest.public_ip,
            peer_port=session.guest.public_port,
            got_data=True,
            finished=True,
        )

        # Send to guest: LAN for port_type 0,1 | WAN for port_type 2,3
        for port_type, conn in session.guest.connections.items():
            if port_type <= 1:
                packet = connect_lan_to_guest
                mode = "LAN"
                peer_ip, peer_port = session.host.local_ip, session.host.local_port
            else:
                packet = connect_wan_to_guest
                mode = "WAN"
                peer_ip, peer_port = session.host.public_ip, session.host.public_port
            self._send_to(packet, (conn.public_ip, conn.public_port))
            logger.debug(
                "Sent CONNECT to GUEST %s:%d (port_type=%d, %s) -> peer %s:%d",
                conn.public_ip,
                conn.public_port,
                port_type,
                mode,
                peer_ip,
                peer_port,
            )

        # Send to host: LAN for port_type 0,1 | WAN for port_type 2,3
        for port_type, conn in session.host.connections.items():
            if port_type <= 1:
                packet = connect_lan_to_host
                mode = "LAN"
                peer_ip, peer_port = session.guest.local_ip, session.guest.local_port
            else:
                packet = connect_wan_to_host
                mode = "WAN"
                peer_ip, peer_port = session.guest.public_ip, session.guest.public_port
            self._send_to(packet, (conn.public_ip, conn.public_port))
            logger.debug(
                "Sent CONNECT to HOST %s:%d (port_type=%d, %s) -> peer %s:%d",
                conn.public_ip,
                conn.public_port,
                port_type,
                mode,
                peer_ip,
                peer_port,
            )

        logger.info(
            "Session %08X: Sent CONNECT to %d guest + %d host connections (dual LAN/WAN mode)",
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
