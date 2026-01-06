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
    build_address_reply_packet,
    build_connect_packet,
    build_init_ack_packet,
    build_report_ack_packet,
    is_natneg_packet,
    parse_init_packet,
    parse_natneg_packet,
    parse_report_packet,
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
            asyncio.create_task(self._handle_report(header, data, addr))
        elif header.record_type == NatNegRecordType.ADDRESS_CHECK:
            asyncio.create_task(self._handle_address_check(data, addr))
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
        Uses alternating mode for port_type 1 based on session order per host IP:
        - port_type 0: Always LAN
        - port_type 1: LAN for odd session_order (1, 3, 5...), WAN for even (2, 4, 6...)
        - port_type 2,3: Always WAN

        Game sends 3 sessions per lobby, and only uses port_type 1.
        This alternation helps test which address type works.
        """
        if not session.host or not session.guest:
            logger.error("Session ready but missing client(s)")
            return

        # Determine if port_type 1 should use LAN or WAN based on session order
        # Even session_order (0, 2, 4...) = LAN, Odd (1, 3, 5...) = WAN
        use_lan_for_pt1 = (session.session_order % 2) == 0
        pt1_mode = "LAN" if use_lan_for_pt1 else "WAN"

        logger.info(
            "Session %08X ready - session_order=%d, port_type_1=%s",
            session.session_id,
            session.session_order,
            pt1_mode,
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

        # Only send CONNECT for port_type 1
        # Send to guest
        if 1 in session.guest.connections:
            conn = session.guest.connections[1]
            if use_lan_for_pt1:
                packet = connect_lan_to_guest
                mode = "LAN"
                peer_ip, peer_port = session.host.local_ip, session.host.local_port
            else:
                packet = connect_wan_to_guest
                mode = "WAN"
                peer_ip, peer_port = session.host.public_ip, session.host.public_port
            self._send_to(packet, (conn.public_ip, conn.public_port))
            logger.info(
                "CONNECT to GUEST %s:%d (pt=1, %s) -> peer %s:%d",
                conn.public_ip,
                conn.public_port,
                mode,
                peer_ip,
                peer_port,
            )

        # Send to host
        if 1 in session.host.connections:
            conn = session.host.connections[1]
            if use_lan_for_pt1:
                packet = connect_lan_to_host
                mode = "LAN"
                peer_ip, peer_port = session.guest.local_ip, session.guest.local_port
            else:
                packet = connect_wan_to_host
                mode = "WAN"
                peer_ip, peer_port = session.guest.public_ip, session.guest.public_port
            self._send_to(packet, (conn.public_ip, conn.public_port))
            logger.info(
                "CONNECT to HOST %s:%d (pt=1, %s) -> peer %s:%d",
                conn.public_ip,
                conn.public_port,
                mode,
                peer_ip,
                peer_port,
            )

        logger.info(
            "Session %08X: Sent CONNECT only to port_type 1 (session_order=%d, mode=%s)",
            session.session_id,
            session.session_order,
            pt1_mode,
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

    async def _handle_report(self, header: NatNegHeader, data: bytes, addr: tuple[str, int]):
        """Handle REPORT packet from client."""
        client_ip, client_port = addr

        # Parse full REPORT packet for detailed logging
        report = parse_report_packet(data)
        if report:
            logger.info(
                "REPORT from %s:%d - session=%08X, index=%s, port_type=%d, nat_type=%d, mapping=%d, game=%s",
                client_ip,
                client_port,
                header.session_id,
                header.client_index.name,
                report.port_type,
                report.nat_type,
                report.mapping_scheme,
                report.game_name,
            )
            logger.debug("REPORT raw: %s", format_hex(data))
        else:
            logger.info(
                "REPORT from %s:%d (session=%08X, index=%s) - parse failed",
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

    async def _handle_address_check(self, data: bytes, addr: tuple[str, int]):
        """
        Handle ADDRESS_CHECK packet from client.

        Responds with ADDRESS_REPLY containing the client's public IP:port
        as seen by the server. This allows clients to discover their
        external address for NAT traversal.
        """
        client_ip, client_port = addr

        logger.info(
            "ADDRESS_CHECK from %s:%d - responding with public address",
            client_ip,
            client_port,
        )

        # Build and send ADDRESS_REPLY with client's public IP:port
        reply_packet = build_address_reply_packet(data, client_ip, client_port)
        self._send_to(reply_packet, addr)

        logger.debug(
            "Sent ADDRESS_REPLY to %s:%d (public=%s:%d)",
            client_ip,
            client_port,
            client_ip,
            client_port,
        )

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
