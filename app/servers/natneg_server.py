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
from app.models.relay_types import PairAttemptInfo
from app.servers.relay_server import RelayServer
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
    3. When both host and guest register, sends CONNECT packets with progressive fallback:
       - Attempt 1: WAN addresses (public_ip:public_port)
       - Attempt 2: LAN addresses (local_ip:local_port)
       - Attempt 3+: Relay addresses (relay server ports)
    4. Handles CONNECT_ACK and REPORT packets
    """

    def __init__(
        self,
        session_manager: NatNegSessionManager | None = None,
        relay_server: RelayServer | None = None,
        pair_ttl: float = 300.0,
    ):
        """
        Initialize the NAT negotiation server.

        Args:
            session_manager: Optional session manager. If None, creates a new one.
            relay_server: Optional relay server for fallback connections.
            pair_ttl: Time-to-live for pair attempt tracking in seconds.
        """
        self.transport: asyncio.DatagramTransport | None = None
        self.session_manager = session_manager or NatNegSessionManager()
        self.relay_server = relay_server
        self.pair_ttl = pair_ttl

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

        Implements progressive fallback based on pair attempt count:
        - Attempt 1: WAN addresses (public IP, most common scenario)
        - Attempt 2: LAN addresses (same network)
        - Attempt 3+: Relay addresses (guaranteed to work)

        The attempt count is tracked by (host_ip, guest_ip) pair since
        clients retry with new session_ids on connection failure.
        """
        if not session.host or not session.guest:
            logger.error("Session ready but missing client(s)")
            return

        # Get pair attempt info (increments counter)
        pair_info = await self.session_manager.get_pair_attempt(
            session.host.public_ip,
            session.guest.public_ip,
        )
        attempt = pair_info.attempt_count

        # Determine address mode based on attempt count
        if attempt == 1:
            address_mode = "wan"
        elif attempt == 2:
            address_mode = "lan"
        else:
            address_mode = "relay"

        logger.info(
            "Session %08X ready - pair attempt #%d, mode=%s",
            session.session_id,
            attempt,
            address_mode.upper(),
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

        # Handle relay mode
        if address_mode == "relay":
            await self._send_connect_relay(session, pair_info)
            return

        # Build CONNECT packets for WAN or LAN mode
        if address_mode == "wan":
            # WAN: Use public addresses as seen by server
            host_ip, host_port = session.host.public_ip, session.host.public_port
            guest_ip, guest_port = session.guest.public_ip, session.guest.public_port
        else:
            # LAN: Use local addresses from INIT packets
            host_ip, host_port = session.host.local_ip, session.host.local_port
            guest_ip, guest_port = session.guest.local_ip, session.guest.local_port

        # Build CONNECT packets
        connect_to_guest = build_connect_packet(
            session_id=session.session_id,
            peer_ip=host_ip,
            peer_port=host_port,
            got_data=True,
            finished=True,
        )
        connect_to_host = build_connect_packet(
            session_id=session.session_id,
            peer_ip=guest_ip,
            peer_port=guest_port,
            got_data=True,
            finished=True,
        )

        # Send CONNECT packets (only for port_type 1)
        self._send_connect_to_client(session, session.guest, connect_to_guest, address_mode.upper(), host_ip, host_port)
        self._send_connect_to_client(session, session.host, connect_to_host, address_mode.upper(), guest_ip, guest_port)

        logger.info(
            "Session %08X: Sent CONNECT (attempt #%d, mode=%s)",
            session.session_id,
            attempt,
            address_mode.upper(),
        )

    def _send_connect_to_client(
        self,
        session: NatNegSession,
        client,
        packet: bytes,
        mode: str,
        peer_ip: str,
        peer_port: int,
    ):
        """Send CONNECT packet to a client's port_type 1 connection."""
        if 1 not in client.connections:
            logger.warning(
                "Session %08X: %s has no port_type 1 connection",
                session.session_id,
                client.client_index.name,
            )
            return

        conn = client.connections[1]
        self._send_to(packet, (conn.public_ip, conn.public_port))
        logger.info(
            "CONNECT to %s %s:%d (pt=1, %s) -> peer %s:%d",
            client.client_index.name,
            conn.public_ip,
            conn.public_port,
            mode,
            peer_ip,
            peer_port,
        )

    async def _send_connect_relay(self, session: NatNegSession, pair_info: PairAttemptInfo):
        """
        Send CONNECT packets with relay server addresses.

        Allocates relay ports if not already allocated for this pair.
        """
        if self.relay_server is None:
            logger.warning(
                "Session %08X: Relay requested but no relay server available, falling back to WAN",
                session.session_id,
            )
            # Fall back to WAN if no relay server
            await self._send_connect_fallback_wan(session)
            return

        # Atomically allocate relay ports if not already done for this pair
        relay_ports = await self.session_manager.allocate_pair_relay_if_missing(
            session.host.public_ip,
            session.guest.public_ip,
            self.relay_server,
        )
        if relay_ports is None:
            logger.error(
                "Session %08X: Failed to allocate relay ports, falling back to WAN",
                session.session_id,
            )
            await self._send_connect_fallback_wan(session)
            return

        port_a, port_b = relay_ports

        # Get relay server host (use the transport's local address)
        relay_host = self.relay_server.host
        if relay_host == "0.0.0.0" and self.transport:
            # Use the natneg server's bound address as relay address
            # This assumes relay and natneg are on the same machine
            sockname = self.transport.get_extra_info("sockname")
            if sockname and sockname[0] != "0.0.0.0":
                relay_host = sockname[0]

        # If still 0.0.0.0, we need a proper public IP
        # For now, use the server's perspective of the connection
        # In production, this should be configured
        if relay_host == "0.0.0.0":
            logger.warning(
                "Session %08X: Relay host is 0.0.0.0, clients may not be able to connect",
                session.session_id,
            )

        logger.info(
            "Session %08X: Using relay at %s ports %d (host) and %d (guest)",
            session.session_id,
            relay_host,
            port_a,
            port_b,
        )

        # Build CONNECT packets pointing to relay ports
        # connect_to_guest (peer_port=port_a) instructs the guest to connect to relay_host:port_a to reach the host
        # connect_to_host (peer_port=port_b) instructs the host to connect to relay_host:port_b to reach the guest
        connect_to_guest = build_connect_packet(
            session_id=session.session_id,
            peer_ip=relay_host,
            peer_port=port_a,
            got_data=True,
            finished=True,
        )
        connect_to_host = build_connect_packet(
            session_id=session.session_id,
            peer_ip=relay_host,
            peer_port=port_b,
            got_data=True,
            finished=True,
        )

        # Send CONNECT packets
        self._send_connect_to_client(session, session.guest, connect_to_guest, "RELAY", relay_host, port_a)
        self._send_connect_to_client(session, session.host, connect_to_host, "RELAY", relay_host, port_b)

        logger.info(
            "Session %08X: Sent CONNECT via RELAY (ports %d <-> %d)",
            session.session_id,
            port_a,
            port_b,
        )

    async def _send_connect_fallback_wan(self, session: NatNegSession):
        """Send CONNECT with WAN addresses as fallback when relay unavailable."""
        connect_to_guest = build_connect_packet(
            session_id=session.session_id,
            peer_ip=session.host.public_ip,
            peer_port=session.host.public_port,
            got_data=True,
            finished=True,
        )
        connect_to_host = build_connect_packet(
            session_id=session.session_id,
            peer_ip=session.guest.public_ip,
            peer_port=session.guest.public_port,
            got_data=True,
            finished=True,
        )

        self._send_connect_to_client(
            session,
            session.guest,
            connect_to_guest,
            "WAN-FALLBACK",
            session.host.public_ip,
            session.host.public_port,
        )
        self._send_connect_to_client(
            session,
            session.host,
            connect_to_host,
            "WAN-FALLBACK",
            session.guest.public_ip,
            session.guest.public_port,
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
        """Periodically clean up expired sessions and stale pairs."""
        try:
            while True:
                await asyncio.sleep(10.0)  # Run every 10 seconds
                await self.session_manager.cleanup_expired_sessions()

                # Cleanup stale pair tracking entries
                released_pairs = await self.session_manager.cleanup_stale_pairs(self.pair_ttl)

                # Release relay routes for expired pairs only if the route is stale
                if self.relay_server and released_pairs:
                    for host_ip, guest_ip, relay_ports in released_pairs:
                        route = self.relay_server.get_route_by_port(relay_ports[0])
                        if route:
                            # Only release if the route is stale (no recent traffic)
                            # Otherwise let RelayServer's own traffic-based timeout handle it
                            if route.is_stale(self.relay_server.session_timeout):
                                await self.relay_server.release_route(route)
                                logger.info(
                                    "Released relay route for expired pair %s <-> %s",
                                    host_ip,
                                    guest_ip,
                                )
                            else:
                                logger.debug(
                                    "Skipping relay route release for pair %s <-> %s - route still active",
                                    host_ip,
                                    guest_ip,
                                )
        except asyncio.CancelledError:
            pass

    def error_received(self, exc: Exception):
        """Handle error on the UDP socket."""
        logger.error("UDP error: %s", exc)


async def start_natneg_server(
    host: str = "0.0.0.0",
    port: int = 27901,
    session_manager: NatNegSessionManager | None = None,
    relay_server: RelayServer | None = None,
    pair_ttl: float = 300.0,
) -> tuple[asyncio.DatagramTransport, NatNegServer]:
    """
    Start the NAT negotiation UDP server.

    Args:
        host: Host to bind to
        port: Port to bind to (default 27901)
        session_manager: Optional shared session manager
        relay_server: Optional relay server for fallback connections
        pair_ttl: Time-to-live for pair attempt tracking in seconds

    Returns:
        Tuple of (transport, protocol)
    """
    loop = asyncio.get_running_loop()

    transport, protocol = await loop.create_datagram_endpoint(
        lambda: NatNegServer(session_manager, relay_server, pair_ttl),
        local_addr=(host, port),
    )

    return transport, protocol
