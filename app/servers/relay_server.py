"""
UDP Relay Server for NAT Traversal.

Provides relay functionality as a fallback when direct P2P connections fail.
Each relay session uses a pair of ports - traffic received on one port
is forwarded to the client associated with the other port.
"""

import asyncio
from dataclasses import dataclass, field

from app.models.relay_types import RelayEndpoint, RelayRoute
from app.servers.port_pool import PortPool
from app.util.logging_helper import get_logger

logger = get_logger(__name__)


class RelayPortProtocol(asyncio.DatagramProtocol):
    """
    Protocol handler for a single relay port.

    Receives UDP packets and forwards them to the peer endpoint.
    """

    def __init__(self, relay_server: "RelayServer", port: int, peer_port: int):
        """
        Initialize relay port protocol.

        Args:
            relay_server: Parent relay server for routing lookups.
            port: This port number (for logging).
            peer_port: The paired port number.
        """
        self.relay_server = relay_server
        self.port = port
        self.peer_port = peer_port
        self.transport: asyncio.DatagramTransport | None = None

    def connection_made(self, transport: asyncio.DatagramTransport):
        """Called when the UDP socket is ready."""
        self.transport = transport
        logger.debug("Relay port %d ready", self.port)

    def datagram_received(self, data: bytes, addr: tuple[str, int]):
        """
        Handle incoming UDP datagram.

        Registers the sender as a client and forwards to peer.
        """
        client_ip, client_port = addr

        # Get the route for this port pair
        route = self.relay_server.get_route_by_port(self.port)
        if route is None:
            logger.warning("No route found for relay port %d", self.port)
            return

        # Update activity
        route.update_activity()

        # Register client endpoint if not set
        client_endpoint = RelayEndpoint(client_ip, client_port)
        if self.port == route.port_a:
            if route.client_a is None:
                route.client_a = client_endpoint
                logger.info(
                    "Relay port %d: registered client A at %s:%d",
                    self.port,
                    client_ip,
                    client_port,
                )
            peer_endpoint = route.client_b
        else:  # port_b
            if route.client_b is None:
                route.client_b = client_endpoint
                logger.info(
                    "Relay port %d: registered client B at %s:%d",
                    self.port,
                    client_ip,
                    client_port,
                )
            peer_endpoint = route.client_a

        # Forward to peer if known
        if peer_endpoint is not None:
            peer_transport = self.relay_server.get_transport(self.peer_port)
            if peer_transport is not None:
                peer_transport.sendto(data, peer_endpoint.as_tuple())
                route.packets_forwarded += 1
                route.bytes_forwarded += len(data)
                logger.debug(
                    "Relay %d->%d: %d bytes from %s:%d to %s:%d",
                    self.port,
                    self.peer_port,
                    len(data),
                    client_ip,
                    client_port,
                    peer_endpoint.ip,
                    peer_endpoint.port,
                )
        else:
            logger.debug(
                "Relay port %d: buffering packet, peer not yet registered",
                self.port,
            )

    def connection_lost(self, exc: Exception | None):
        """Called when the connection is closed."""
        logger.debug("Relay port %d closed", self.port)

    def error_received(self, exc: Exception):
        """Handle error on the UDP socket."""
        logger.error("Relay port %d error: %s", self.port, exc)


@dataclass
class RelayServer:
    """
    UDP Relay Server.

    Manages multiple relay port pairs for NAT traversal fallback.
    Each pair forwards traffic bidirectionally between two clients.
    """

    host: str = "0.0.0.0"
    port_pool: PortPool = field(default_factory=PortPool)
    session_timeout: float = 120.0  # Seconds of inactivity before cleanup

    # Active routes by port pair key (min_port, max_port)
    _routes: dict[tuple[int, int], RelayRoute] = field(default_factory=dict)

    # Port -> transport mapping for sending
    _transports: dict[int, asyncio.DatagramTransport] = field(default_factory=dict)

    # Port -> protocol mapping
    _protocols: dict[int, RelayPortProtocol] = field(default_factory=dict)

    # Lock for thread safety
    _lock: asyncio.Lock = field(default_factory=asyncio.Lock)

    # Cleanup task
    _cleanup_task: asyncio.Task | None = None

    async def start(self):
        """Start the relay server and cleanup task."""
        logger.info(
            "Relay server starting (host=%s, ports=%d-%d, timeout=%ds)",
            self.host,
            self.port_pool.port_start,
            self.port_pool.port_end,
            int(self.session_timeout),
        )
        self._cleanup_task = asyncio.create_task(self._cleanup_loop())

    async def stop(self):
        """Stop the relay server and cleanup all resources."""
        logger.info("Relay server stopping...")

        # Cancel cleanup task
        if self._cleanup_task:
            self._cleanup_task.cancel()
            try:
                await self._cleanup_task
            except asyncio.CancelledError:
                pass

        # Close all transports
        for transport in list(self._transports.values()):
            transport.close()

        self._transports.clear()
        self._protocols.clear()
        self._routes.clear()

        logger.info("Relay server stopped")

    async def allocate_route(self) -> RelayRoute | None:
        """
        Allocate a new relay route with a port pair.

        Returns:
            RelayRoute with allocated ports, or None if no ports available.
        """
        async with self._lock:
            # Allocate port pair
            ports = await self.port_pool.allocate_pair()
            if ports is None:
                logger.warning("Failed to allocate relay ports - pool exhausted")
                return None

            port_a, port_b = ports

            # Create route
            route = RelayRoute(port_a=port_a, port_b=port_b)
            route_key = (min(port_a, port_b), max(port_a, port_b))
            self._routes[route_key] = route

            # Start listeners for both ports
            try:
                await self._start_port_listener(port_a, port_b)
                await self._start_port_listener(port_b, port_a)
            except OSError as e:
                logger.error("Failed to start relay listeners: %s", e)
                # Cleanup on failure
                await self.port_pool.release_pair(ports)
                self._routes.pop(route_key, None)
                return None

            logger.info("Allocated relay route: ports %d <-> %d", port_a, port_b)
            return route

    async def _start_port_listener(self, port: int, peer_port: int):
        """Start a UDP listener on the specified port."""
        loop = asyncio.get_running_loop()
        transport, protocol = await loop.create_datagram_endpoint(
            lambda: RelayPortProtocol(self, port, peer_port),
            local_addr=(self.host, port),
        )
        self._transports[port] = transport
        self._protocols[port] = protocol

    async def release_route(self, route: RelayRoute):
        """Release a relay route and its ports."""
        async with self._lock:
            route_key = (min(route.port_a, route.port_b), max(route.port_a, route.port_b))

            # Close transports
            for port in (route.port_a, route.port_b):
                transport = self._transports.pop(port, None)
                if transport:
                    transport.close()
                self._protocols.pop(port, None)

            # Release ports
            await self.port_pool.release_pair((route.port_a, route.port_b))

            # Remove route
            self._routes.pop(route_key, None)

            logger.info(
                "Released relay route: ports %d <-> %d (forwarded %d packets, %d bytes)",
                route.port_a,
                route.port_b,
                route.packets_forwarded,
                route.bytes_forwarded,
            )

    def get_route_by_port(self, port: int) -> RelayRoute | None:
        """Get the route associated with a port."""
        for route_key, route in self._routes.items():
            if route.port_a == port or route.port_b == port:
                return route
        return None

    def get_transport(self, port: int) -> asyncio.DatagramTransport | None:
        """Get the transport for a specific port."""
        return self._transports.get(port)

    async def _cleanup_loop(self):
        """Periodically clean up stale relay routes."""
        try:
            while True:
                await asyncio.sleep(30.0)  # Check every 30 seconds
                await self._cleanup_stale_routes()
        except asyncio.CancelledError:
            pass

    async def _cleanup_stale_routes(self):
        """Remove routes that have been inactive for too long."""
        stale_routes = []

        async with self._lock:
            for route_key, route in self._routes.items():
                if route.is_stale(self.session_timeout):
                    stale_routes.append(route)

        for route in stale_routes:
            logger.info(
                "Cleaning up stale relay route: ports %d <-> %d",
                route.port_a,
                route.port_b,
            )
            await self.release_route(route)

    @property
    def active_route_count(self) -> int:
        """Get the number of active relay routes."""
        return len(self._routes)


async def start_relay_server(
    host: str = "0.0.0.0",
    port_start: int = 50000,
    port_end: int = 59999,
    session_timeout: float = 120.0,
) -> RelayServer:
    """
    Start the relay server.

    Args:
        host: Host to bind to.
        port_start: Start of port range for relay.
        port_end: End of port range for relay.
        session_timeout: Seconds of inactivity before route cleanup.

    Returns:
        The started RelayServer instance.
    """
    port_pool = PortPool(port_start=port_start, port_end=port_end)
    server = RelayServer(
        host=host,
        port_pool=port_pool,
        session_timeout=session_timeout,
    )
    await server.start()
    return server
