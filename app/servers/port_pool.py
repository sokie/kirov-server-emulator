"""
Port Pool Manager for Relay Server.

Manages allocation and release of UDP ports for relay connections.
Each relay session requires a pair of ports - one for each client.
"""

import asyncio
from dataclasses import dataclass, field

from app.util.logging_helper import get_logger

logger = get_logger(__name__)


@dataclass
class PortPool:
    """
    Manages a pool of ports for relay connections.

    Allocates ports in pairs for bidirectional relay between two clients.
    Each client connects to their assigned port and traffic is forwarded
    to the other client's endpoint.
    """

    port_start: int = 50000
    port_end: int = 59999

    # Track allocated ports
    _allocated: set[int] = field(default_factory=set)
    _lock: asyncio.Lock = field(default_factory=asyncio.Lock)

    def __post_init__(self):
        """Validate port range."""
        if self.port_start >= self.port_end:
            raise ValueError("port_start must be less than port_end")
        if self.port_start < 1024:
            raise ValueError("port_start must be >= 1024")
        if self.port_end > 65535:
            raise ValueError("port_end must be <= 65535")

        total_ports = self.port_end - self.port_start + 1
        max_pairs = total_ports // 2
        logger.info(
            "Port pool initialized: range %d-%d (%d ports, %d max pairs)",
            self.port_start,
            self.port_end,
            total_ports,
            max_pairs,
        )

    async def allocate_pair(self) -> tuple[int, int] | None:
        """
        Allocate a pair of consecutive ports for a relay session.

        Returns:
            Tuple of (port_a, port_b) or None if no ports available.
        """
        async with self._lock:
            # Find two consecutive available ports
            for port in range(self.port_start, self.port_end, 2):
                port_a = port
                port_b = port + 1

                if port_a not in self._allocated and port_b not in self._allocated:
                    self._allocated.add(port_a)
                    self._allocated.add(port_b)
                    logger.debug("Allocated port pair: %d, %d", port_a, port_b)
                    return (port_a, port_b)

            logger.warning("No available port pairs in pool")
            return None

    async def release_pair(self, ports: tuple[int, int]):
        """
        Release a pair of ports back to the pool.

        Args:
            ports: Tuple of (port_a, port_b) to release.
        """
        async with self._lock:
            port_a, port_b = ports
            self._allocated.discard(port_a)
            self._allocated.discard(port_b)
            logger.debug("Released port pair: %d, %d", port_a, port_b)

    async def release(self, port: int):
        """
        Release a single port back to the pool.

        Args:
            port: Port number to release.
        """
        async with self._lock:
            self._allocated.discard(port)
            logger.debug("Released port: %d", port)

    def is_allocated(self, port: int) -> bool:
        """Check if a port is currently allocated."""
        return port in self._allocated

    @property
    def allocated_count(self) -> int:
        """Get the number of currently allocated ports."""
        return len(self._allocated)

    @property
    def available_pairs(self) -> int:
        """Get the approximate number of available port pairs."""
        total_ports = self.port_end - self.port_start + 1
        return (total_ports - len(self._allocated)) // 2
