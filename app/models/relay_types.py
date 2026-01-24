"""
Relay Server Types.

Data structures for UDP relay routing and session management.
"""

import time
from dataclasses import dataclass, field


@dataclass
class RelayEndpoint:
    """Represents one endpoint in a relay connection."""

    ip: str
    port: int

    def __hash__(self):
        return hash((self.ip, self.port))

    def __eq__(self, other):
        if not isinstance(other, RelayEndpoint):
            return False
        return self.ip == other.ip and self.port == other.port

    def as_tuple(self) -> tuple[str, int]:
        """Return as (ip, port) tuple for socket operations."""
        return (self.ip, self.port)


@dataclass
class RelayRoute:
    """
    Defines a relay route between two clients.

    Each client connects to their assigned relay port.
    Traffic received on port_a is forwarded to client_b's endpoint,
    and traffic on port_b is forwarded to client_a's endpoint.
    """

    # Relay ports (server-side)
    port_a: int  # Port for client A to connect to
    port_b: int  # Port for client B to connect to

    # Client endpoints (where to forward traffic)
    client_a: RelayEndpoint | None = None  # Client A's actual address
    client_b: RelayEndpoint | None = None  # Client B's actual address

    # Activity tracking
    created_at: float = field(default_factory=time.time)
    last_activity: float = field(default_factory=time.time)

    # Statistics
    packets_forwarded: int = 0
    bytes_forwarded: int = 0

    def update_activity(self):
        """Update last activity timestamp."""
        self.last_activity = time.time()

    def is_stale(self, timeout_seconds: float) -> bool:
        """Check if this route has been inactive for too long."""
        return time.time() - self.last_activity > timeout_seconds

    def is_ready(self) -> bool:
        """Check if both clients have been registered."""
        return self.client_a is not None and self.client_b is not None


@dataclass
class PairAttemptInfo:
    """
    Tracks connection attempts for a host-guest pair.

    Used to implement progressive fallback: WAN -> LAN -> Relay.
    Tracked by (host_ip, guest_ip) tuple since session_id changes on retry.
    """

    attempt_count: int = 0
    last_activity: float = field(default_factory=time.time)
    relay_ports: tuple[int, int] | None = None

    def increment(self) -> int:
        """Increment attempt count and update activity. Returns new count."""
        self.attempt_count += 1
        self.last_activity = time.time()
        return self.attempt_count

    def update_activity(self):
        """Update last activity timestamp."""
        self.last_activity = time.time()

    def is_stale(self, ttl_seconds: float) -> bool:
        """Check if this pair entry has been inactive for too long."""
        return time.time() - self.last_activity > ttl_seconds
