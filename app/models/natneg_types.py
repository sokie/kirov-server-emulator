"""
NAT Negotiation Protocol Types for GameSpy NAT traversal.

This module defines the packet structures and enums used in the GameSpy
NAT negotiation protocol (natneg) on port 27901.

Protocol reference:
- Magic bytes: 0xFD 0xFC 0x1E 0x66 0x6A 0xB2
- Version: 0x03 (RA3 uses version 3)
- All multi-byte integers are big-endian (network byte order)
"""

import struct
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Optional, Tuple


# GameSpy NAT negotiation magic bytes (6 bytes)
NATNEG_MAGIC = bytes([0xFD, 0xFC, 0x1E, 0x66, 0x6A, 0xB2])

# Protocol version used by Red Alert 3
NATNEG_VERSION = 0x03


class NatNegRecordType(IntEnum):
    """
    NAT Negotiation packet record types.

    These define the message type in byte offset 7 of the packet.
    """
    INIT = 0x00           # Client -> Server: Initialize connection
    INIT_ACK = 0x01       # Server -> Client: Acknowledge initialization
    ERT_TEST = 0x02       # Server -> Client: NAT type testing (STUN-like)
    ERT_ACK = 0x03        # Client -> Server: Test acknowledgement
    STATE_UPDATE = 0x04   # Bidirectional: State synchronization
    CONNECT = 0x05        # Server -> Client: Peer connection information
    CONNECT_ACK = 0x06    # Client -> Server: Connection acknowledged
    CONNECT_PING = 0x07   # Client <-> Client: Direct peer keep-alive
    BACKUP_TEST = 0x08    # Client -> Server: Backup connectivity test
    BACKUP_ACK = 0x09     # Server -> Client: Backup test response
    ADDRESS_CHECK = 0x0A  # Client -> Server: Request public address detection
    ADDRESS_REPLY = 0x0B  # Server -> Client: Public address response
    NATIFY_REQUEST = 0x0C # Client -> Server: NAT detection request
    REPORT = 0x0D         # Client -> Server: Connection status report
    REPORT_ACK = 0x0E     # Server -> Client: Report acknowledgement
    PREINIT = 0x0F        # Client -> Server: Pre-initialization (v4 only)
    PREINIT_ACK = 0x10    # Server -> Client: Pre-init acknowledgement (v4 only)


class NatNegPortType(IntEnum):
    """
    Port type indicator in NAT negotiation packets.

    Indicates which connection this packet belongs to.
    """
    GP = 0x00      # GameSpy Protocol connection
    NN1 = 0x01     # NAT Negotiation port 1 (primary)
    NN2 = 0x02     # NAT Negotiation port 2 (STUN)
    NN3 = 0x03     # NAT Negotiation port 3 (STUN)


class NatNegClientIndex(IntEnum):
    """
    Client index indicating role in NAT negotiation.
    """
    GUEST = 0x00   # Client/guest initiating connection
    HOST = 0x01    # Server/host accepting connection


@dataclass
class NatNegHeader:
    """
    NAT Negotiation packet header structure.

    Fixed 14-byte header at the beginning of every natneg packet:
    - Bytes 0-5: Magic (FD FC 1E 66 6A B2)
    - Byte 6: Version (0x03)
    - Byte 7: Record type (message type)
    - Bytes 8-11: Session ID (cookie) - 4 bytes big-endian
    - Byte 12: Port type
    - Byte 13: Client index (0=guest, 1=host)
    """
    version: int
    record_type: NatNegRecordType
    session_id: int  # Cookie shared between host and guest
    port_type: NatNegPortType
    client_index: NatNegClientIndex

    HEADER_SIZE = 14
    HEADER_FORMAT = '>6sBBIBB'  # magic(6) + version(1) + type(1) + session(4) + port(1) + index(1)

    @classmethod
    def from_bytes(cls, data: bytes) -> Optional['NatNegHeader']:
        """
        Parse a NAT negotiation header from raw bytes.

        Args:
            data: Raw packet bytes (must be at least 14 bytes)

        Returns:
            NatNegHeader if valid, None if invalid magic or too short
        """
        if len(data) < cls.HEADER_SIZE:
            return None

        # Verify magic bytes
        if data[:6] != NATNEG_MAGIC:
            return None

        try:
            magic, version, record_type, session_id, port_type, client_index = struct.unpack(
                cls.HEADER_FORMAT, data[:cls.HEADER_SIZE]
            )

            return cls(
                version=version,
                record_type=NatNegRecordType(record_type),
                session_id=session_id,
                port_type=NatNegPortType(port_type) if port_type <= 3 else NatNegPortType.NN1,
                client_index=NatNegClientIndex(client_index) if client_index <= 1 else NatNegClientIndex.GUEST
            )
        except (struct.error, ValueError):
            return None

    def to_bytes(self) -> bytes:
        """Serialize header to bytes."""
        return struct.pack(
            self.HEADER_FORMAT,
            NATNEG_MAGIC,
            self.version,
            self.record_type,
            self.session_id,
            self.port_type,
            self.client_index
        )


@dataclass
class NatNegInitPacket:
    """
    INIT packet (type 0x00) sent by client to server.

    Structure after header (starting at byte 14):
    - Byte 14: Use game port flag
    - Bytes 15-18: Local IP address (4 bytes)
    - Bytes 19-20: Local port (2 bytes, big-endian)
    - Bytes 21+: Game name (null-terminated string)
    """
    header: NatNegHeader
    use_game_port: bool
    local_ip: str  # Dotted decimal string
    local_port: int
    game_name: str

    @classmethod
    def from_bytes(cls, data: bytes, header: NatNegHeader) -> Optional['NatNegInitPacket']:
        """Parse INIT packet from raw bytes."""
        if len(data) < NatNegHeader.HEADER_SIZE + 7:  # header + flag + ip + port
            return None

        offset = NatNegHeader.HEADER_SIZE

        use_game_port = data[offset] != 0
        offset += 1

        # Parse IP address (4 bytes)
        ip_bytes = data[offset:offset + 4]
        local_ip = '.'.join(str(b) for b in ip_bytes)
        offset += 4

        # Parse port (2 bytes, big-endian)
        local_port = struct.unpack('>H', data[offset:offset + 2])[0]
        offset += 2

        # Parse game name (null-terminated)
        game_name_end = data.find(b'\x00', offset)
        if game_name_end == -1:
            game_name = data[offset:].decode('ascii', errors='ignore')
        else:
            game_name = data[offset:game_name_end].decode('ascii', errors='ignore')

        return cls(
            header=header,
            use_game_port=use_game_port,
            local_ip=local_ip,
            local_port=local_port,
            game_name=game_name
        )


@dataclass
class NatNegConnectPacket:
    """
    CONNECT packet (type 0x05) sent by server to clients.

    Contains the peer's address information for direct P2P connection.

    IMPORTANT: CONNECT packet has a DIFFERENT structure than INIT!
    The IP/port comes directly after session_id, WITHOUT port_type/client_index.

    Structure:
    - Bytes 0-5: Magic (6 bytes)
    - Byte 6: Version (1 byte)
    - Byte 7: Record type 0x05 (1 byte)
    - Bytes 8-11: Session ID (4 bytes)
    - Bytes 12-15: Peer IP address (4 bytes)
    - Bytes 16-17: Peer port (2 bytes, big-endian)
    - Byte 18: Got data flag (0x42 = 'B' means data is valid)
    - Byte 19: Finished flag

    Total: 20 bytes
    """
    session_id: int
    peer_ip: str  # Dotted decimal string
    peer_port: int
    got_data: bool = True
    finished: bool = True

    # Minimal header size for CONNECT (no port_type/client_index)
    CONNECT_HEADER_SIZE = 12  # magic(6) + version(1) + type(1) + session(4)

    def to_bytes(self) -> bytes:
        """Serialize CONNECT packet to bytes."""
        # Build minimal header for CONNECT (no port_type/client_index)
        header = struct.pack(
            '>6sBBI',
            NATNEG_MAGIC,
            NATNEG_VERSION,
            NatNegRecordType.CONNECT,
            self.session_id
        )

        # Convert IP string to bytes
        ip_parts = [int(x) for x in self.peer_ip.split('.')]
        ip_bytes = bytes(ip_parts)

        # Pack port as big-endian
        port_bytes = struct.pack('>H', self.peer_port)

        # Got data flag (0x42 = 'B' if data valid, 0x00 otherwise)
        got_data_byte = 0x42 if self.got_data else 0x00

        # Finished field is an error code, NOT a boolean!
        # FINISHED_NOERROR = 0, FINISHED_ERROR_DEADBEAT_PARTNER = 1, etc.
        # We always send 0 (no error) when successfully connecting peers
        finished_byte = 0x00

        return header + ip_bytes + port_bytes + bytes([got_data_byte, finished_byte])

    @classmethod
    def from_bytes(cls, data: bytes, header: NatNegHeader) -> Optional['NatNegConnectPacket']:
        """Parse CONNECT packet from raw bytes."""
        if len(data) < NatNegHeader.HEADER_SIZE + 8:  # header + ip(4) + port(2) + flags(2)
            return None

        offset = NatNegHeader.HEADER_SIZE

        # Parse IP address
        ip_bytes = data[offset:offset + 4]
        peer_ip = '.'.join(str(b) for b in ip_bytes)
        offset += 4

        # Parse port
        peer_port = struct.unpack('>H', data[offset:offset + 2])[0]
        offset += 2

        # Parse flags
        got_data = data[offset] == 0x42 if len(data) > offset else False
        finished = data[offset + 1] != 0 if len(data) > offset + 1 else False

        return cls(
            header=header,
            peer_ip=peer_ip,
            peer_port=peer_port,
            got_data=got_data,
            finished=finished
        )


@dataclass
class NatNegReportPacket:
    """
    REPORT packet (type 0x0D) sent by client to server.

    Reports the success/failure of NAT negotiation.

    Structure after header:
    - Byte 14: Port type
    - Byte 15: NAT type
    - Byte 16: Mapping scheme
    - Bytes 17+: Game name (null-terminated)
    """
    header: NatNegHeader
    port_type: int
    nat_type: int
    mapping_scheme: int
    game_name: str

    @classmethod
    def from_bytes(cls, data: bytes, header: NatNegHeader) -> Optional['NatNegReportPacket']:
        """Parse REPORT packet from raw bytes."""
        if len(data) < NatNegHeader.HEADER_SIZE + 3:
            return None

        offset = NatNegHeader.HEADER_SIZE

        port_type = data[offset]
        nat_type = data[offset + 1]
        mapping_scheme = data[offset + 2]
        offset += 3

        # Parse game name
        game_name_end = data.find(b'\x00', offset)
        if game_name_end == -1:
            game_name = data[offset:].decode('ascii', errors='ignore')
        else:
            game_name = data[offset:game_name_end].decode('ascii', errors='ignore')

        return cls(
            header=header,
            port_type=port_type,
            nat_type=nat_type,
            mapping_scheme=mapping_scheme,
            game_name=game_name
        )


@dataclass
class NatNegClientConnection:
    """
    Represents a single connection (port_type) from a client.

    Each client sends multiple INIT packets with different port_types (0-3).
    """
    # Public address (as seen by server)
    public_ip: str
    public_port: int

    # Local address (from INIT packet) - this is where game listens for P2P
    local_ip: str
    local_port: int

    # Connection info
    port_type: NatNegPortType

    # State tracking
    connect_sent: bool = False
    connect_acked: bool = False


@dataclass
class NatNegClient:
    """
    Represents a client in a NAT negotiation session.

    Tracks all port_type connections from this client.
    A client typically sends 4 INIT packets with port_types 0-3.
    """
    # Session info
    session_id: int  # Cookie
    client_index: NatNegClientIndex
    game_name: str

    # Multiple connections by port_type
    connections: dict = field(default_factory=dict)  # port_type -> NatNegClientConnection

    # State tracking
    init_received: bool = False

    def add_connection(self, conn: NatNegClientConnection):
        """Add or update a connection for a port_type."""
        self.connections[conn.port_type] = conn
        self.init_received = True

    def get_best_connection(self) -> Optional[NatNegClientConnection]:
        """
        Get the best connection to use for P2P.

        Prefers connections with valid local_port (non-zero).
        Falls back to port_type NN3 (0x03) which typically has the game port.
        """
        # First, try to find a connection with a valid local port
        for pt in [NatNegPortType.NN3, NatNegPortType.NN2, NatNegPortType.NN1, NatNegPortType.GP]:
            if pt in self.connections:
                conn = self.connections[pt]
                if conn.local_port != 0:
                    return conn

        # Fall back to any connection
        if self.connections:
            return next(iter(self.connections.values()))
        return None

    @property
    def public_ip(self) -> Optional[str]:
        """Get public IP from best connection."""
        conn = self.get_best_connection()
        return conn.public_ip if conn else None

    @property
    def public_port(self) -> Optional[int]:
        """Get public port from best connection."""
        conn = self.get_best_connection()
        return conn.public_port if conn else None

    @property
    def local_ip(self) -> Optional[str]:
        """Get local IP from best connection."""
        conn = self.get_best_connection()
        return conn.local_ip if conn else None

    @property
    def local_port(self) -> Optional[int]:
        """Get local port from best connection."""
        conn = self.get_best_connection()
        return conn.local_port if conn else None


def _get_subnet(ip: str) -> str:
    """Get the /24 subnet (first 3 octets) from an IP address."""
    parts = ip.split('.')
    if len(parts) >= 3:
        return '.'.join(parts[:3])
    return ip


@dataclass
class NatNegSession:
    """
    Represents a NAT negotiation session between two clients.

    A session is identified by a shared cookie (session_id) and matches
    one host (client_index=1) with one guest (client_index=0).
    """
    session_id: int  # Cookie shared by both clients
    game_name: str

    # The two clients in this session
    host: Optional[NatNegClient] = None  # client_index = 1
    guest: Optional[NatNegClient] = None  # client_index = 0

    # Session state
    created_at: float = 0.0  # Timestamp
    connect_sent: bool = False
    completed: bool = False

    def is_ready(self) -> bool:
        """
        Check if both clients have registered and we can send CONNECT.

        We require both clients to have sent ALL 4 port types (0,1,2,3)
        before sending CONNECT. The game sends INIT packets for all 4
        port types, and expects CONNECT only after all are received.

        Port types 2 and 3 contain the actual game port (local_port != 0).
        """
        if not (self.host and self.guest and
                self.host.init_received and self.guest.init_received):
            return False

        # Check that both clients have sent port_type 3 (the last one)
        # This ensures all 4 port types have been received
        if NatNegPortType.NN3 not in self.host.connections:
            return False
        if NatNegPortType.NN3 not in self.guest.connections:
            return False

        host_conn = self.host.get_best_connection()
        guest_conn = self.guest.get_best_connection()

        if not host_conn or not guest_conn:
            return False

        # Both must have valid (non-zero) local ports
        return host_conn.local_port != 0 and guest_conn.local_port != 0

    def are_same_lan(self) -> bool:
        """
        Check if both clients are on the same LAN.

        They're on the same LAN if they have the same /24 subnet
        (first 3 octets of IP address match).
        """
        if not self.host or not self.guest:
            return False
        host_ip = self.host.public_ip
        guest_ip = self.guest.public_ip
        if not host_ip or not guest_ip:
            return False
        return _get_subnet(host_ip) == _get_subnet(guest_ip)
