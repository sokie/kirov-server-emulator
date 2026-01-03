"""
NAT Negotiation Protocol Parsing and Serialization.

Handles parsing incoming NAT negotiation packets and building response packets.
"""

import struct

from app.models.natneg_types import (
    NATNEG_MAGIC,
    NATNEG_VERSION,
    NatNegClientIndex,
    NatNegConnectPacket,
    NatNegHeader,
    NatNegInitPacket,
    NatNegPortType,
    NatNegRecordType,
    NatNegReportPacket,
)
from app.util.logging_helper import get_logger

logger = get_logger(__name__)


def is_natneg_packet(data: bytes) -> bool:
    """
    Check if the given data is a NAT negotiation packet.

    Args:
        data: Raw packet bytes

    Returns:
        True if the packet starts with the natneg magic bytes
    """
    return len(data) >= 6 and data[:6] == NATNEG_MAGIC


def parse_natneg_packet(data: bytes) -> tuple[NatNegHeader, bytes] | None:
    """
    Parse a NAT negotiation packet.

    Args:
        data: Raw packet bytes

    Returns:
        Tuple of (header, payload) if valid, None if invalid
    """
    if not is_natneg_packet(data):
        return None

    header = NatNegHeader.from_bytes(data)
    if header is None:
        return None

    payload = data[NatNegHeader.HEADER_SIZE :]
    return header, payload


def parse_init_packet(data: bytes) -> NatNegInitPacket | None:
    """
    Parse an INIT packet (type 0x00).

    Args:
        data: Raw packet bytes

    Returns:
        NatNegInitPacket if valid, None otherwise
    """
    result = parse_natneg_packet(data)
    if result is None:
        return None

    header, payload = result
    if header.record_type != NatNegRecordType.INIT:
        return None

    return NatNegInitPacket.from_bytes(data, header)


def parse_connect_packet(data: bytes) -> NatNegConnectPacket | None:
    """
    Parse a CONNECT packet (type 0x05).

    Args:
        data: Raw packet bytes

    Returns:
        NatNegConnectPacket if valid, None otherwise
    """
    result = parse_natneg_packet(data)
    if result is None:
        return None

    header, payload = result
    if header.record_type != NatNegRecordType.CONNECT:
        return None

    return NatNegConnectPacket.from_bytes(data, header)


def parse_report_packet(data: bytes) -> NatNegReportPacket | None:
    """
    Parse a REPORT packet (type 0x0D).

    Args:
        data: Raw packet bytes

    Returns:
        NatNegReportPacket if valid, None otherwise
    """
    result = parse_natneg_packet(data)
    if result is None:
        return None

    header, payload = result
    if header.record_type != NatNegRecordType.REPORT:
        return None

    return NatNegReportPacket.from_bytes(data, header)


def build_init_ack_packet(session_id: int, port_type: NatNegPortType, client_index: NatNegClientIndex) -> bytes:
    """
    Build an INIT_ACK packet (type 0x01).

    This is sent in response to an INIT packet.

    Args:
        session_id: Session cookie
        port_type: Port type from original INIT
        client_index: Client index from original INIT

    Returns:
        Raw packet bytes
    """
    header = NatNegHeader(
        version=NATNEG_VERSION,
        record_type=NatNegRecordType.INIT_ACK,
        session_id=session_id,
        port_type=port_type,
        client_index=client_index,
    )
    return header.to_bytes()


def build_connect_packet(
    session_id: int, peer_ip: str, peer_port: int, got_data: bool = True, finished: bool = True
) -> bytes:
    """
    Build a CONNECT packet (type 0x05).

    This tells a client where to connect to reach their peer.

    IMPORTANT: CONNECT packets have a different structure than other packets.
    They do NOT include port_type or client_index fields. The peer IP/port
    comes directly after the session_id.

    Args:
        session_id: Session cookie
        peer_ip: IP address of the peer to connect to
        peer_port: Port of the peer to connect to
        got_data: Whether peer data was received
        finished: Whether negotiation is finished

    Returns:
        Raw packet bytes (20 bytes total)
    """
    connect = NatNegConnectPacket(
        session_id=session_id, peer_ip=peer_ip, peer_port=peer_port, got_data=got_data, finished=finished
    )

    return connect.to_bytes()


def build_report_ack_packet(session_id: int, port_type: NatNegPortType, client_index: NatNegClientIndex) -> bytes:
    """
    Build a REPORT_ACK packet (type 0x0E).

    This acknowledges a REPORT packet from a client.

    Args:
        session_id: Session cookie
        port_type: Port type from original REPORT
        client_index: Client index from original REPORT

    Returns:
        Raw packet bytes
    """
    header = NatNegHeader(
        version=NATNEG_VERSION,
        record_type=NatNegRecordType.REPORT_ACK,
        session_id=session_id,
        port_type=port_type,
        client_index=client_index,
    )
    return header.to_bytes()


def build_connect_ack_packet(session_id: int, port_type: NatNegPortType, client_index: NatNegClientIndex) -> bytes:
    """
    Build a CONNECT_ACK packet (type 0x06).

    Args:
        session_id: Session cookie
        port_type: Port type
        client_index: Client index

    Returns:
        Raw packet bytes
    """
    header = NatNegHeader(
        version=NATNEG_VERSION,
        record_type=NatNegRecordType.CONNECT_ACK,
        session_id=session_id,
        port_type=port_type,
        client_index=client_index,
    )
    return header.to_bytes()


def ip_string_to_bytes(ip: str) -> bytes:
    """Convert dotted decimal IP string to 4 bytes."""
    parts = [int(x) for x in ip.split(".")]
    return bytes(parts)


def ip_bytes_to_string(ip_bytes: bytes) -> str:
    """Convert 4 bytes to dotted decimal IP string."""
    return ".".join(str(b) for b in ip_bytes)


def replace_ip_port_in_packet(data: bytes, old_ip: str, old_port: int, new_ip: str, new_port: int) -> bytes:
    """
    Replace an IP:port pair in a packet (for LAN relay functionality).

    Searches for the old IP:port pattern and replaces with new values.
    Used for substituting public addresses with local addresses.

    Args:
        data: Raw packet bytes
        old_ip: IP address to find
        old_port: Port to find (big-endian in packet)
        new_ip: Replacement IP address
        new_port: Replacement port

    Returns:
        Modified packet bytes
    """
    # Build search pattern: 4 bytes IP + 2 bytes port (big-endian)
    old_ip_bytes = ip_string_to_bytes(old_ip)
    old_port_bytes = struct.pack(">H", old_port)
    old_pattern = old_ip_bytes + old_port_bytes

    # Build replacement
    new_ip_bytes = ip_string_to_bytes(new_ip)
    new_port_bytes = struct.pack(">H", new_port)
    new_pattern = new_ip_bytes + new_port_bytes

    # Replace all occurrences
    result = data.replace(old_pattern, new_pattern)

    if result != data:
        logger.debug("Replaced IP:port %s:%d -> %s:%d in packet", old_ip, old_port, new_ip, new_port)

    return result
