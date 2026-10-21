"""C&C mangler UDP service for NAT classification and port prediction."""

import asyncio
import socket
import struct
from dataclasses import dataclass, field

from app.util.logging_helper import format_hex, get_logger

logger = get_logger(__name__)

PACKET_SIZE = 20
CNC3_MAGIC = 0xF00E
GENERALS_MAGIC = 0xF00D
REQUEST_COMMAND = 12
RESPONSE_COMMAND = 44
BLITZ_PORT_COUNT = 4


def mangler_checksum(data: bytes) -> int:
    """Return the rolling 32-bit checksum used by the SAGE network protocol."""
    checksum = 0
    for value in data:
        checksum = ((checksum << 1) + value + (checksum >> 31)) & 0xFFFFFFFF
    return checksum


def build_mangler_response(data: bytes, addr: tuple[str, int]) -> bytes | None:
    """Validate a mangler request and fill in its observed public endpoint."""
    if len(data) != PACKET_SIZE:
        return None

    magic = struct.unpack_from("!H", data, 4)[0]
    if magic not in (CNC3_MAGIC, GENERALS_MAGIC):
        return None

    if data[16] != REQUEST_COMMAND:
        return None

    expected_checksum = struct.unpack_from("!I", data)[0]
    if mangler_checksum(data[4:]) != expected_checksum:
        return None

    try:
        address = socket.inet_aton(addr[0])
    except OSError:
        return None

    response = bytearray(data)
    struct.pack_into("!H", response, 8, addr[1])
    response[12:16] = address
    response[16] = RESPONSE_COMMAND
    struct.pack_into("!I", response, 0, mangler_checksum(response[4:]))
    return bytes(response)


class ManglerProtocol(asyncio.DatagramProtocol):
    """Handle mangler requests received on the primary UDP port."""

    def __init__(self, server: "ManglerServer", port_offset: int):
        self.server = server
        self.port_offset = port_offset

    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        if self.port_offset != 0:
            logger.debug("Ignoring mangler datagram on auxiliary port from %s:%d", *addr)
            return

        response = build_mangler_response(data, addr)
        if response is None:
            logger.debug(
                "Discarding invalid mangler request from %s:%d (%d bytes): %s",
                *addr,
                len(data),
                format_hex(data[:PACKET_SIZE]),
            )
            return

        logger.debug("Mangler observed %s:%d", *addr)
        self.server.send(0, response, addr)

        if self.server.blitz_enabled and data[17]:
            for offset in range(1, BLITZ_PORT_COUNT):
                if addr[1] + offset <= 65535:
                    self.server.send(offset, response, (addr[0], addr[1] + offset))

    def error_received(self, exc: Exception) -> None:
        logger.error("Mangler UDP error on port offset %d: %s", self.port_offset, exc)


@dataclass
class ManglerServer:
    """Own the UDP sockets used by the mangler protocol."""

    host: str = "0.0.0.0"
    port: int = 4321
    blitz_enabled: bool = True
    _transports: list[asyncio.DatagramTransport] = field(default_factory=list)

    async def start(self) -> None:
        loop = asyncio.get_running_loop()
        try:
            port_count = BLITZ_PORT_COUNT if self.blitz_enabled else 1
            for offset in range(port_count):
                transport, _ = await loop.create_datagram_endpoint(
                    lambda offset=offset: ManglerProtocol(self, offset),
                    local_addr=(self.host, self.port + offset),
                    family=socket.AF_INET,
                )
                self._transports.append(transport)
        except Exception:
            self.stop()
            raise

        if self.blitz_enabled:
            logger.info("Mangler UDP server listening on %s:%d-%d", self.host, self.port, self.port + 3)
        else:
            logger.info("Mangler UDP server listening on %s:%d", self.host, self.port)

    def send(self, offset: int, data: bytes, addr: tuple[str, int]) -> None:
        if offset < len(self._transports):
            self._transports[offset].sendto(data, addr)

    def stop(self) -> None:
        for transport in self._transports:
            transport.close()
        self._transports.clear()


async def start_mangler_server(
    host: str = "0.0.0.0",
    port: int = 4321,
    blitz_enabled: bool = True,
) -> ManglerServer:
    """Create and start a mangler server."""
    server = ManglerServer(host=host, port=port, blitz_enabled=blitz_enabled)
    await server.start()
    return server
