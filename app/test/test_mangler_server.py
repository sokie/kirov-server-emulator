"""Tests for the SAGE mangler UDP service."""

import socket
import struct
from unittest.mock import AsyncMock, Mock, call

import pytest

from app.servers.mangler_server import (
    CNC3_MAGIC,
    GENERALS_MAGIC,
    REQUEST_COMMAND,
    RESPONSE_COMMAND,
    ManglerProtocol,
    ManglerServer,
    build_mangler_response,
    mangler_checksum,
)

TEST_CLIENT_IP = "192.168.1.10"
TEST_CLIENT_PORT = 41000


def make_request(
    *,
    magic: int = CNC3_MAGIC,
    packet_id: int = 0x7F00,
    original_port: int = TEST_CLIENT_PORT,
    command: int = REQUEST_COMMAND,
    blitz: bool = False,
) -> bytes:
    packet = bytearray(b"\x44" * 20)
    struct.pack_into("!H", packet, 4, magic)
    struct.pack_into("!H", packet, 6, packet_id)
    struct.pack_into("!H", packet, 10, original_port)
    packet[16] = command
    packet[17] = int(blitz)
    struct.pack_into("!I", packet, 0, mangler_checksum(packet[4:]))
    return bytes(packet)


def test_mangler_checksum_matches_sage_algorithm():
    assert mangler_checksum(bytes(range(16))) == 0xFFEF


@pytest.mark.parametrize("magic", [CNC3_MAGIC, GENERALS_MAGIC])
def test_response_reports_observed_endpoint(magic: int):
    request = make_request(magic=magic, packet_id=0x1234)

    response = build_mangler_response(request, (TEST_CLIENT_IP, TEST_CLIENT_PORT))

    assert response is not None
    assert len(response) == 20
    assert struct.unpack_from("!I", response)[0] == mangler_checksum(response[4:])
    assert struct.unpack_from("!H", response, 4)[0] == magic
    assert struct.unpack_from("!H", response, 6)[0] == 0x1234
    assert struct.unpack_from("!H", response, 8)[0] == TEST_CLIENT_PORT
    assert struct.unpack_from("!H", response, 10)[0] == TEST_CLIENT_PORT
    assert response[12:16] == socket.inet_aton(TEST_CLIENT_IP)
    assert response[16] == RESPONSE_COMMAND


def test_cnc3_wire_packet_matches_known_response():
    request = bytes.fromhex("0085d8ecf00e12344444a028444444440c004444")

    response = build_mangler_response(request, (TEST_CLIENT_IP, TEST_CLIENT_PORT))

    assert response == bytes.fromhex("008894ecf00e1234a028a028c0a8010a2c004444")


@pytest.mark.parametrize(
    "packet",
    [
        b"too short",
        make_request()[:16] + b"\x00\x00\x00\x00",
        make_request(magic=0xFFFF),
        make_request(command=RESPONSE_COMMAND),
    ],
)
def test_malformed_request_is_rejected(packet: bytes):
    assert build_mangler_response(packet, (TEST_CLIENT_IP, TEST_CLIENT_PORT)) is None


def test_blitz_replies_use_adjacent_server_and_client_ports():
    server = Mock()
    server.blitz_enabled = True
    protocol = ManglerProtocol(server, port_offset=0)
    request = make_request(blitz=True)

    protocol.datagram_received(request, (TEST_CLIENT_IP, TEST_CLIENT_PORT))

    response = server.send.call_args_list[0].args[1]
    assert server.send.call_args_list == [
        call(0, response, (TEST_CLIENT_IP, TEST_CLIENT_PORT)),
        call(1, response, (TEST_CLIENT_IP, TEST_CLIENT_PORT + 1)),
        call(2, response, (TEST_CLIENT_IP, TEST_CLIENT_PORT + 2)),
        call(3, response, (TEST_CLIENT_IP, TEST_CLIENT_PORT + 3)),
    ]


def test_blitz_replies_can_be_disabled():
    server = Mock()
    server.blitz_enabled = False
    protocol = ManglerProtocol(server, port_offset=0)

    protocol.datagram_received(make_request(blitz=True), (TEST_CLIENT_IP, TEST_CLIENT_PORT))

    assert server.send.call_count == 1
    assert server.send.call_args.args[0] == 0


@pytest.mark.asyncio
async def test_disabling_blitz_binds_only_the_primary_port(monkeypatch: pytest.MonkeyPatch):
    transport = Mock()
    loop = Mock()
    loop.create_datagram_endpoint = AsyncMock(return_value=(transport, Mock()))
    monkeypatch.setattr("app.servers.mangler_server.asyncio.get_running_loop", lambda: loop)
    server = ManglerServer(blitz_enabled=False)

    await server.start()

    loop.create_datagram_endpoint.assert_awaited_once()
    assert loop.create_datagram_endpoint.call_args.kwargs["local_addr"] == ("0.0.0.0", 4321)
    server.stop()
    transport.close.assert_called_once()


def test_auxiliary_port_does_not_answer_requests():
    server = Mock()
    protocol = ManglerProtocol(server, port_offset=1)

    protocol.datagram_received(make_request(), (TEST_CLIENT_IP, TEST_CLIENT_PORT))

    server.send.assert_not_called()
