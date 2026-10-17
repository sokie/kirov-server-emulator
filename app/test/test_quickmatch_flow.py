"""
A Kane's Wrath QuickMatch between two clients, through the real master (TCP) and heartbeat (UDP) servers and
the peerchat handlers.

The clients follow the Peer SDK automatch and the game handshake as Kane's Wrath 1.3 runs them: search, host
when nothing is listed, rate the listed host, derive its room from the list entry, join, then
QMREQ / QMRES / QMRDY / QMGO.
"""

import asyncio
import struct

import pytest
import pytest_asyncio

from app.models.irc_types import IRCMessage, IRCNumeric
from app.models.peerchat_state import irc_channels, irc_clients, irc_clients_lock
from app.servers.automatch.base import staging_room_name
from app.servers.peerchat_handlers import IRCFactory
from app.servers.peerchat_server import IRCClient
from app.servers.query_master_parsing import DELETE_SERVER_MESSAGE, PUSH_SERVER_MESSAGE
from app.servers.query_master_tcp import QueryMasterServer, start_master_server, stop_master_maintenance
from app.servers.query_master_udp import start_heartbeat_server
from app.servers.sessions import GameSessionRegistry
from app.test.test_master_automatch import (
    GAMEKEY,
    VALIDATE,
    heartbeat,
    list_request,
    parse_entry,
    parse_list,
    push_messages,
)
from app.test.test_peerchat_server import MockStreamReader, MockStreamWriter
from app.util.cipher import EncTypeX

LOCALHOST = "127.0.0.1"


class SearchConnection:
    """The server browser connection of one client: a cc3xp1am query with push updates."""

    def __init__(self, reader, writer):
        self.reader = reader
        self.writer = writer
        self.cipher = EncTypeX(key=GAMEKEY, validate=VALIDATE)
        self.pending = b""

    @classmethod
    async def open(cls, port: int) -> "SearchConnection":
        reader, writer = await asyncio.open_connection(LOCALHOST, port)
        connection = cls(reader, writer)
        writer.write(list_request("cc3xp1am"))
        await writer.drain()
        return connection

    async def _fill(self, done) -> None:
        while not done(self.pending):
            chunk = await asyncio.wait_for(self.reader.read(4096), timeout=5)
            assert chunk, "master closed the connection"
            self.pending += self.cipher.decode(chunk)

    async def read_list(self) -> list[dict]:
        await self._fill(lambda buf: buf.endswith(b"\x00\xff\xff\xff\xff"))
        _, entries = parse_list(self.pending)
        self.pending = b""
        return entries

    async def read_push(self) -> tuple[int, bytes]:
        def whole(buf: bytes) -> bool:
            return len(buf) >= 2 and len(buf) >= struct.unpack("!H", buf[:2])[0]

        await self._fill(whole)
        length = struct.unpack("!H", self.pending[:2])[0]
        (message,) = push_messages(self.pending[:length])
        self.pending = self.pending[length:]
        return message

    def close(self):
        self.writer.close()


def rates(searcher_rank: int, entry: dict) -> bool:
    """The parts of the game's rate callback that the server's data decides (QM_RateServer)."""
    rules = entry["rules"]
    window = 400
    return (
        rules["maxRPlyr"] == "2"
        and int(rules["numplayers"]) < int(rules["maxplayers"])
        and searcher_rank - window <= int(rules["rank_0"]) <= searcher_rank + window
        and int(rules["minPntPrcnt"]) <= searcher_rank <= int(rules["maxPntPrcnt"])
        and any(a == b == "1" for a, b in zip(rules["mapBit"], "11111", strict=True))
    )


def host_heartbeat(port: int, rank: int, statechanged: str = "3", numplayers: int = 1) -> bytes:
    """A QuickMatch host heartbeat, with the rank window the menu builds from the new ladder line."""
    data = heartbeat("cc3xp1am", (LOCALHOST, port), statechanged, rank=str(rank))
    data = data.replace(b"minPntPrcnt\x0013439", b"minPntPrcnt\x00" + str(rank - 400).encode())
    data = data.replace(b"maxPntPrcnt\x0015359", b"maxPntPrcnt\x00" + str(rank + 400).encode())
    return data.replace(b"numplayers\x001\x00", b"numplayers\x00" + str(numplayers).encode() + b"\x00")


def chat_client(nick: str) -> tuple[IRCClient, MockStreamWriter]:
    writer = MockStreamWriter()
    client = IRCClient(MockStreamReader([]), writer, (LOCALHOST, 1))
    client.user.nickname = nick
    client.user.username = "X1fsaFv1DX|1"
    with irc_clients_lock:
        irc_clients[nick] = client
    return client, writer


def received(writer: MockStreamWriter) -> str:
    return writer.get_all_written().decode()


async def wait_for(condition):
    for _ in range(100):
        if condition():
            return
        await asyncio.sleep(0.02)
    raise AssertionError("timed out")


@pytest_asyncio.fixture
async def servers():
    registry = GameSessionRegistry.get_instance()
    registry.clear()
    QueryMasterServer._subscribers.clear()
    with irc_clients_lock:
        irc_clients.clear()
    irc_channels.clear()

    master = await start_master_server(host=LOCALHOST, port=0, gamekeys={"cnc3ep1pc": GAMEKEY})
    hb_transport, _ = await start_heartbeat_server(host=LOCALHOST, port=0)
    yield master.sockets[0].getsockname()[1], hb_transport.get_extra_info("sockname")[1]

    hb_transport.close()
    await stop_master_maintenance()
    master.close()
    await master.wait_closed()
    registry.remove_listener(QueryMasterServer.on_registry_change)
    registry.clear()
    QueryMasterServer._subscribers.clear()


@pytest.mark.asyncio
async def test_two_clients_meet_through_the_automatch(servers):
    master_port, heartbeat_port = servers
    loop = asyncio.get_running_loop()
    registry = GameSessionRegistry.get_instance()

    # soky searches first: nothing is listed, so it hosts.
    soky_search = await SearchConnection.open(master_port)
    assert await soky_search.read_list() == []
    qr2, _ = await loop.create_datagram_endpoint(asyncio.DatagramProtocol, remote_addr=(LOCALHOST, heartbeat_port))
    qr2_port = qr2.get_extra_info("sockname")[1]
    soky_room = staging_room_name("cc3xp1", LOCALHOST, LOCALHOST, qr2_port)
    soky, soky_out = chat_client("soky")
    await IRCFactory.handle_join(soky, IRCMessage(command="JOIN", params=[soky_room]))
    await IRCFactory.handle_mode(soky, IRCMessage(command="MODE", params=[soky_room, "-i-p-s-m-n-t+l+e", "2"]))
    qr2.sendto(host_heartbeat(qr2_port, 1210))
    await wait_for(lambda: registry.get_games("cc3xp1am"))

    # soky's own browser is told about its server (the SDK skips its own).
    msg_type, payload = await soky_search.read_push()
    assert msg_type == PUSH_SERVER_MESSAGE and parse_entry(payload, 0, [], popular=False)[0]["port"] == qr2_port
    soky_search.close()

    # sokiee searches, rates soky's server and derives the room from the entry.
    sokiee_search = await SearchConnection.open(master_port)
    (entry,) = await sokiee_search.read_list()
    assert rates(1250, entry)
    room = staging_room_name("cc3xp1", entry["ip"], entry["private_ip"], entry["private_port"])
    assert room == soky_room
    sokiee_search.close()

    sokiee, sokiee_out = chat_client("sokiee")
    await IRCFactory.handle_join(sokiee, IRCMessage(command="JOIN", params=[room]))
    assert irc_channels[room].users == {"soky", "sokiee"}

    # A third searcher that picked the same host finds the room full.
    third, third_out = chat_client("third")
    await IRCFactory.handle_join(third, IRCMessage(command="JOIN", params=[room]))
    assert f" {IRCNumeric.ERR_CHANNELISFULL} third {room} " in received(third_out)

    # The handshake.
    await IRCFactory.handle_utm(soky, IRCMessage(command="UTM", params=["sokiee", "QMREQ/"]))
    assert ":soky!X1fsaFv1DX|1@* UTM sokiee :QMREQ/" in received(sokiee_out)
    for field in ("Faction=1", "Color=0", "IP=2130706433", "NAT=1", "Rank=1250", "ProfileID=2", "BroadcastEnabled=1"):
        await IRCFactory.handle_utm(sokiee, IRCMessage(command="UTM", params=["soky", f"QMRES/ {field}"]))
    await IRCFactory.handle_utm(sokiee, IRCMessage(command="UTM", params=["soky", "QMRDY/"]))
    assert received(soky_out).count("UTM soky :QMRES/ ") == 7 and "UTM soky :QMRDY/" in received(soky_out)

    qmgo = "QMGO/ 3 123456 1 soky 2130706433 1 0 1 1210 1 sokiee 2130706433 5 1 1 1250 2"
    soky_before = received(soky_out)
    await IRCFactory.handle_utm(soky, IRCMessage(command="UTM", params=[room, qmgo]))
    assert f"UTM {room} :{qmgo}" in received(sokiee_out)
    assert received(soky_out) == soky_before  # the chat SDK hands the host its own QMGO

    # A later searcher sees the host full, then gone.
    watcher = await SearchConnection.open(master_port)
    await watcher.read_list()
    qr2.sendto(host_heartbeat(qr2_port, 1210, statechanged="1", numplayers=2))
    msg_type, payload = await watcher.read_push()
    full = parse_entry(payload, 0, [], popular=False)[0]
    assert msg_type == PUSH_SERVER_MESSAGE and full["rules"]["numplayers"] == "2"
    assert not rates(1250, full)
    full["rules"]["numplayers"] = "1"
    assert rates(1250, full)

    qr2.sendto(host_heartbeat(qr2_port, 1210, statechanged="2"))
    msg_type, payload = await watcher.read_push()
    assert (msg_type, payload) == (DELETE_SERVER_MESSAGE, bytes([127, 0, 0, 1]) + struct.pack("!H", qr2_port))
    watcher.close()
    qr2.close()
