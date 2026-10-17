"""
Server list and push protocol for the Kane's Wrath and Tiberium Wars QuickMatch (GameSpy Peer SDK automatch).

The host keys, the validate token and the SERVER_INFO_REQUEST bytes are the ones two Kane's Wrath 1.3 clients
sent on 2026-03-12. The entries are read the way the client's server browser reads them.
"""

import socket
import struct

import pytest

from app.models.irc_types import IRCMessage, IRCNumeric
from app.models.peerchat_state import irc_channels, irc_clients, irc_clients_lock
from app.servers.automatch.base import staging_room_name
from app.servers.peerchat_handlers import IRCFactory, channel_limit
from app.servers.peerchat_server import IRCClient
from app.servers.query_master_parsing import (
    DELETE_SERVER_MESSAGE,
    HAS_FULL_RULES_FLAG,
    HAS_KEYS_FLAG,
    KEEPALIVE_MESSAGE,
    PUSH_SERVER_MESSAGE,
    PUSH_UPDATES,
    parse_tcp_query,
)
from app.servers.query_master_tcp import QueryMasterHandler, QueryMasterServer
from app.servers.query_master_udp import HeartbeatMaster
from app.servers.sessions import GameSessionRegistry
from app.test.test_peerchat_server import MockStreamReader, MockStreamWriter
from app.util.cipher import EncTypeX

GAMEKEY = "BhcJLQ"
VALIDATE = b")j|EJg@_"
SEARCHER = ("192.168.68.62", 55599)
HOST = ("192.168.68.63", 6500)

# The keys the host reported in the 2026-03-12 list, in its order.
HOST_KEYS = [
    ("NAT", "1"),
    ("cCRC", "15728400"),
    ("disc", "10000"),
    ("iCRC", "710133300"),
    ("lddrID", "0"),
    ("mapBit", "11111"),
    ("maxDisc", "2147483647"),
    ("maxPing", "255"),
    ("maxPntPrcnt", "15359"),
    ("maxRPlyr", "2"),
    ("maxplayers", "2"),
    ("minPntPrcnt", "13439"),
    ("numRPlyr", "1"),
    ("numplayers", "1"),
    ("pings", "FF4239FF"),
    ("vCRC", "1.3.0.0"),
    ("widen", "0"),
]


def heartbeat(gamename: str, address: tuple[str, int], statechanged: str = "3", rank: str = "1250") -> bytes:
    keys = [
        ("localip0", address[0]),
        ("localport", str(address[1])),
        ("natneg", "1"),
        ("statechanged", statechanged),
        ("gamename", gamename),
        ("publicip", "0"),
        ("hostname", "soky"),
        *HOST_KEYS,
    ]
    body = b"".join(k.encode() + b"\0" + v.encode() + b"\0" for k, v in keys) + b"\0"
    body += b"\x00\x01name_\0rank_\0\0soky\0" + rank.encode() + b"\0"
    return b"\x03" + struct.pack("!I", 0x1234) + body


def list_request(game: str, fields: str = "", options: int = PUSH_UPDATES) -> bytes:
    body = b"\x00\x01\x03\x00\x00\x00\x00" + game.encode() + b"\0cc3xp1\0" + VALIDATE + b"\0" + fields.encode()
    body += b"\0" + struct.pack("!I", options)
    return struct.pack("!H", len(body) + 2) + body


def cstr(buf: bytes, pos: int) -> tuple[str, int]:
    end = buf.index(b"\0", pos)
    return buf[pos:end].decode(), end + 1


def parse_entry(buf: bytes, pos: int, keys: list[str], popular: bool) -> tuple[dict, int]:
    """Reads one server entry like the client's SBParseServer."""
    flags = buf[pos]
    pos += 1
    entry = {"flags": flags, "ip": socket.inet_ntoa(buf[pos : pos + 4])}
    pos += 4
    if flags & 0x10:
        entry["port"] = struct.unpack("!H", buf[pos : pos + 2])[0]
        pos += 2
    if flags & 0x02:
        entry["private_ip"] = socket.inet_ntoa(buf[pos : pos + 4])
        pos += 4
    if flags & 0x20:
        entry["private_port"] = struct.unpack("!H", buf[pos : pos + 2])[0]
        pos += 2
    if flags & 0x08:
        pos += 4
    values = {}
    if flags & HAS_KEYS_FLAG:
        for key in keys:
            if popular:
                assert buf[pos] == 0xFF
                pos += 1
            values[key], pos = cstr(buf, pos)
    rules = {}
    if flags & HAS_FULL_RULES_FLAG:
        while buf[pos]:
            key, pos = cstr(buf, pos)
            rules[key], pos = cstr(buf, pos)
        pos += 1
    entry["values"] = values
    entry["rules"] = rules
    return entry, pos


def parse_list(buf: bytes) -> tuple[list[str], list[dict]]:
    pos = 7
    keys = []
    for _ in range(buf[6]):
        pos += 1
        name, pos = cstr(buf, pos)
        keys.append(name)
    assert buf[pos] == 0  # no popular strings
    pos += 1
    entries = []
    while not (buf[pos] == 0 and buf[pos + 1 : pos + 5] == b"\xff\xff\xff\xff"):
        entry, pos = parse_entry(buf, pos, keys, popular=True)
        entries.append(entry)
    return keys, entries


def push_messages(data: bytes) -> list[tuple[int, bytes]]:
    messages = []
    while data:
        length = struct.unpack("!H", data[:2])[0]
        messages.append((data[2], data[3:length]))
        data = data[length:]
    return messages


class FakeTransport:
    def __init__(self):
        self.written = []

    def write(self, data: bytes):
        self.written.append(data)

    def get_extra_info(self, name):
        return SEARCHER if name == "peername" else None


class Searcher:
    """A query connection, read through a client-side cipher."""

    def __init__(self):
        self.server = QueryMasterServer()
        self.transport = FakeTransport()
        self.server.connection_made(self.transport)
        self.client_cipher = EncTypeX(key=GAMEKEY, validate=VALIDATE)

    def send(self, data: bytes) -> bytes:
        before = len(self.transport.written)
        self.server.data_received(data)
        return self.read(before)

    def read(self, since: int = 0) -> bytes:
        return b"".join(self.client_cipher.decode(chunk) for chunk in self.transport.written[since:])


@pytest.fixture
def master():
    registry = GameSessionRegistry.get_instance()
    registry.clear()
    QueryMasterServer._subscribers.clear()
    QueryMasterServer.set_handler(QueryMasterHandler(gamekeys={"cnc3ep1pc": GAMEKEY}))
    registry.add_listener(QueryMasterServer.on_registry_change)
    hb = HeartbeatMaster()
    yield hb
    registry.remove_listener(QueryMasterServer.on_registry_change)
    registry.clear()
    QueryMasterServer._subscribers.clear()


class TestListRequest:
    def test_the_options_follow_the_field_list(self):
        request = parse_tcp_query(list_request("cc3xp1am"))
        assert (request.game_name, request.game_name2, request.validate_token) == ("cc3xp1am", "cc3xp1", VALIDATE)
        assert (request.filter_string, request.fields, request.options) == ("", [], PUSH_UPDATES)

    def test_a_query_without_fields_gets_the_full_rules_of_each_host(self, master):
        master.datagram_received(heartbeat("cc3xp1am", HOST), HOST)
        searcher = Searcher()
        keys, entries = parse_list(searcher.send(list_request("cc3xp1am")))
        assert keys == []
        (entry,) = entries
        assert entry["flags"] & HAS_FULL_RULES_FLAG and not entry["flags"] & HAS_KEYS_FLAG
        assert (entry["ip"], entry["port"], entry["private_ip"], entry["private_port"]) == (*HOST, *HOST)
        assert {k: entry["rules"][k] for k, _ in HOST_KEYS} == dict(HOST_KEYS)
        assert (entry["rules"]["rank_0"], entry["rules"]["name_0"]) == ("1250", "soky")
        assert "statechanged" not in entry["rules"]

    def test_the_entry_names_the_room_the_host_created(self, master):
        master.datagram_received(heartbeat("cc3xp1am", HOST), HOST)
        _, (entry,) = parse_list(Searcher().send(list_request("cc3xp1am")))
        name = staging_room_name("cc3xp1", entry["ip"], entry["private_ip"], entry["private_port"])
        assert name == "#GSP!cc3xp1!M1NqPKPNDM"
        assert staging_room_name("cc3xp1", *SEARCHER[:1], SEARCHER[0], 6500) == "#GSP!cc3xp1!M14qPKPN0M"

    def test_only_the_queried_game_is_listed(self, master):
        master.datagram_received(heartbeat("cc3xp1", HOST), HOST)
        assert parse_list(Searcher().send(list_request("cc3xp1am")))[1] == []

    def test_a_query_with_fields_gets_their_values(self, master):
        master.datagram_received(heartbeat("cc3xp1am", HOST), HOST)
        keys, (entry,) = parse_list(Searcher().send(list_request("cc3xp1am", "\\hostname\\numplayers", 0)))
        assert keys == ["hostname", "numplayers"]
        assert entry["values"] == {"hostname": "soky", "numplayers": "1"} and entry["rules"] == {}


class TestPushUpdates:
    def test_a_new_host_is_pushed_with_its_rules(self, master):
        searcher = Searcher()
        searcher.send(list_request("cc3xp1am"))
        before = len(searcher.transport.written)
        master.datagram_received(heartbeat("cc3xp1am", HOST), HOST)
        ((msg_type, payload),) = push_messages(searcher.read(before))
        assert msg_type == PUSH_SERVER_MESSAGE
        entry, end = parse_entry(payload, 0, [], popular=False)
        assert end == len(payload)
        assert entry["rules"]["maxRPlyr"] == "2" and entry["ip"] == HOST[0]

    def test_a_host_that_leaves_is_deleted(self, master):
        master.datagram_received(heartbeat("cc3xp1am", HOST), HOST)
        searcher = Searcher()
        searcher.send(list_request("cc3xp1am"))
        before = len(searcher.transport.written)
        master.datagram_received(heartbeat("cc3xp1am", HOST, statechanged="2"), HOST)
        assert push_messages(searcher.read(before)) == [
            (DELETE_SERVER_MESSAGE, socket.inet_aton(HOST[0]) + struct.pack("!H", HOST[1]))
        ]

    def test_a_silent_host_is_pruned_and_deleted(self, master):
        master.datagram_received(heartbeat("cc3xp1am", HOST), HOST)
        searcher = Searcher()
        searcher.send(list_request("cc3xp1am"))
        before = len(searcher.transport.written)
        assert GameSessionRegistry.get_instance().prune(-1) == 1
        assert [m for m, _ in push_messages(searcher.read(before))] == [DELETE_SERVER_MESSAGE]

    def test_other_games_are_not_pushed(self, master):
        searcher = Searcher()
        searcher.send(list_request("cc3xp1am"))
        before = len(searcher.transport.written)
        master.datagram_received(heartbeat("cc3xp1", HOST), HOST)
        assert searcher.read(before) == b""

    def test_keepalive(self, master):
        searcher = Searcher()
        searcher.send(list_request("cc3xp1am"))
        before = len(searcher.transport.written)
        QueryMasterServer.send_keepalives()
        assert push_messages(searcher.read(before)) == [(KEEPALIVE_MESSAGE, b"")]

    def test_a_closed_connection_stops_following(self, master):
        searcher = Searcher()
        searcher.send(list_request("cc3xp1am"))
        searcher.server.connection_lost(None)
        before = len(searcher.transport.written)
        master.datagram_received(heartbeat("cc3xp1am", HOST), HOST)
        assert len(searcher.transport.written) == before


class TestServerInfoRequest:
    def test_the_request_the_game_sent_gets_the_host_rules(self, master):
        master.datagram_received(heartbeat("cc3xp1am", HOST), HOST)
        searcher = Searcher()
        searcher.send(list_request("cc3xp1am", options=0))
        reply = searcher.send(bytes.fromhex("000901c0a8443f1964"))
        ((msg_type, payload),) = push_messages(reply)
        assert msg_type == PUSH_SERVER_MESSAGE
        entry, _ = parse_entry(payload, 0, [], popular=False)
        assert entry["rules"]["pings"] == "FF4239FF" and entry["rules"]["rank_0"] == "1250"

    def test_an_unknown_server_is_deleted(self, master):
        searcher = Searcher()
        searcher.send(list_request("cc3xp1am", options=0))
        ((msg_type, payload),) = push_messages(searcher.send(bytes.fromhex("000901c0a8443f1964")))
        assert (msg_type, payload) == (DELETE_SERVER_MESSAGE, bytes.fromhex("c0a8443f1964"))


class TestStagingRoomLimit:
    def setup_method(self):
        with irc_clients_lock:
            irc_clients.clear()
        irc_channels.clear()

    def test_mode_changes_set_the_limit(self):
        assert channel_limit("+l", ["2"]) == 2
        assert channel_limit("-i-p-s-m-n-t+l+e", ["2"]) == 2
        assert channel_limit("+k+l", ["secret", "4"]) == 4
        assert channel_limit("-l", []) == 0
        assert channel_limit("+t", []) is None

    @pytest.mark.asyncio
    async def test_a_full_room_refuses_a_join(self):
        room = "#GSP!cc3xp1!M1NqPKPNDM"
        clients = []
        for nick in ("soky", "sokiee", "third"):
            writer = MockStreamWriter()
            client = IRCClient(MockStreamReader([]), writer, ("192.168.68.10", 1))
            client.user.nickname = nick
            client.user.username = "X1fsaFv1DX|1"
            with irc_clients_lock:
                irc_clients[nick] = client
            clients.append((client, writer))

        host, _ = clients[0]
        await IRCFactory.handle_join(host, IRCMessage(command="JOIN", params=[room]))
        await IRCFactory.handle_mode(host, IRCMessage(command="MODE", params=[room, "+l", "2"]))
        await IRCFactory.handle_join(clients[1][0], IRCMessage(command="JOIN", params=[room]))
        third, writer = clients[2]
        await IRCFactory.handle_join(third, IRCMessage(command="JOIN", params=[room]))

        assert irc_channels[room].users == {"soky", "sokiee"}
        assert f" {IRCNumeric.ERR_CHANNELISFULL} third {room} " in writer.get_all_written().decode()
