"""Tests for CNC3 peerchat NAT relay fallback."""

import time
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

import pytest

# Configure pytest-asyncio mode
pytest_plugins = ("pytest_asyncio",)

from app.models.relay_types import RelayEndpoint, RelayRoute
from app.servers.peerchat_relay import PeerchatRelayCoordinator
from app.servers.relay_server import RelayPortProtocol, RelayServer

# =============================================================================
# Test Data Constants (placeholder/fake data)
# =============================================================================

TEST_RELAY_IP = "203.0.113.10"
TEST_IP_JOHN = "192.168.1.10"
TEST_IP_DOE = "192.168.1.20"
TEST_IP_ALICE = "192.168.1.30"
TEST_CHANNEL = "#GSP!cc3tibwars!test"


def make_client(nickname: str, ip: str):
    """Create a minimal fake peerchat client."""
    writer = Mock()
    writer.get_extra_info.return_value = (TEST_RELAY_IP, 16667)
    return SimpleNamespace(
        game_name="cc3tibwars",
        user=SimpleNamespace(
            nickname=nickname,
            get_prefix=lambda: f"{nickname}!user@*",
        ),
        writer=writer,
        addr=(ip, 16667),
    )


def make_relay_server(*routes: RelayRoute):
    """Create a relay server mock backed by the supplied routes."""
    relay_server = Mock()
    relay_server.advertised_host = TEST_RELAY_IP
    relay_server.allocate_route = AsyncMock(side_effect=routes)
    relay_server.get_route_by_port.side_effect = lambda port: next(
        (route for route in routes if port in (route.port_a, route.port_b)), None
    )
    return relay_server


class TestPeerchatRelay:
    """Test CNC3 direct-to-relay fallback over peerchat."""

    @pytest.mark.asyncio
    async def test_direct_failure_uses_stock_req_then_relay_port(self):
        """A failed direct connection should retry through the relay."""
        route = RelayRoute(50000, 50001)
        relay_server = make_relay_server(route)
        coordinator = PeerchatRelayCoordinator()
        coordinator.configure(relay_server)
        host = make_client("John", TEST_IP_JOHN)
        guest = make_client("Doe", TEST_IP_DOE)
        clients = {"John": host, "Doe": guest}
        slot_list = (
            "SL/ M=0;S=H,C0A8010A,11718,TT,-1,1,-1,-1,0,1,-1,:H,C0A80114,8088,FT,-1,1,-1,-1,0,1,-1,:X:X:X:X:X:X:;"
        )

        coordinator.remember_player_numbers(host, TEST_CHANNEL, clients, "PN/ 0=John,1=Doe")
        prepared = coordinator.prepare_slot_list(host, TEST_CHANNEL, clients, slot_list)

        assert prepared.host_requests == [("Doe!user@*", "REQ/ IP=-1062731510")]
        assert "H,C0A8010A,11718" in prepared.messages["Doe"]
        assert "H,C0A8010A,8088" in prepared.messages["Doe"]

        await coordinator.observe(host, ["John", "Doe"], "NAT/ NEGO0 1 DIRECT")
        await coordinator.observe(host, ["Doe"], "NAT/ PORT0 11718 0A000001 DIRECT")

        rewritten = coordinator.rewrite_for_target(host, "Doe", "NAT/ PORT0 11718 0A000001 DIRECT")

        assert rewritten == "NAT/ PORT0 11718 C0A8010A DIRECT"
        relay_server.allocate_route.assert_not_awaited()

        await coordinator.observe(guest, ["John", "John"], "NAT CONNFAILED1 0 DIRECT")
        relay_server.allocate_route.assert_awaited_once()

        await coordinator.observe(host, ["John", "Doe"], "NAT/ NEGO0 1 RELAY")
        await coordinator.observe(host, ["Doe"], "NAT/ PORT0 11719 C0A8010A RELAY")
        await coordinator.observe(guest, ["John"], "NAT/ PORT1 8089 C0A80114 RELAY")

        host_port = coordinator.rewrite_for_target(host, "Doe", "NAT/ PORT0 11719 C0A8010A RELAY")
        guest_port = coordinator.rewrite_for_target(guest, "John", "NAT/ PORT1 8089 C0A80114 RELAY")

        assert host_port == "NAT/ PORT0 50001 CB00710A RELAY"
        assert guest_port == "NAT/ PORT1 50000 CB00710A RELAY"
        assert route.expected_ip_a == TEST_IP_JOHN
        assert route.expected_ip_b == TEST_IP_DOE

    @pytest.mark.asyncio
    async def test_three_players_track_and_relay_pairs_independently(self):
        """Relay fallback should affect only failed pairs in a three-player mesh."""
        route_ab = RelayRoute(50000, 50001)
        route_bc = RelayRoute(50002, 50003)
        relay_server = make_relay_server(route_ab, route_bc)
        coordinator = PeerchatRelayCoordinator()
        coordinator.configure(relay_server)
        host = make_client("John", TEST_IP_JOHN)
        guest_a = make_client("Doe", TEST_IP_DOE)
        guest_b = make_client("Alice", TEST_IP_ALICE)
        clients = {"John": host, "Doe": guest_a, "Alice": guest_b}
        slot_list = "SL/ M=0;S=H,C0A8010A,10000,TT,:H,C0A80114,10001,FT,:H,C0A8011E,10002,FT,:X:X:X:X:X:;"

        coordinator.remember_player_numbers(host, TEST_CHANNEL, clients, "PN/ 0=John,1=Doe,2=Alice")
        prepared = coordinator.prepare_slot_list(host, TEST_CHANNEL, clients, slot_list)

        assert len(prepared.host_requests) == 2
        assert all(message.count("H,C0A8010A") == 3 for message in prepared.messages.values())

        await coordinator.observe(host, ["John", "Doe", "Alice"], "NAT/ NEGO0 1 ROUND1")
        await coordinator.observe(guest_a, ["John"], "NAT CONNFAILED1 0 ROUND1")
        await coordinator.observe(host, ["John", "Doe", "Alice"], "NAT/ NEGO0 1 ROUND2")
        await coordinator.observe(host, ["Doe"], "NAT/ PORT0 10001 C0A8010A ROUND2")

        john_to_doe = coordinator.rewrite_for_target(host, "Doe", "NAT/ PORT0 10001 C0A8010A ROUND2")

        assert john_to_doe == "NAT/ PORT0 50001 CB00710A ROUND2"

        await coordinator.observe(host, ["John", "Doe", "Alice"], "NAT/ NEGO0 2 ROUND2")
        await coordinator.observe(host, ["Alice"], "NAT/ PORT0 10002 C0A8010A ROUND2")

        john_to_alice = coordinator.rewrite_for_target(host, "Alice", "NAT/ PORT0 10002 C0A8010A ROUND2")

        assert john_to_alice == "NAT/ PORT0 10002 C0A8010A ROUND2"

        await coordinator.observe(guest_b, ["Doe"], "NAT CONNFAILED2 1 ROUND2")
        await coordinator.observe(host, ["John", "Doe", "Alice"], "NAT/ NEGO1 2 ROUND3")
        await coordinator.observe(guest_a, ["Alice"], "NAT/ PORT1 10003 C0A80114 ROUND3")

        doe_to_alice = coordinator.rewrite_for_target(guest_a, "Alice", "NAT/ PORT1 10003 C0A80114 ROUND3")

        assert doe_to_alice == "NAT/ PORT1 50003 CB00710A ROUND3"
        assert relay_server.allocate_route.await_count == 2

    @pytest.mark.asyncio
    async def test_same_public_ip_keeps_internal_port_address(self):
        """Players sharing a public IP should retain their internal addresses."""
        route = RelayRoute(50000, 50001)
        relay_server = make_relay_server(route)
        coordinator = PeerchatRelayCoordinator()
        coordinator.configure(relay_server)
        host = make_client("John", TEST_IP_JOHN)
        guest = make_client("Doe", TEST_IP_JOHN)
        clients = {"John": host, "Doe": guest}
        slot_list = "SL/ M=0;S=H,C0A8010A,10000,TT,:H,C0A8010A,10001,FT,:X:X:X:X:X:X:;"
        coordinator.remember_player_numbers(host, TEST_CHANNEL, clients, "PN/ 0=John,1=Doe")
        coordinator.prepare_slot_list(host, TEST_CHANNEL, clients, slot_list)
        await coordinator.observe(host, ["John", "Doe"], "NAT/ NEGO0 1 COOKIE")
        await coordinator.observe(host, ["Doe"], "NAT/ PORT0 10000 0A000001 COOKIE")

        rewritten = coordinator.rewrite_for_target(host, "Doe", "NAT/ PORT0 10000 0A000001 COOKIE")

        assert rewritten == "NAT/ PORT0 10000 0A000001 COOKIE"

    def test_other_games_are_not_modified(self):
        """Peerchat relay preparation should not modify other games."""
        coordinator = PeerchatRelayCoordinator()
        coordinator.configure(make_relay_server())
        host = make_client("John", TEST_IP_JOHN)
        guest = make_client("Doe", TEST_IP_DOE)
        host.game_name = "redalert3pc"
        slot_list = "SL/ M=0;S=H,C0A8010A,10000,TT,:H,C0A80114,10001,FT,:X:X:X:X:X:X:;"

        prepared = coordinator.prepare_slot_list(host, TEST_CHANNEL, {"John": host, "Doe": guest}, slot_list)

        assert prepared is None

    def test_non_slot_list_utm_is_not_modified(self):
        """Only SL/ messages should be prepared as CNC3 slot lists."""
        coordinator = PeerchatRelayCoordinator()
        coordinator.configure(make_relay_server())
        host = make_client("John", TEST_IP_JOHN)
        guest = make_client("Doe", TEST_IP_DOE)
        text = "GM/ opts=foo;S=H,C0A8010A,1,x,:H,C0A80114,2,y,:;more=1;"

        prepared = coordinator.prepare_slot_list(host, TEST_CHANNEL, {"John": host, "Doe": guest}, text)

        assert prepared is None

    def test_malformed_port_message_is_not_parsed(self):
        """A truncated PORT message should not reach rewriting."""
        assert PeerchatRelayCoordinator._parse_nat("NAT/ PORT0 CK") is None
        assert PeerchatRelayCoordinator._parse_nat("NAT/ PORT0 11718 COOKIE") is None

    def test_unmatched_slot_does_not_use_arbitrary_channel_member(self):
        """An unmatched slot must not be assigned to a spectator or unverified client."""
        coordinator = PeerchatRelayCoordinator()
        coordinator.configure(make_relay_server())
        host = make_client("John", TEST_IP_JOHN)
        spectator = make_client("Alice", TEST_IP_ALICE)
        guest = make_client("Doe", TEST_IP_DOE)
        clients = {"John": host, "Alice": spectator, "Doe": guest}
        slot_list = "SL/ M=0;S=H,C0A8010A,10000,TT,:H,C0A80163,10001,FT,:X:X:X:X:X:X:;"

        prepared = coordinator.prepare_slot_list(host, TEST_CHANNEL, clients, slot_list)

        assert prepared is None

    def test_relay_allows_same_ip_port_rebind_after_silence(self):
        """An authorized client may rebind its port after being silent."""
        relay_server = Mock()
        route = RelayRoute(50000, 50001, expected_ip_a=TEST_IP_JOHN)
        route.client_a = RelayEndpoint(TEST_IP_JOHN, 10000)
        route.client_b = RelayEndpoint(TEST_IP_DOE, 10001)
        route.client_a_last_activity = time.time() - 11
        relay_server.get_route_by_port.return_value = route
        peer_transport = Mock()
        relay_server.get_transport.return_value = peer_transport
        protocol = RelayPortProtocol(relay_server, 50000, 50001)

        protocol.datagram_received(b"game", (TEST_IP_JOHN, 20000))

        assert route.client_a.port == 20000
        peer_transport.sendto.assert_called_once_with(b"game", (TEST_IP_DOE, 10001))

    def test_route_expires_when_one_registered_endpoint_stops(self):
        """A route should expire when either registered endpoint becomes stale."""
        route = RelayRoute(50000, 50001)
        route.client_a = RelayEndpoint(TEST_IP_JOHN, 10000)
        route.client_b = RelayEndpoint(TEST_IP_DOE, 10001)
        route.client_a_last_activity = 1
        route.client_b_last_activity = time.time()

        assert route.is_stale(120)

    def test_unready_route_expires_from_last_activity(self):
        """A partially registered route should expire only after going quiet."""
        route = RelayRoute(50000, 50001)
        route.created_at = 1
        route.last_activity = time.time()

        assert not route.is_stale(120)

        route.last_activity = 1
        assert route.is_stale(120)

    @pytest.mark.asyncio
    async def test_relay_server_resolves_advertised_host_once(self):
        """The relay should expose one address to NATNEG and PeerChat."""
        servers = (
            (RelayServer(host=TEST_IP_JOHN), TEST_IP_JOHN),
            (RelayServer(host="0.0.0.0", advertised_host=TEST_RELAY_IP), TEST_RELAY_IP),
        )

        for relay_server, expected_host in servers:
            await relay_server.start()
            try:
                assert relay_server.advertised_host == expected_host
            finally:
                await relay_server.stop()

    @pytest.mark.asyncio
    async def test_wildcard_relay_requires_advertised_host(self):
        """A wildcard listener cannot be advertised to game clients."""
        with pytest.raises(ValueError, match="advertised_host"):
            await RelayServer(host="0.0.0.0").start()
