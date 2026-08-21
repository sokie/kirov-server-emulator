"""CNC3 peerchat NAT negotiation through the UDP relay."""

import asyncio
import ipaddress
import time
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from app.models.fesl_types import GAMESPY_GAME_KEY_MAP
from app.models.relay_types import RelayRoute
from app.util.logging_helper import get_logger

if TYPE_CHECKING:
    from app.servers.peerchat_server import IRCClient
    from app.servers.relay_server import RelayServer

logger = get_logger(__name__)

PlayerPair = frozenset[str]


@dataclass
class PeerchatNegotiation:
    pair: PlayerPair
    route: RelayRoute | None = None
    completed: set[str] = field(default_factory=set)
    updated_at: float = field(default_factory=time.time)


@dataclass
class PeerchatLobby:
    channel: str
    host: str
    slots: list[str]
    slot_players: dict[int, str]
    node_players: dict[int, str]
    clients: dict[str, "IRCClient"]
    updated_at: float = field(default_factory=time.time)


@dataclass
class SlotPreparation:
    messages: dict[str, str]
    host_requests: list[tuple[str, str]]


class PeerchatRelayCoordinator:
    """Provide pairwise direct-to-relay fallback for CNC3 and Kane's Wrath."""

    negotiation_ttl = 300.0

    def __init__(self):
        self.relay_server: RelayServer | None = None
        self.advertised_host: str | None = None
        self.lobbies: dict[str, PeerchatLobby] = {}
        self.channel_nodes: dict[str, dict[int, str]] = {}
        self.negotiations: dict[tuple[str, PlayerPair], PeerchatNegotiation] = {}
        self.active_pairs: dict[tuple[str, int], PlayerPair] = {}
        self.pair_routes: dict[PlayerPair, RelayRoute] = {}
        self.pair_sides: dict[PlayerPair, tuple[str, str]] = {}
        self.pair_cookies: dict[PlayerPair, str] = {}
        self.prepared_pairs: set[PlayerPair] = set()
        self.relay_pairs: set[PlayerPair] = set()
        self.player_ips: dict[str, str] = {}
        self._route_lock = asyncio.Lock()

    def configure(
        self,
        relay_server: "RelayServer | None",
        advertised_host: str | None = None,
    ):
        self.relay_server = relay_server
        self.advertised_host = advertised_host
        self.lobbies.clear()
        self.channel_nodes.clear()
        self.negotiations.clear()
        self.active_pairs.clear()
        self.pair_routes.clear()
        self.pair_sides.clear()
        self.pair_cookies.clear()
        self.prepared_pairs.clear()
        self.relay_pairs.clear()
        self.player_ips.clear()

    def remember_player_numbers(
        self,
        host: "IRCClient",
        channel: str,
        clients: dict[str, "IRCClient"],
        text: str,
    ):
        if not self._is_cnc3(host) or not text.startswith("PN/ "):
            return

        nodes: dict[int, str] = {}
        for item in text[4:].split(","):
            number, separator, nickname = item.partition("=")
            if separator and number.isdigit() and nickname in clients:
                nodes[int(number)] = nickname
        if not nodes:
            return

        self.channel_nodes[channel] = nodes
        for nickname in nodes.values():
            self.player_ips[nickname] = clients[nickname].addr[0]
        lobby = self.lobbies.get(channel)
        if lobby is not None:
            lobby.node_players = nodes
            lobby.updated_at = time.time()

    def prepare_slot_list(
        self,
        host: "IRCClient",
        channel: str,
        clients: dict[str, "IRCClient"],
        text: str,
    ) -> SlotPreparation | None:
        """Give every stock client a shared slot IP before NAT starts."""
        if self.relay_server is None or not self._is_cnc3(host):
            return None

        self._prune_state()
        parsed = self._parse_slot_list(text)
        host_nick = host.user.nickname
        if parsed is None or host_nick is None:
            return None
        prefix, slots, suffix = parsed
        human_slots = [index for index, value in enumerate(slots) if value.startswith("H,")]
        if len(human_slots) < 2:
            return None

        node_players = self.channel_nodes.get(channel, {})
        slot_players = self._match_slot_players(host, clients, slots, human_slots, node_players)
        if len(slot_players) != len(human_slots) or slot_players[human_slots[0]] != host_nick:
            logger.warning("Could not match every CNC3 slot to a peerchat client")
            return None

        sentinel = self._ip_hex(host.addr[0])
        if sentinel is None:
            return None
        for nickname in slot_players.values():
            self.player_ips[nickname] = clients[nickname].addr[0]

        prepared_slots = slots.copy()
        host_requests: list[tuple[str, str]] = []
        for slot, nickname in slot_players.items():
            fields = prepared_slots[slot].split(",")
            if len(fields) < 3:
                return None
            if nickname != host_nick and fields[1].upper() != sentinel:
                signed_ip = self._signed_ipv4(host.addr[0])
                host_requests.append((clients[nickname].user.get_prefix(), f"REQ/ IP={signed_ip}"))
            fields[1] = sentinel
            prepared_slots[slot] = ",".join(fields)

        players = [slot_players[index] for index in human_slots]
        for left_index, left in enumerate(players):
            for right in players[left_index + 1 :]:
                pair = frozenset((left, right))
                self.prepared_pairs.add(pair)
                self.relay_pairs.discard(pair)

        self.lobbies[channel] = PeerchatLobby(
            channel=channel,
            host=host_nick,
            slots=prepared_slots,
            slot_players=slot_players,
            node_players=node_players,
            clients=clients,
        )
        prepared_text = prefix + ":".join(prepared_slots) + suffix
        messages = {nickname: prepared_text for nickname in slot_players.values()}
        if host_requests:
            logger.info(
                "Preparing CNC3 slot IPs through %d stock REQ/ IP update(s)",
                len(host_requests),
            )
        return SlotPreparation(messages, host_requests)

    async def observe(self, client: "IRCClient", targets: list[str], text: str):
        if not self._is_cnc3(client) or not targets:
            return

        self._prune_state()
        parsed = self._parse_nat(text)
        nickname = client.user.nickname
        if parsed is None or nickname is None:
            return
        command, node, peer_node, cookie, _ = parsed

        pair: PlayerPair | None = None
        if peer_node is not None:
            pair = self._pair_for_nodes(node, peer_node, nickname, targets)
            if pair is not None:
                self.active_pairs[(cookie, node)] = pair
                self.active_pairs[(cookie, peer_node)] = pair
        else:
            pair = self.active_pairs.get((cookie, node))
        if pair is None:
            pair = self._pair_from_targets(nickname, targets)
        if pair is None or pair not in self.prepared_pairs:
            return

        key = (cookie, pair)
        negotiation = self.negotiations.setdefault(key, PeerchatNegotiation(pair))
        negotiation.updated_at = time.time()

        route = self._active_route(pair) if pair in self.relay_pairs else None
        if command == "NEGO" and route is not None:
            previous_cookie = self.pair_cookies.get(pair)
            if previous_cookie is not None and previous_cookie != cookie:
                route.reset_endpoints()
                logger.info(
                    "Reset CNC3 relay ports %d/%d for negotiation %s",
                    route.port_a,
                    route.port_b,
                    cookie,
                )
            self.pair_cookies[pair] = cookie
        if route is not None:
            negotiation.route = route

        if command == "CONNDONE":
            negotiation.completed.add(nickname)
            if route is not None:
                logger.info("CNC3 relay negotiation %s connected for %s", cookie, sorted(pair))
        elif command == "CONNFAILED":
            if pair in self.relay_pairs:
                logger.warning("CNC3 relay negotiation %s failed for %s", cookie, sorted(pair))
            elif await self._enable_relay(pair):
                logger.info("CNC3 direct negotiation %s failed; relaying %s", cookie, sorted(pair))

    def rewrite_for_target(self, client: "IRCClient", target: str, text: str) -> str:
        parsed = self._parse_nat(text)
        if parsed is None:
            return text
        command, node, _, cookie, parts = parsed
        if command != "PORT":
            return text

        pair = self.active_pairs.get((cookie, node))
        if pair is None or target not in pair or pair not in self.prepared_pairs:
            return text
        negotiation = self.negotiations.get((cookie, pair))
        if negotiation is None:
            return text

        if pair not in self.relay_pairs:
            sender_ip = self.player_ips.get(client.user.nickname or "", client.addr[0])
            target_ip = self.player_ips.get(target)
            if target_ip != sender_ip:
                direct_ip = self._ip_hex(sender_ip)
                if direct_ip is not None:
                    parts[3] = direct_ip
            return " ".join(parts)

        route = self._active_route(pair)
        relay_port = self._port_for(pair, target)
        relay_ip = self._relay_ip_hex(client)
        if route is None or relay_port is None or relay_ip is None:
            logger.warning("Cannot determine relay endpoint for %s in negotiation %s", target, cookie)
            return text

        negotiation.route = route
        parts[2] = str(relay_port)
        parts[3] = relay_ip
        logger.info(
            "CNC3 relay negotiation %s: slot %d uses relay port %d for %s",
            cookie,
            node,
            relay_port,
            target,
        )
        return " ".join(parts)

    async def _enable_relay(self, pair: PlayerPair) -> bool:
        lobby = self._find_lobby(pair)
        if lobby is None:
            logger.warning("Cannot find the CNC3 lobby for %s", sorted(pair))
            return False
        sides = self._ordered_pair(lobby, pair)
        if sides is None or await self._ensure_route(pair, *sides) is None:
            return False
        self.relay_pairs.add(pair)
        return True

    async def _ensure_route(self, pair: PlayerPair, side_a: str, side_b: str) -> RelayRoute | None:
        route = self._active_route(pair)
        if route is not None:
            self._authorize_route(pair, route)
            return route
        if self.relay_server is None:
            return None

        async with self._route_lock:
            route = self._active_route(pair)
            if route is None:
                route = await self.relay_server.allocate_route()
                if route is None:
                    logger.error("Could not allocate CNC3 relay route for %s", sorted(pair))
                    return None
                self.pair_routes[pair] = route
                self.pair_sides[pair] = (side_a, side_b)
            self._authorize_route(pair, route)
            return route

    def _authorize_route(self, pair: PlayerPair, route: RelayRoute):
        sides = self.pair_sides.get(pair)
        if sides is not None:
            route.expected_ip_a = self.player_ips.get(sides[0])
            route.expected_ip_b = self.player_ips.get(sides[1])

    def _active_route(self, pair: PlayerPair) -> RelayRoute | None:
        route = self.pair_routes.get(pair)
        if route is None or self.relay_server is None:
            return None
        if self.relay_server.get_route_by_port(route.port_a) is route:
            return route
        self.pair_routes.pop(pair, None)
        self.pair_sides.pop(pair, None)
        self.pair_cookies.pop(pair, None)
        self.relay_pairs.discard(pair)
        return None

    def _port_for(self, pair: PlayerPair, nickname: str) -> int | None:
        route = self._active_route(pair)
        sides = self.pair_sides.get(pair)
        if route is None or sides is None:
            return None
        if nickname == sides[0]:
            return route.port_a
        if nickname == sides[1]:
            return route.port_b
        return None

    def _pair_for_nodes(
        self,
        node: int,
        peer_node: int,
        nickname: str,
        targets: list[str],
    ) -> PlayerPair | None:
        candidates = sorted(self.lobbies.values(), key=lambda lobby: lobby.updated_at, reverse=True)
        for lobby in candidates:
            left = lobby.node_players.get(node)
            right = lobby.node_players.get(peer_node)
            if left is not None and right is not None and nickname in lobby.clients:
                return frozenset((left, right))
        return self._pair_from_targets(nickname, targets)

    @staticmethod
    def _pair_from_targets(nickname: str, targets: list[str]) -> PlayerPair | None:
        participants = {nickname, *targets}
        return frozenset(participants) if len(participants) == 2 else None

    def _find_lobby(self, pair: PlayerPair) -> PeerchatLobby | None:
        matches = [lobby for lobby in self.lobbies.values() if pair.issubset(lobby.slot_players.values())]
        return max(matches, key=lambda lobby: lobby.updated_at, default=None)

    @staticmethod
    def _ordered_pair(lobby: PeerchatLobby, pair: PlayerPair) -> tuple[str, str] | None:
        ordered = [name for _, name in sorted(lobby.node_players.items()) if name in pair]
        if len(ordered) != 2:
            ordered = [name for _, name in sorted(lobby.slot_players.items()) if name in pair]
        return (ordered[0], ordered[1]) if len(ordered) == 2 else None

    def _prune_state(self):
        cutoff = time.time() - self.negotiation_ttl
        self.negotiations = {
            key: negotiation for key, negotiation in self.negotiations.items() if negotiation.updated_at >= cutoff
        }
        active_keys = set(self.negotiations)
        self.active_pairs = {key: pair for key, pair in self.active_pairs.items() if (key[0], pair) in active_keys}
        self.lobbies = {channel: lobby for channel, lobby in self.lobbies.items() if lobby.updated_at >= cutoff}
        for pair in list(self.pair_routes):
            self._active_route(pair)

    def _relay_ip_hex(self, client: "IRCClient") -> str | None:
        relay_host = self.advertised_host or client.writer.get_extra_info("sockname")[0]
        relay_ip = self._ip_hex(relay_host)
        if relay_ip is None:
            logger.error("Relay advertised_host must be an IPv4 address, got %r", relay_host)
        return relay_ip

    @staticmethod
    def _ip_hex(value: str) -> str | None:
        try:
            return f"{int(ipaddress.IPv4Address(value)):08X}"
        except (ipaddress.AddressValueError, TypeError):
            return None

    @staticmethod
    def _signed_ipv4(value: str) -> int:
        number = int(ipaddress.IPv4Address(value))
        return number if number < 0x80000000 else number - 0x100000000

    @staticmethod
    def _is_cnc3(client: "IRCClient") -> bool:
        return GAMESPY_GAME_KEY_MAP.get(client.game_name) in {"cnc3pc", "cnc3ep1pc"}

    @staticmethod
    def _parse_nat(text: str) -> tuple[str, int, int | None, str, list[str]] | None:
        parts = text.split()
        if len(parts) < 3 or parts[0] not in {"NAT", "NAT/"}:
            return None
        token = parts[1]
        command = next(
            (name for name in ("CONNFAILED", "CONNDONE", "PROBED", "PORT", "NEGO") if token.startswith(name)),
            None,
        )
        if command is None:
            return None
        suffix = token[len(command) :]
        if not suffix.isdigit():
            return None
        peer_node = int(parts[2]) if command in {"NEGO", "CONNDONE", "CONNFAILED"} and parts[2].isdigit() else None
        return command, int(suffix), peer_node, parts[-1], parts

    @staticmethod
    def _parse_slot_list(text: str) -> tuple[str, list[str], str] | None:
        marker = ";S="
        start = text.find(marker)
        if start < 0:
            return None
        end = text.find(";", start + len(marker))
        if end < 0:
            return None
        prefix = text[: start + len(marker)]
        return prefix, text[start + len(marker) : end].split(":"), text[end:]

    @classmethod
    def _match_slot_players(
        cls,
        host: "IRCClient",
        clients: dict[str, "IRCClient"],
        slots: list[str],
        human_slots: list[int],
        node_players: dict[int, str],
    ) -> dict[int, str]:
        host_nick = host.user.nickname
        if host_nick is None:
            return {}

        ordered_nodes = [name for _, name in sorted(node_players.items()) if name in clients]
        if len(ordered_nodes) == len(human_slots) and ordered_nodes[0] == host_nick:
            return dict(zip(human_slots, ordered_nodes, strict=True))

        result = {human_slots[0]: host_nick}
        remaining = [nickname for nickname in clients if nickname != host_nick]
        for slot in human_slots[1:]:
            fields = slots[slot].split(",")
            slot_ip = fields[1].upper() if len(fields) >= 3 else ""
            matches = [name for name in remaining if cls._ip_hex(clients[name].addr[0]) == slot_ip]
            nickname = matches[0] if len(matches) == 1 else remaining[0] if remaining else None
            if nickname is not None:
                result[slot] = nickname
                remaining.remove(nickname)
        return result


peerchat_relay = PeerchatRelayCoordinator()
