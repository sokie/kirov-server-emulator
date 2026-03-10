"""Generals/Zero Hour automatch game factory — fitness score matching."""

import random
import time
from dataclasses import dataclass, field

from app.servers.automatch.base import (
    BasePlayer,
    GameFactory,
    encode_gamespy_username,
    find_common_maps,
    pick_random_map_index,
)


@dataclass
class GeneralsPlayer(BasePlayer):
    """Generals-specific player fields."""

    min_points: int = 0
    max_points: int = 100
    max_discons: int = 100
    discons: int = 0
    max_ping: int = 1000
    pseudo_pings: list[int] = field(default_factory=list)
    widened: bool = False
    time_to_widen: float = 0.0


class GeneralsGameFactory(GameFactory):
    """Factory for Generals / Zero Hour automatch."""

    game_id = "generals_zh"
    nickname = "qmbot"
    # Username must be GameSpy-encoded: X<encoded_ip>X|<profile_id>
    # The game decodes this via piDemangleUser before accepting any MBOT: messages.
    # encode_gamespy_username(0x0A000001, 17461195) -> "X1fsaFv1DX|17461195"
    username = encode_gamespy_username(0x0A000001, 17461195)
    channels = ["#GPG!597", "#GPG!392"]
    match_interval = 2.0
    valid_num_players = [2, 4, 6, 8]

    def get_supported_commands(self) -> set[str]:
        return {"WIDEN"}

    def handle_extra_command(self, command: str, player: BasePlayer) -> str | None:
        if command != "WIDEN":
            return None
        if not isinstance(player, GeneralsPlayer):
            return None
        player.widened = True
        player.map_bitset = "1" * len(player.map_bitset)
        return "MBOT:WIDENINGSEARCH"

    def build_player(self, nickname: str, profile_id: int, infos: dict[str, str]) -> GeneralsPlayer:
        pseudo_pings: list[int] = []
        pings_str = infos.get("Pings", "")
        if pings_str and len(pings_str) % 2 == 0:
            pseudo_pings = [int(pings_str[i : i + 2], 16) for i in range(0, len(pings_str), 2)]

        widen_secs = int(infos.get("Widen", "0"))

        return GeneralsPlayer(
            nickname=nickname,
            profile_id=profile_id,
            points=max(1, int(infos.get("Points", "1"))),
            ip=int(infos.get("IP", "0")),
            side=int(infos.get("Side", "-1")),
            color=int(infos.get("Color", "-1")),
            nat=int(infos.get("NAT", "0")),
            num_players=int(infos.get("NumPlayers", "2")),
            map_bitset=infos.get("Maps", ""),
            ladder_id=int(infos.get("LadID", "0")),
            min_points=int(infos.get("PointsMin", "0")),
            max_points=int(infos.get("PointsMax", "100")),
            max_discons=int(infos.get("DisconMax", "100")),
            discons=int(infos.get("Discons", "0")),
            max_ping=int(infos.get("PingMax", "1000")),
            pseudo_pings=pseudo_pings,
            time_to_widen=time.time() + widen_secs if widen_secs > 0 else 0.0,
            queued_at=time.time(),
            infos=infos,
        )

    def on_match_loop_tick(self, players: dict[str, BasePlayer], now: float) -> list[tuple[str, str]]:
        messages: list[tuple[str, str]] = []
        for nick, player in list(players.items()):
            if not isinstance(player, GeneralsPlayer):
                continue
            if player.time_to_widen > 0 and player.time_to_widen <= now:
                player.time_to_widen = 0
                player.map_bitset = "1" * len(player.map_bitset)
                player.widened = True
                messages.append((nick, "MBOT:WIDENINGSEARCH"))
        return messages

    def try_match(self, players: dict[str, BasePlayer]) -> list[tuple[list[BasePlayer], str]] | None:
        if len(players) < 2:
            return None

        pools: dict[int, list[GeneralsPlayer]] = {}
        for p in players.values():
            pools.setdefault(p.num_players, []).append(p)  # type: ignore[arg-type]

        results: list[tuple[list[BasePlayer], str]] = []
        for num_players, pool in pools.items():
            if num_players == 2:
                match = self._match_1v1(pool)
                if match:
                    results.append(match)
            else:
                match = self._match_team(pool, num_players)
                if match:
                    results.append(match)

        return results or None

    def _match_1v1(self, pool: list[GeneralsPlayer]) -> tuple[list[BasePlayer], str] | None:
        if len(pool) < 2:
            return None

        best_pair: tuple[GeneralsPlayer, GeneralsPlayer] | None = None
        best_fitness = 0.0

        for i in range(len(pool)):
            for j in range(i + 1, len(pool)):
                fitness = _compute_fitness(pool[i], pool[j])
                if fitness > best_fitness:
                    best_fitness = fitness
                    best_pair = (pool[i], pool[j])

        if not best_pair:
            return None

        p1, p2 = best_pair
        map_index = self._pick_map([p1, p2])
        if map_index == -1:
            return None

        msg = self._format_matched([p1, p2], map_index)
        return [p1, p2], msg

    def _match_team(self, pool: list[GeneralsPlayer], num_players: int) -> tuple[list[BasePlayer], str] | None:
        team_size = num_players // 2
        if len(pool) < team_size * 2:
            return None

        for i in range(len(pool)):
            team_a = [pool[i]]

            for j in range(i + 1, len(pool)):
                if len(team_a) >= team_size:
                    break
                if _compute_fitness(pool[i], pool[j]) > 0:
                    team_a.append(pool[j])

            if len(team_a) != team_size:
                continue

            team_b: list[GeneralsPlayer] = []
            for candidate in pool:
                if candidate in team_a:
                    continue
                if len(team_b) >= team_size:
                    break
                if all(_compute_fitness(a, candidate) > 0 for a in team_a):
                    team_b.append(candidate)

            if len(team_b) != team_size:
                continue

            all_players = team_a + team_b
            common = all_players[0].map_bitset
            for p in all_players[1:]:
                common = find_common_maps(common, p.map_bitset)
            if not common:
                continue

            map_index = pick_random_map_index(common)
            if map_index == -1:
                continue

            msg = self._format_matched(all_players, map_index)
            return list(all_players), msg

        return None

    def _pick_map(self, players: list[GeneralsPlayer]) -> int:
        """Pick a map by intersecting client-provided bitsets."""
        if not players:
            return -1

        common = players[0].map_bitset
        for p in players[1:]:
            common = find_common_maps(common, p.map_bitset)

        if not common:
            return -1

        return pick_random_map_index(common)

    def _format_matched(self, players: list[GeneralsPlayer], map_index: int) -> str:
        """
        Build Generals MBOT:MATCHED message.

        Format: MBOT:MATCHED {mapIdx} {seed} {p1} {ip1} {side1} {color1} {nat1} {p2} ...
        """
        seed = random.randint(0, 2**31 - 1)
        parts = [f"MBOT:MATCHED {map_index} {seed}"]

        for player in players:
            ip_unsigned = player.ip & 0xFFFFFFFF
            parts.append(f"{player.nickname} {ip_unsigned} {player.side} {player.color} {player.nat}")

        return " ".join(parts)


def _compute_fitness(p1: GeneralsPlayer, p2: GeneralsPlayer) -> float:
    """
    Compute match fitness between two Generals players.
    Mirrors the C++ computeMatchFitness logic.
    """
    pts1 = max(1, p1.points)
    pts2 = max(1, p2.points)

    p1_pct = pts2 * 100 // pts1
    p2_pct = pts1 * 100 // pts2

    if not p1.widened and (p1_pct < p1.min_points or p1_pct > p1.max_points):
        return 0.0

    if not p2.widened and (p2_pct < p2.min_points or p2_pct > p2.max_points):
        return 0.0

    if p1.max_discons != 0 and not p1.widened and p2.discons > p1.max_discons:
        return 0.0
    if p2.max_discons != 0 and not p2.widened and p1.discons > p2.max_discons:
        return 0.0

    common_maps = find_common_maps(p1.map_bitset, p2.map_bitset)
    if not common_maps:
        return 0.0

    point_percent = min(pts1, pts2) / max(pts1, pts2)
    return point_percent
