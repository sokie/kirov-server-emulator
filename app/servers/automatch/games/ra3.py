"""RA3 automatch game factory — ELO range matching, client map bitsets."""

import random
import time
from dataclasses import dataclass

from app.servers.automatch.base import BasePlayer, GameFactory, find_common_maps, pick_random_map_index


@dataclass
class RA3Player(BasePlayer):
    """RA3-specific player fields."""

    point_range: int = 1000
    points_stddev: int = 50
    teammate: str | None = None


# PointRange -> sigma coefficient for ELO interval
POINTS_RANGE_MAPPING = {"100": 1, "250": 2, "400": 4, "1000": 8}

# Ladder IDs
LAD_1V1 = 1
LAD_2V2 = 2
LAD_TEAM_2V2 = 3


class RA3GameFactory(GameFactory):
    """Factory for Red Alert 3 automatch."""

    game_id = "ra3"
    nickname = "anpwcjnybr2008"
    username = "XDqGfsuOsX|167408418"
    channels = ["#GSP!redalert3pc"]
    match_interval = 10.0
    valid_num_players = [2, 4]

    def build_player(self, nickname: str, profile_id: int, infos: dict[str, str]) -> RA3Player:
        return RA3Player(
            nickname=nickname,
            profile_id=profile_id,
            points=int(infos.get("Points", "1000")),
            points_stddev=int(infos.get("PointsStddev", "50")),
            point_range=int(infos.get("PointRange", "1000")),
            ip=int(infos.get("IP", "0")),
            side=int(infos.get("Side", "-1")),
            color=int(infos.get("Color", "-1")),
            nat=int(infos.get("NAT", "0")),
            num_players=int(infos.get("NumPlayers", "2")),
            map_bitset=infos.get("Maps", ""),
            ladder_id=int(infos.get("LadID", "1")),
            teammate=infos.get("teammate1"),
            queued_at=time.time(),
            infos=infos,
        )

    def try_match(self, players: dict[str, BasePlayer]) -> list[tuple[list[BasePlayer], str]] | None:
        if len(players) < 2:
            return None

        # Group by (num_players, ladder_id)
        pools: dict[tuple[int, int], list[RA3Player]] = {}
        for p in players.values():
            key = (p.num_players, p.ladder_id)
            pools.setdefault(key, []).append(p)  # type: ignore[arg-type]

        results: list[tuple[list[BasePlayer], str]] = []
        for (num_players, ladder_id), pool in pools.items():
            if num_players == 2 and ladder_id == LAD_1V1:
                match = self._match_1v1(pool)
                if match:
                    results.append(match)
            elif num_players == 4 and ladder_id == LAD_2V2:
                match = self._match_2v2_random(pool)
                if match:
                    results.append(match)
            elif num_players == 4 and ladder_id == LAD_TEAM_2V2:
                match = self._match_2v2_team(pool)
                if match:
                    results.append(match)

        return results or None

    # ── 1v1 ELO-range matching ──────────────────────────────────────────────

    def _match_1v1(self, pool: list[RA3Player]) -> tuple[list[BasePlayer], str] | None:
        """Find the best ELO-range pair and return (players, formatted message)."""
        if len(pool) < 2:
            return None

        best_pair: tuple[RA3Player, RA3Player] | None = None
        best_score = 0.0

        for i in range(len(pool)):
            p1 = pool[i]
            p1_elo = max(p1.points, 1)
            p1_stddev = max(p1.points_stddev, 50)
            p1_sigma = POINTS_RANGE_MAPPING.get(str(p1.point_range), 8)
            p1_interval = (p1_elo - p1_sigma * p1_stddev, p1_elo + p1_sigma * p1_stddev)

            for j in range(i + 1, len(pool)):
                p2 = pool[j]

                p2_elo = max(p2.points, 1)
                p2_stddev = max(p2.points_stddev, 50)
                p2_sigma = POINTS_RANGE_MAPPING.get(str(p2.point_range), 8)
                p2_interval = (p2_elo - p2_sigma * p2_stddev, p2_elo + p2_sigma * p2_stddev)

                overlap_low = max(p1_interval[0], p2_interval[0])
                overlap_high = min(p1_interval[1], p2_interval[1])

                if overlap_high < overlap_low:
                    continue

                overlap_len = overlap_high - overlap_low
                p1_range = p1_interval[1] - p1_interval[0]
                p2_range = p2_interval[1] - p2_interval[0]

                if p1_range == 0 or p2_range == 0:
                    continue

                score = min(overlap_len / p1_range, overlap_len / p2_range)
                score += random.randint(0, 3) / 100.0
                score = max(0.0, min(1.0, score))

                if score > best_score:
                    best_score = score
                    best_pair = (p1, p2)

        if not best_pair:
            return None

        p1, p2 = best_pair
        common = find_common_maps(p1.map_bitset, p2.map_bitset)
        if not common:
            return None
        map_index = pick_random_map_index(common)
        if map_index == -1:
            return None
        msg = self._format_matched([p1, p2], map_index)
        return [p1, p2], msg

    # ── 2v2 random matching (LadID=2) ───────────────────────────────────────

    def _match_2v2_random(self, pool: list[RA3Player]) -> tuple[list[BasePlayer], str] | None:
        """Match 4 random players. No ELO check — mirrors reference."""
        if len(pool) < 4:
            return None

        matched = pool[:4]
        common = matched[0].map_bitset
        for p in matched[1:]:
            common = find_common_maps(common, p.map_bitset)
        if not common:
            return None
        map_index = pick_random_map_index(common)
        if map_index == -1:
            return None
        msg = self._format_matched(matched, map_index, team_ids=[0, 0, 1, 1])
        return list(matched), msg

    # ── Team 2v2 matching (LadID=3) ─────────────────────────────────────────

    def _match_2v2_team(self, pool: list[RA3Player]) -> tuple[list[BasePlayer], str] | None:
        """
        Match pre-formed teams using teammate1 field.

        Both players in a team must reference each other. Two complete teams
        are required for a match.
        """
        # Find complete teams (mutual teammate references)
        teams: list[tuple[RA3Player, RA3Player]] = []
        used: set[str] = set()

        for p in pool:
            if p.nickname in used or not p.teammate:
                continue
            # Find the teammate in the pool
            mate = next((t for t in pool if t.nickname == p.teammate and t.nickname not in used), None)
            if mate and mate.teammate == p.nickname:
                teams.append((p, mate))
                used.add(p.nickname)
                used.add(mate.nickname)

        if len(teams) < 2:
            return None

        team_a = teams[0]
        team_b = teams[1]
        matched: list[RA3Player] = [team_a[0], team_a[1], team_b[0], team_b[1]]
        common = matched[0].map_bitset
        for p in matched[1:]:
            common = find_common_maps(common, p.map_bitset)
        if not common:
            return None
        map_index = pick_random_map_index(common)
        if map_index == -1:
            return None
        msg = self._format_matched(matched, map_index, team_ids=[0, 0, 1, 1])
        return list(matched), msg

    # ── Message formatting ──────────────────────────────────────────────────

    def _format_matched(
        self,
        players: list[RA3Player],
        map_index: int,
        team_ids: list[int] | None = None,
    ) -> str:
        """
        Build RA3 MBOT:MATCHED message.

        Format: MBOT:MATCHED {mapIdx} {matchId} 1 {p1} {ip1} {side1} {color1} {nat1} -1 {points1} {team1} ...
        """
        match_id = random.randint(2000, 20000)
        parts = [f"MBOT:MATCHED {map_index} {match_id} 1"]

        if team_ids is None:
            if len(players) == 2:
                team_ids = [0, 1]
            else:
                team_ids = [0] * (len(players) // 2) + [1] * (len(players) // 2)

        for player, team_id in zip(players, team_ids):
            parts.append(
                f"{player.nickname} {player.ip} {player.side} {player.color} {player.nat} -1 {player.points} {team_id}"
            )

        return " ".join(parts)
