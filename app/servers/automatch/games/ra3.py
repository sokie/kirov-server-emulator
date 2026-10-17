"""RA3 automatch game factory: ELO matching on the server's ratings, client map bitsets."""

import random
import time
from dataclasses import dataclass
from functools import reduce
from itertools import combinations

from app.db.crud import get_mode_elo
from app.db.database import create_session
from app.models.game_config import GAME_ID_RA
from app.models.ladder import INITIAL_ELO, SEARCH_WINDOW, balanced_split, team_average, within_reach
from app.servers.automatch.base import BasePlayer, GameFactory, find_common_maps, pick_random_map_index


@dataclass
class RA3Player(BasePlayer):
    """RA3-specific player fields."""

    point_range: int = SEARCH_WINDOW  # the rating difference the player accepts
    teammate: str | None = None


# Ladder IDs
LAD_1V1 = 1
LAD_2V2 = 2
LAD_TEAM_2V2 = 3

LADDER_MODES = {LAD_1V1: "ranked_1v1", LAD_2V2: "ranked_2v2", LAD_TEAM_2V2: "ranked_2v2"}


def ladder_elo(profile_id: int, ladder_id: int) -> int:
    """Returns the player's ELO in the mode the ladder rates."""
    if profile_id <= 0:
        return INITIAL_ELO
    session = create_session()
    try:
        return get_mode_elo(session, profile_id, GAME_ID_RA, LADDER_MODES.get(ladder_id, "ranked_1v1"))
    finally:
        session.close()


def common_maps(players: list[RA3Player]) -> str:
    return reduce(find_common_maps, (p.map_bitset for p in players[1:]), players[0].map_bitset)


def all_within_reach(players: list[RA3Player]) -> bool:
    return all(within_reach(a.points, a.point_range, b.points, b.point_range) for a, b in combinations(players, 2))


class RA3GameFactory(GameFactory):
    """Factory for Red Alert 3 automatch."""

    game_id = "ra3"
    nickname = "anpwcjnybr2008"
    username = "XDqGfsuOsX|167408418"
    channels = ["#GSP!redalert3pc"]
    match_interval = 10.0
    valid_num_players = [2, 4]

    def build_player(self, nickname: str, profile_id: int, infos: dict[str, str]) -> RA3Player:
        ladder_id = int(infos.get("LadID", "1"))
        return RA3Player(
            nickname=nickname,
            profile_id=profile_id,
            points=ladder_elo(profile_id, ladder_id),
            point_range=int(infos.get("PointRange", str(SEARCH_WINDOW))),
            ip=int(infos.get("IP", "0")),
            side=int(infos.get("Side", "-1")),
            color=int(infos.get("Color", "-1")),
            nat=int(infos.get("NAT", "0")),
            num_players=int(infos.get("NumPlayers", "2")),
            map_bitset=infos.get("Maps", ""),
            ladder_id=ladder_id,
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
            elif num_players == 4 and ladder_id == LAD_2V2:
                match = self._match_2v2_random(pool)
            elif num_players == 4 and ladder_id == LAD_TEAM_2V2:
                match = self._match_2v2_team(pool)
            else:
                match = None
            if match:
                results.append(match)

        return results or None

    def _finish(
        self, matched: list[RA3Player], team_ids: list[int] | None = None
    ) -> tuple[list[BasePlayer], str] | None:
        map_index = pick_random_map_index(common_maps(matched))
        if map_index == -1:
            return None
        return list(matched), self._format_matched(matched, map_index, team_ids)

    # ── 1v1 ─────────────────────────────────────────────────────────────────

    def _match_1v1(self, pool: list[RA3Player]) -> tuple[list[BasePlayer], str] | None:
        """Pairs the two players with the closest ratings that are within reach and share a map."""
        pairs = [
            (abs(a.points - b.points), min(a.queued_at, b.queued_at), a, b)
            for a, b in combinations(pool, 2)
            if within_reach(a.points, a.point_range, b.points, b.point_range) and common_maps([a, b])
        ]
        if not pairs:
            return None
        _, _, a, b = min(pairs, key=lambda pair: pair[:2])
        return self._finish([a, b])

    # ── 2v2 random partners (LadID=2) ───────────────────────────────────────

    def _match_2v2_random(self, pool: list[RA3Player]) -> tuple[list[BasePlayer], str] | None:
        """Takes the four neighbours in rating order with the smallest spread, then balances the teams."""
        ranked = sorted(pool, key=lambda p: p.points)
        groups = [ranked[i : i + 4] for i in range(len(ranked) - 3)]
        groups = [g for g in groups if all_within_reach(g) and common_maps(g)]
        if not groups:
            return None
        group = min(groups, key=lambda g: g[-1].points - g[0].points)
        team_a, team_b = balanced_split(group, lambda p: p.points)
        return self._finish(team_a + team_b, team_ids=[0, 0, 1, 1])

    # ── Team 2v2 (LadID=3) ──────────────────────────────────────────────────

    def _match_2v2_team(self, pool: list[RA3Player]) -> tuple[list[BasePlayer], str] | None:
        """Pairs the two pre-formed teams (mutual teammate1) with the closest average ratings."""
        teams: list[tuple[RA3Player, RA3Player]] = []
        used: set[str] = set()
        for p in pool:
            if p.nickname in used or not p.teammate:
                continue
            mate = next((t for t in pool if t.nickname == p.teammate and t.nickname not in used), None)
            if mate and mate.teammate == p.nickname:
                teams.append((p, mate))
                used.update((p.nickname, mate.nickname))

        candidates = []
        for team_a, team_b in combinations(teams, 2):
            gap = abs(team_average([p.points for p in team_a]) - team_average([p.points for p in team_b]))
            matched = [*team_a, *team_b]
            if gap <= min(p.point_range for p in matched) and common_maps(matched):
                candidates.append((gap, matched))
        if not candidates:
            return None
        _, matched = min(candidates, key=lambda c: c[0])
        return self._finish(matched, team_ids=[0, 0, 1, 1])

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
