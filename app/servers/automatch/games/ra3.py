"""RA3 automatch game factory: ELO matching on the server's ratings, client map bitsets."""

import random
import time
from dataclasses import dataclass
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
    """Returns the map bitset of the maps that every player has."""
    maps = players[0].map_bitset
    for player in players[1:]:
        maps = find_common_maps(maps, player.map_bitset)
    return maps


def can_meet(a: RA3Player, b: RA3Player) -> bool:
    return within_reach(a.points, a.point_range, b.points, b.point_range)


def all_can_meet(players: list[RA3Player]) -> bool:
    return all(can_meet(a, b) for a, b in combinations(players, 2))


def closest_first(pair: tuple[RA3Player, RA3Player]) -> tuple[int, float]:
    """Orders pairs by their rating gap, then by the time the first of them started to search."""
    a, b = pair
    return abs(a.points - b.points), min(a.queued_at, b.queued_at)


def rating_spread(group: list[RA3Player]) -> int:
    """The rating gap between the first and the last player of a group in rating order."""
    return group[-1].points - group[0].points


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
        """Pairs the two players with the closest ratings that can meet and share a map."""
        pairs = [(a, b) for a, b in combinations(pool, 2) if can_meet(a, b) and common_maps([a, b])]
        if not pairs:
            return None
        a, b = min(pairs, key=closest_first)
        return self._finish([a, b])

    # ── 2v2 random partners (LadID=2) ───────────────────────────────────────

    def _match_2v2_random(self, pool: list[RA3Player]) -> tuple[list[BasePlayer], str] | None:
        """Takes the four neighbours in rating order with the smallest spread, then balances the teams."""
        ranked = sorted(pool, key=lambda player: player.points)
        groups = []
        for start in range(len(ranked) - 3):
            group = ranked[start : start + 4]
            if all_can_meet(group) and common_maps(group):
                groups.append(group)
        if not groups:
            return None
        team_a, team_b = balanced_split(min(groups, key=rating_spread))
        return self._finish(team_a + team_b, team_ids=[0, 0, 1, 1])

    # ── Team 2v2 (LadID=3) ──────────────────────────────────────────────────

    def _match_2v2_team(self, pool: list[RA3Player]) -> tuple[list[BasePlayer], str] | None:
        """Pairs the two pre-formed teams with the closest average ratings."""
        by_nickname = {player.nickname: player for player in pool}
        teams: list[tuple[RA3Player, RA3Player]] = []
        in_a_team: set[str] = set()
        for player in pool:
            mate = by_nickname.get(player.teammate or "")
            # A team is two players who name each other as teammate1.
            if mate is None or mate.teammate != player.nickname:
                continue
            if player.nickname in in_a_team or mate.nickname in in_a_team:
                continue
            teams.append((player, mate))
            in_a_team.update((player.nickname, mate.nickname))

        best_gap = None
        best_match = None
        for team_a, team_b in combinations(teams, 2):
            gap = abs(team_average([p.points for p in team_a]) - team_average([p.points for p in team_b]))
            matched = [*team_a, *team_b]
            if gap > min(p.point_range for p in matched) or not common_maps(matched):
                continue
            if best_gap is None or gap < best_gap:
                best_gap = gap
                best_match = matched
        if best_match is None:
            return None
        return self._finish(best_match, team_ids=[0, 0, 1, 1])

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
