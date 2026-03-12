"""Kane's Wrath automatch game factory — UTM-based protocol with channel key matching."""

import time
from dataclasses import dataclass

from app.servers.automatch.base import (
    BasePlayer,
    GameFactory,
    encode_gamespy_username,
    find_common_maps,
    pick_random_map_index,
)


@dataclass
class KWPlayer(BasePlayer):
    """Kane's Wrath player built from channel keys + QMRES/ fields."""

    # From QMRES/ responses (game session data, filled after QMRES/)
    faction: int = -1
    broadcast_enabled: int = 0


class KWGameFactory(GameFactory):
    """
    Factory for Kane's Wrath automatch.

    Unlike RA3/Generals which use CINFO/MBOT via PRIVMSG, KW uses a UTM-based
    protocol. The bot detects searching players via b_flags channel key, reads
    their stats, matches them, and initiates the QMREQ/QMRES/QMRDY/QMGO flow.
    """

    game_id = "kw"
    nickname = "kwmatchbot"
    username = encode_gamespy_username(0x0A000001, 17461195)
    channels = ["#GPG!2157"]
    match_interval = 2.0
    valid_num_players = [2, 4]

    def create_bot(self):
        from app.servers.automatch.kw_bot import KWBot

        return KWBot(self)

    def build_player(self, nickname: str, profile_id: int, infos: dict[str, str]) -> KWPlayer:
        """Build KW player from channel key values."""
        return KWPlayer(
            nickname=nickname,
            profile_id=profile_id,
            points=max(1, int(infos.get("b_onlineRank", infos.get("rank_", "1000")))),
            ip=0,
            side=-1,
            color=int(infos.get("color_", "-1")),
            nat=int(infos.get("NAT", "0")),
            num_players=2,
            map_bitset=infos.get("mapBit", ""),
            ladder_id=int(infos.get("lddrID", "1")),
            queued_at=time.time(),
            infos=infos,
        )

    def try_match(self, players: dict[str, BasePlayer]) -> list[tuple[list[BasePlayer], str]] | None:
        """Not used — KW bot uses find_matches() with UTM flow instead."""
        return None

    def find_matches(self, players: dict[str, KWPlayer]) -> list[tuple[list[KWPlayer], int]] | None:
        """
        Find compatible players from the searching pool.

        Returns list of (matched_players, map_index) tuples, or None.
        """
        if len(players) < 2:
            return None

        pool = list(players.values())
        match = self._match_1v1(pool)
        if match:
            return [match]
        return None

    # ── 1v1 matching ────────────────────────────────────────────────────────

    def _match_1v1(self, pool: list[KWPlayer]) -> tuple[list[KWPlayer], int] | None:
        """Find best 1v1 match using point percentage fitness."""
        if len(pool) < 2:
            return None

        best_pair: tuple[KWPlayer, KWPlayer] | None = None
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

        # Map check — skip if no map data available (channel key matching)
        if p1.map_bitset and p2.map_bitset:
            common = find_common_maps(p1.map_bitset, p2.map_bitset)
            if not common:
                return None
            map_index = pick_random_map_index(common)
            if map_index == -1:
                return None
        else:
            map_index = 0

        return [p1, p2], map_index


def _compute_fitness(p1: KWPlayer, p2: KWPlayer) -> float:
    """
    Compute match fitness based on rank closeness.

    KW ranks are small integers (b_onlineRank), so we just use
    rank ratio as fitness — closer ranks = higher fitness.
    Always returns > 0 so any two players can match.
    """
    pts1 = max(1, p1.points)
    pts2 = max(1, p2.points)
    return min(pts1, pts2) / max(pts1, pts2)
