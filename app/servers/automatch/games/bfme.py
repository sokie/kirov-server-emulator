"""Battle for Middle-earth automatch: same as Generals, with custom BFME ladder ranks."""

import random

from app.servers.automatch.base import BasePlayer, encode_gamespy_username, find_common_maps
from app.servers.automatch.games.generals import GeneralsGameFactory, GeneralsPlayer

NO_RANK_LIMIT = 2**31 - 1


class BfmeGameFactory(GeneralsGameFactory):
    game_id = "bfme"
    nickname = "bfmeqmbot"
    # The game finds the bot by this profile id. It must match the <QMBot> id in static/servserv/lotrbfme/config.txt.
    username = encode_gamespy_username(0x0A000001, 17461196)
    channels = ["#GPG!662"]

    def build_player(self, nickname: str, profile_id: int, infos: dict[str, str]) -> GeneralsPlayer:
        """Reads the ladder rank from Points and the rank window from PointsMin and PointsMax."""
        player = super().build_player(nickname, profile_id, infos)
        player.points = int(infos.get("Points", "-1"))
        player.min_points = int(infos.get("PointsMin", "1"))
        player.max_points = int(infos.get("PointsMax", str(NO_RANK_LIMIT)))
        return player

    def try_match(self, players: dict[str, BasePlayer]) -> list[tuple[list[BasePlayer], str]] | None:
        """Matches players by the EXE and INI checksums in their CINFO. A player without both is not matched."""
        builds: dict[tuple[str, str], dict[str, BasePlayer]] = {}
        for nick, player in players.items():
            exe, ini = player.infos.get("EXE"), player.infos.get("INI")
            if exe and ini:
                builds.setdefault((exe, ini), {})[nick] = player

        results: list[tuple[list[BasePlayer], str]] = []
        for build_players in builds.values():
            results.extend(super().try_match(build_players) or [])
        return results or None

    def _widen(self, player: GeneralsPlayer):
        """Drops the rank window. The map bitfield stays, so a pair still needs a map both players have."""
        player.widened = True

    def _fitness(self, p1: GeneralsPlayer, p2: GeneralsPlayer) -> float:
        """Scores a pair that is within the rank window and shares at least one map in the map bitfield."""
        rank1, rank2 = _rank(p1), _rank(p2)
        if not p1.widened and not p1.min_points <= rank2 <= p1.max_points:
            return 0.0
        if not p2.widened and not p2.min_points <= rank1 <= p2.max_points:
            return 0.0
        if not find_common_maps(p1.map_bitset, p2.map_bitset):
            return 0.0
        return max(1, min(rank1, rank2)) / max(1, rank1, rank2)

    def _format_matched(self, players: list[GeneralsPlayer], map_index: int) -> str:
        """
        Build BFME MBOT:MATCHED message.

        Format: MBOT:MATCHED {mapIdx} {seed} {p1} {ip1} {side1} {color1} {nat1} {rank1} {p2} ...
        """
        seed = random.randint(0, 2**31 - 1)
        parts = [f"MBOT:MATCHED {map_index} {seed}"]

        # The sixth field is the ladder rank shown on the loading screen. A rank below 1 shows as unavailable.
        for player in players:
            ip_unsigned = player.ip & 0xFFFFFFFF
            parts.append(f"{player.nickname} {ip_unsigned} {player.side} {player.color} {player.nat} {player.points}")

        return " ".join(parts)


def _rank(player: GeneralsPlayer) -> int:
    # A player without a ladder rank uses the top of their rank window.
    return player.points if player.points >= 1 else player.max_points
