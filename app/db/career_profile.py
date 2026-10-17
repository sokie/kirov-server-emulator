"""
Web profile data for Red Alert 3, Tiberium Wars and Kane's Wrath: every lifetime stat, per mode and per faction.

All online is the career's all_online bucket, so its streaks, averages and ratios cover every match in order
instead of adding up the modes.
"""

from sqlmodel import Session

from app.db.crud import get_persona_by_id, get_player_level, get_player_stats
from app.models import cnc3_stats, ra3_stats
from app.models.game_config import GAME_ID_RA, KW_FACTION_DISPLAY, RA3_FACTION_DISPLAY, TW_FACTION_DISPLAY

MODES: tuple[str, ...] = (ra3_stats.ALL_ONLINE, *ra3_stats.MODES)
MODE_LABELS: dict[str, str] = {
    ra3_stats.ALL_ONLINE: "All online",
    "unranked": "Unranked",
    "ranked_1v1": "Ranked 1v1",
    "ranked_2v2": "Ranked 2v2",
    "clan_1v1": "Clan 1v1",
    "clan_2v2": "Clan 2v2",
}
RATED_MODES: tuple[str, ...] = ("ranked_1v1", "ranked_2v2", "clan_1v1", "clan_2v2")
TIME_STATS = ("total_time_played", "avg_game_length")

# Kane's Wrath: each parent faction with all its subfactions, then the subfactions.
KW_PROFILE_FACTIONS: list[tuple[str, str, str]] = [
    ("GDI (all)", "parents", "gdi"),
    *[(name, "factions", key) for name, key in KW_FACTION_DISPLAY[0:3]],
    ("Nod (all)", "parents", "nod"),
    *[(name, "factions", key) for name, key in KW_FACTION_DISPLAY[3:6]],
    ("Scrin (all)", "parents", "scrin"),
    *[(name, "factions", key) for name, key in KW_FACTION_DISPLAY[6:9]],
]


def _stat_list(game_id: int) -> list[tuple[str, str, str, str]]:
    """(career key, label, fold, value type) of every stat the server keeps for the game."""
    if game_id == GAME_ID_RA:
        return [(s.key, s.label, s.fold, s.sake_type) for s in ra3_stats.STATS]
    game = cnc3_stats.GAMES[game_id]
    return [(s.key, s.label, s.fold, s.sake_type) for s in game.stats if s.fold != cnc3_stats.UNREPORTED]


def _faction_list(game_id: int) -> list[tuple[str, str, str]]:
    """(display name, career group, faction key) for the faction table."""
    if game_id == GAME_ID_RA:
        return [(name, "factions", key) for name, key in RA3_FACTION_DISPLAY]
    if game_id == cnc3_stats.KW.game_id:
        return KW_PROFILE_FACTIONS
    return [(name, "factions", key) for name, key in TW_FACTION_DISPLAY]


def stat_value(bucket: dict, key: str, fold: str) -> int | float:
    """One stat of a career bucket. The ratios and the average are worked out from the bucket's totals."""
    if fold != ra3_stats.DERIVED:
        return bucket.get(key, 0)
    if key == "win_loss_ratio":
        return bucket.get("wins", 0) / max(bucket.get("losses", 0), 1)
    if key == "unit_kill_death_ratio":
        return bucket.get("units_killed", 0) / max(bucket.get("units_lost", 0), 1)
    if key == "avg_game_length":
        matches = bucket.get("total_matches", 0)
        return bucket.get("total_time_played", 0) / matches if matches else 0
    raise KeyError(key)


def duration_text(seconds: float) -> str:
    seconds = int(round(seconds))
    hours, rest = divmod(seconds, 3600)
    minutes, secs = divmod(rest, 60)
    if hours:
        return f"{hours}h {minutes:02d}m"
    return f"{minutes}m {secs:02d}s"


def _text(key: str, value_type: str, value: int | float) -> str:
    if key in TIME_STATS:
        return duration_text(value)
    if value_type == "float":
        return f"{value:.2f}"
    return str(int(value))


def _results(bucket: dict) -> dict:
    wins, losses = bucket.get("wins", 0), bucket.get("losses", 0)
    matches = bucket.get("total_matches", wins + losses)
    return {
        "matches": matches,
        "wins": wins,
        "losses": losses,
        "win_percent": round(wins / matches * 100, 1) if matches else 0.0,
        "win_loss_ratio": f"{wins / max(losses, 1):.2f}",
    }


def career_profile(session: Session, persona_id: int, game_id: int) -> dict | None:
    """The profile page data of one game, or None when the player has no career in it."""
    stats = get_player_stats(session, persona_id, game_id=game_id)
    persona = get_persona_by_id(session, persona_id)
    if stats is None or persona is None:
        return None
    level = get_player_level(session, persona_id, game_id=game_id)
    career = stats.stats or {}
    total = career.get(ra3_stats.ALL_ONLINE, {})

    modes = []
    for mode in MODES:
        row = {"key": mode, "label": MODE_LABELS[mode], **_results(career.get(mode, {}))}
        if mode in RATED_MODES:
            row["elo"] = getattr(stats, f"elo_{mode}", 1200)
            row["rated_games"] = getattr(stats, f"games_{mode}", 0)
        modes.append(row)

    stat_rows = [
        {
            "key": key,
            "label": label,
            "values": [_text(key, kind, stat_value(career.get(m, {}), key, fold)) for m in MODES],
        }
        for key, label, fold, kind in _stat_list(game_id)
    ]

    factions = []
    for name, group, key in _faction_list(game_id):
        per_mode = {m: _results(career.get(m, {}).get(group, {}).get(key, {})) for m in MODES}
        factions.append(
            {"name": name, "parent": group == "parents", **per_mode[ra3_stats.ALL_ONLINE], "modes": per_mode}
        )

    return {
        "persona_id": persona.id,
        "name": persona.name,
        "score": level.score if level else 0,
        "rank": level.rank if level else 1,
        "best_elo": max(m["elo"] for m in modes if "elo" in m),
        "total": modes[0],
        "time_played": duration_text(total.get("total_time_played", 0)),
        "avg_game_length": duration_text(stat_value(total, "avg_game_length", ra3_stats.DERIVED)),
        "modes": modes,
        "mode_labels": [MODE_LABELS[m] for m in MODES],
        "stats": stat_rows,
        "factions": factions,
    }
