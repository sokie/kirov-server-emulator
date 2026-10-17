"""
Red Alert 3 stat catalogue: every career stat with its fold rule, PlayerStats_v5 columns and report key.
"""

from dataclasses import dataclass

from app.models.game_config import SAGE_SCORING_MULTIPLIERS

# Report mode index (gt) = lobby type - 2. Campaign, skirmish and LAN send no report.
GT_TO_MODE: dict[int, str] = {1: "unranked", 2: "ranked_1v1", 3: "ranked_2v2", 4: "clan_1v1", 5: "clan_2v2"}
MODE_TO_GT: dict[str, int] = {mode: gt for gt, mode in GT_TO_MODE.items()}
MODES: tuple[str, ...] = tuple(GT_TO_MODE.values())
ALL_ONLINE = "all_online"  # every match together, whatever its mode
SAKE_MODE: dict[str, str] = {
    "unranked": "UNRANKED",
    "ranked_1v1": "RANKED1V1",
    "ranked_2v2": "RANKED2V2",
    "clan_1v1": "CLAN1V1",
    "clan_2v2": "CLAN2V2",
}

# Report side -> career faction key.
SIDE_TO_FACTION: dict[int, str] = {0: "allied", 1: "soviet", 2: "japan"}
FACTIONS: tuple[str, ...] = tuple(SIDE_TO_FACTION.values())
SAKE_FACTION: dict[str, str] = {"allied": "ALLIED", "soviet": "SOVIET", "japan": "JAPAN"}

# SC roster results the game sends. 2 (draw) is never sent.
RESULT_WIN = 0
RESULT_LOSS = 1
RESULT_DISCONNECT = 3
RESULT_DESYNC = 4

# Score added per match. Every mode except unranked is ranked.
SCORING_MULTIPLIERS: dict[str, int] = dict(
    zip(("UnrankedLosses", "UnrankedWins", "RankedLosses", "RankedWins"), SAGE_SCORING_MULTIPLIERS)
)

# Fold rules.
SUM = "sum"  # add the match value
COUNT = "count"  # add 1 when the match result says so
STREAK = "streak"  # current streak: +1 or reset to 0
LONGEST = "longest"  # best streak so far
DERIVED = "derived"  # computed from other stats when read

# Game keys. 72 + gt is the mode flag.
GAME_KEY_MODE_BASE = 72
GAME_KEYS: dict[int, str] = {
    61: "map_name",
    62: "duration_seconds",
    63: "game_version",
    64: "official_map",
    65: "has_match_id",
    66: "map_display_name",
    67: "match_id",
    68: "match_name",
    69: "commentator_profile_id",
    70: "settings_value_84",
    71: "settings_value_88",
}

# Player keys outside the per-stat bases.
PLAYER_KEY_DURATION_BASE = 15  # + gt, local player only
PLAYER_KEY_CLAN_VALUE = 72  # local player only, clan modes only


@dataclass(frozen=True)
class Ra3Stat:
    stat_id: int
    key: str  # career JSON key
    sake: str | None  # PlayerStats_v5 column prefix, None when the game does not read it
    fold: str
    per_faction: bool  # the game also keeps an Allied/Soviet/Japan column
    sake_type: str  # "int" or "float"
    report_base: int | None  # player report key = base + gt
    label: str


STATS: tuple[Ra3Stat, ...] = (
    Ra3Stat(0x00, "current_win_streak", "CurrentWinStreak", STREAK, False, "int", None, "Current win streak"),
    Ra3Stat(0x01, "current_loss_streak", "CurrentLossStreak", STREAK, False, "int", None, "Current loss streak"),
    Ra3Stat(0x02, "longest_win_streak", "LongestWinStreak", LONGEST, False, "int", None, "Longest win streak"),
    Ra3Stat(0x03, "longest_loss_streak", "LongestLossStreak", LONGEST, False, "int", None, "Longest loss streak"),
    Ra3Stat(0x04, "total_matches", "TotalMatches", COUNT, True, "int", None, "Matches played"),
    Ra3Stat(0x05, "losses", "CareerLosses", COUNT, True, "int", None, "Losses (any result but a win)"),
    Ra3Stat(0x06, "wins", "CareerWins", COUNT, True, "int", None, "Wins"),
    Ra3Stat(0x07, "win_loss_ratio", "WinLossRatio", DERIVED, True, "float", None, "Wins / max(losses, 1)"),
    Ra3Stat(0x08, "avg_game_length", "AverageGameLength", DERIVED, False, "int", None, "Time played / matches"),
    Ra3Stat(0x09, "total_time_played", "TotalTimePlayed", SUM, False, "int", None, "Seconds played"),
    Ra3Stat(0x0A, "structures_built", "CareerStructuresCreated", SUM, False, "int", 20, "Structures built"),
    Ra3Stat(0x0B, "structures_lost", "CareerStructuresLost", SUM, False, "int", 25, "Structures lost"),
    Ra3Stat(0x0C, "structures_destroyed", "CareerStructuresDestroyed", SUM, False, "int", 30, "Structures destroyed"),
    Ra3Stat(0x0D, "structures_captured", "CareerStructuresCaptured", SUM, False, "int", 35, "Structures captured"),
    Ra3Stat(0x13, "units_built", "CareerUnitsCreated", SUM, False, "int", 40, "Units built"),
    Ra3Stat(0x14, "units_lost", "CareerUnitsLost", SUM, False, "int", 45, "Units lost"),
    Ra3Stat(0x15, "units_killed", "CareerUnitsKilled", SUM, False, "int", 50, "Units killed"),
    Ra3Stat(0x16, "unit_kill_death_ratio", "UnitKillDeathRatio", DERIVED, False, "float", None, "Kills / max(lost, 1)"),
    Ra3Stat(0x18, "timed_state_seconds", None, SUM, False, "int", 55, "Seconds of a timed score keeper state"),
    Ra3Stat(0x1D, "units_lost_value", "CareerUnitsLostValue", SUM, False, "int", 77, "Value of units lost"),
    Ra3Stat(0x1E, "units_killed_value", "CareerUnitsKilledValue", SUM, False, "int", 82, "Value of units killed"),
    Ra3Stat(
        0x1F,
        "units_killed_allied",
        "CareerNumberUnitsKilledAllied",
        SUM,
        False,
        "int",
        87,
        "Units lost to friendly fire",
    ),
    Ra3Stat(0x20, "units_activated", "CareerNumActivatedUnits", SUM, False, "int", 92, "Special abilities used"),
    Ra3Stat(0x21, "powers_activated", "CareerNumActivatedPowers", SUM, False, "int", 97, "Powers activated"),
    Ra3Stat(
        0x22,
        "structures_infiltrated",
        "CareerNumStructuresInfiltrated",
        SUM,
        False,
        "int",
        102,
        "Structures infiltrated",
    ),
    Ra3Stat(0x24, "disconnects", "Disconnects", COUNT, False, "int", None, "Matches left before the end"),
    Ra3Stat(0x25, "desyncs", "Desyncs", COUNT, False, "int", None, "Matches that desynced"),
)

BY_KEY: dict[str, Ra3Stat] = {s.key: s for s in STATS}
BY_REPORT_BASE: dict[int, Ra3Stat] = {s.report_base: s for s in STATS if s.report_base is not None}
REPORT_STATS: tuple[Ra3Stat, ...] = tuple(s for s in STATS if s.report_base is not None)

# Stats the client keeps only in its own career files.
LOCAL_ONLY_STATS: dict[int, str] = {
    0x0E: "count from score keeper list +0x4F4",
    0x0F: "stat 0x0D / max(stat 0x0E, 1)",
    0x10: "score keeper +0xE4",
    0x11: "score keeper +0xE0",
    0x12: "count from score keeper list (FUN_00868D80)",
    0x17: "stat 0x19 per minute played",
    0x19: "score keeper +0x04",
    0x1A: "score keeper +0x08",
    0x1B: "score keeper +0x100",
    0x1C: "score keeper +0x140 (float)",
    0x23: "games without a game-info object (campaign container only)",
}


@dataclass(frozen=True)
class SakeColumn:
    name: str
    stat: Ra3Stat
    mode: str
    faction: str | None


def _sake_columns() -> dict[str, SakeColumn]:
    columns: dict[str, SakeColumn] = {}
    for stat in STATS:
        if stat.sake is None:
            continue
        for mode in MODES:
            name = f"{stat.sake}_{SAKE_MODE[mode]}"
            columns[name] = SakeColumn(name, stat, mode, None)
        if stat.per_faction:
            for faction in FACTIONS:
                for mode in MODES:
                    name = f"{stat.sake}_{SAKE_FACTION[faction]}_{SAKE_MODE[mode]}"
                    columns[name] = SakeColumn(name, stat, mode, faction)
    return columns


SAKE_COLUMNS: dict[str, SakeColumn] = _sake_columns()
SAKE_COLUMNS_LOWER: dict[str, SakeColumn] = {name.lower(): col for name, col in SAKE_COLUMNS.items()}


def player_key_name(key: int, gt: int) -> str:
    """Names a player-section key of a report whose mode index is gt."""
    if 1 <= key <= 15:
        side = (key - 1) // 5
        return f"side.{SIDE_TO_FACTION.get(side, side)}.{GT_TO_MODE.get((key - 1) % 5 + 1, '?')}"
    if key == PLAYER_KEY_CLAN_VALUE:
        return "clan_value"
    base = key - gt
    if base == PLAYER_KEY_DURATION_BASE:
        return "duration_seconds"
    stat = BY_REPORT_BASE.get(base)
    if stat is not None:
        return stat.key
    return f"unknown_{key}"


def game_key_name(key: int) -> str:
    gt = key - GAME_KEY_MODE_BASE
    if gt in GT_TO_MODE:
        return f"mode.{GT_TO_MODE[gt]}"
    return GAME_KEYS.get(key, f"unknown_{key}")


def side_from_key(key: int) -> tuple[int, int] | None:
    """(side, gt) for a side key: side * 5 + gt, with gt 1..5."""
    if 1 <= key <= 15:
        return (key - 1) // 5, (key - 1) % 5 + 1
    return None


def score_delta(mode: str, won: bool) -> int:
    ranked = mode != "unranked"
    column = ("Ranked" if ranked else "Unranked") + ("Wins" if won else "Losses")
    return SCORING_MULTIPLIERS[column]
