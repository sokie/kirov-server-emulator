"""
Tiberium Wars and Kane's Wrath career stats: how each stat is folded, its Sake columns and its report key.

Kane's Wrath report keys are 45 higher than Tiberium Wars keys. Kane's Wrath also has nine subfactions under
three parent factions, and an ALLONLINE column for every stat.
"""

from dataclasses import dataclass

from app.models.game_config import GAME_ID_KW, GAME_ID_TW
from app.models.ra3_stats import ALL_ONLINE, COUNT, DERIVED, LONGEST, STREAK, SUM

UNREPORTED = "unreported"  # no report carries this stat, so its column is always 0

# Report game type (gt) -> career mode. The game type is the lobby type - 2. Campaign, skirmish and LAN
# games send no report.
GT_TO_MODE: dict[int, str] = {1: "unranked", 2: "ranked_1v1", 3: "ranked_2v2", 4: "clan_1v1", 5: "clan_2v2"}
MODE_TO_GT: dict[str, int] = {mode: gt for gt, mode in GT_TO_MODE.items()}
MODES: tuple[str, ...] = tuple(GT_TO_MODE.values())
SAKE_MODE: dict[str, str] = {
    "unranked": "UNRANKED",
    "ranked_1v1": "RANKED1V1",
    "ranked_2v2": "RANKED2V2",
    "clan_1v1": "CLAN1V1",
    "clan_2v2": "CLAN2V2",
    ALL_ONLINE: "ALLONLINE",
}

# Game section keys, numbered as in Tiberium Wars. Key 72 + gt is the game type flag.
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
    70: "settings_value_ba8",
    71: "settings_value_bac",
}

# Player keys that are not stats, numbered as in Tiberium Wars.
PLAYER_KEY_DURATION_BASE = 15  # key = 15 + gt, sent only for the local player
PLAYER_KEY_CLAN_VALUE = 72  # sent only for the local player in clan games


@dataclass(frozen=True)
class Cnc3Stat:
    stat_id: int
    key: str  # career JSON key
    sake: str  # PlayerStats column prefix
    fold: str
    per_faction: bool  # the game also keeps a column per faction
    sake_type: str  # "int" or "float"
    report_base: int | None  # player report key = base + key offset + gt
    label: str


_TW_STATS: tuple[Cnc3Stat, ...] = (
    Cnc3Stat(0x00, "current_win_streak", "CurrentWinStreak", STREAK, False, "int", None, "Current win streak"),
    Cnc3Stat(0x01, "current_loss_streak", "CurrentLossStreak", STREAK, False, "int", None, "Current loss streak"),
    Cnc3Stat(0x02, "longest_win_streak", "LongestWinStreak", LONGEST, False, "int", None, "Longest win streak"),
    Cnc3Stat(0x03, "longest_loss_streak", "LongestLossStreak", LONGEST, False, "int", None, "Longest loss streak"),
    Cnc3Stat(0x04, "total_matches", "TotalMatches", COUNT, True, "int", None, "Matches played"),
    Cnc3Stat(0x05, "losses", "CareerLosses", COUNT, True, "int", None, "Losses (any result but a win)"),
    Cnc3Stat(0x06, "wins", "CareerWins", COUNT, True, "int", None, "Wins"),
    Cnc3Stat(0x07, "win_loss_ratio", "WinLossRatio", DERIVED, True, "float", None, "Wins / max(losses, 1)"),
    Cnc3Stat(0x08, "avg_game_length", "AverageGameLength", DERIVED, False, "float", None, "Time played / matches"),
    Cnc3Stat(0x09, "total_time_played", "TotalTimePlayed", SUM, False, "int", None, "Seconds played"),
    Cnc3Stat(0x0A, "structures_built", "CareerStructuresCreated", SUM, False, "int", 20, "Structures built"),
    Cnc3Stat(0x0B, "structures_lost", "CareerStructuresLost", SUM, False, "int", 25, "Structures lost"),
    Cnc3Stat(0x0C, "structures_destroyed", "CareerStructuresDestroyed", SUM, False, "int", 30, "Structures destroyed"),
    Cnc3Stat(0x0D, "structures_captured", "CareerStructuresCaptured", SUM, False, "int", 35, "Structures captured"),
    Cnc3Stat(0x14, "units_built", "CareerUnitsCreated", SUM, False, "int", 40, "Units built"),
    Cnc3Stat(0x15, "units_lost", "CareerUnitsLost", SUM, False, "int", 45, "Units lost"),
    Cnc3Stat(0x16, "units_killed", "CareerUnitsKilled", SUM, False, "int", 50, "Units killed"),
    Cnc3Stat(
        0x17, "unit_kill_death_ratio", "UnitKillDeathRatio", DERIVED, False, "float", None, "Kills / max(lost, 1)"
    ),
    Cnc3Stat(0x1F, "disconnects", "Disconnects", COUNT, False, "int", None, "Matches ended by a lost connection"),
    Cnc3Stat(0x20, "desyncs", "Desyncs", COUNT, False, "int", None, "Matches that desynced"),
)

_KW_STATS: tuple[Cnc3Stat, ...] = (
    *_TW_STATS[:-2],
    Cnc3Stat(0x21, "input_commands", "CareerInputCommands", UNREPORTED, False, "int", None, "Input commands"),
    Cnc3Stat(
        0x22,
        "avg_input_commands",
        "AverageCareerInputCommands",
        UNREPORTED,
        False,
        "float",
        None,
        "Input commands per match",
    ),
    *_TW_STATS[-2:],
)

# Stats the client keeps only in its own career files.
LOCAL_ONLY_STATS: dict[int, str] = {
    0x0E: "structures captured by the enemy",
    0x0F: "structures captured / max(structures captured by the enemy, 1)",
    0x10: "superweapons built",
    0x11: "superweapons fired",
    0x12: "bridges destroyed",
    0x13: "structures sold",
    0x18: "resources gathered per minute",
    0x19: "times power was lost",
    0x1A: "resources gathered",
    0x1B: "resources spent",
    0x1C: "times the formation preview was used",
    0x1D: "campaign missions played (campaign container only)",
    0x1E: "votes skipped",
}


@dataclass(frozen=True)
class Cnc3Game:
    game_id: int
    name: str
    sake_table: str
    key_offset: int  # added to every Tiberium Wars report key
    side_to_faction: dict[int, str]  # report side -> career faction key
    sake_faction: dict[str, str]  # career faction key -> Sake column part
    faction_parent: dict[str, str]  # subfaction -> parent faction key
    sake_parent: dict[str, str]  # parent faction key -> Sake column part
    all_online: bool  # the game has ALLONLINE columns, read from the all_online bucket
    stats: tuple[Cnc3Stat, ...]

    @property
    def modes(self) -> tuple[str, ...]:
        return (*MODES, ALL_ONLINE) if self.all_online else MODES

    @property
    def report_stats(self) -> tuple[Cnc3Stat, ...]:
        return tuple(s for s in self.stats if s.report_base is not None)


TW = Cnc3Game(
    game_id=GAME_ID_TW,
    name="tw",
    sake_table="PlayerStats_v5",
    key_offset=0,
    side_to_faction={0: "gdi", 1: "nod", 2: "scrin"},
    sake_faction={"gdi": "GDI", "nod": "NOD", "scrin": "ALIEN"},
    faction_parent={},
    sake_parent={},
    all_online=False,
    stats=_TW_STATS,
)

KW = Cnc3Game(
    game_id=GAME_ID_KW,
    name="kw",
    sake_table="PlayerStats_v100",
    key_offset=45,
    side_to_faction={
        1: "gdi",
        2: "zocom",
        3: "steel_talons",
        5: "nod",
        6: "black_hand",
        7: "marked_of_kane",
        9: "scrin",
        10: "reaper_17",
        11: "traveler_59",
    },
    sake_faction={
        "gdi": "GDI_GDI",
        "zocom": "GDI_ZOCOM",
        "steel_talons": "GDI_TALONS",
        "nod": "NOD_NOD",
        "black_hand": "NOD_BLACKHAND",
        "marked_of_kane": "NOD_MARKED",
        "scrin": "ALIEN_SCRIN",
        "reaper_17": "ALIEN_REAPER",
        "traveler_59": "ALIEN_TRAVELER",
    },
    faction_parent={
        "gdi": "gdi",
        "zocom": "gdi",
        "steel_talons": "gdi",
        "nod": "nod",
        "black_hand": "nod",
        "marked_of_kane": "nod",
        "scrin": "scrin",
        "reaper_17": "scrin",
        "traveler_59": "scrin",
    },
    sake_parent={"gdi": "GDI", "nod": "NOD", "scrin": "ALIEN"},
    all_online=True,
    stats=_KW_STATS,
)

GAMES: dict[int, Cnc3Game] = {TW.game_id: TW, KW.game_id: KW}
BY_NAME: dict[str, Cnc3Game] = {TW.name: TW, KW.name: KW}


@dataclass(frozen=True)
class SakeColumn:
    name: str
    stat: Cnc3Stat
    mode: str
    group: str  # "" for the whole mode, "factions" or "parents"
    faction: str | None


def _sake_columns(game: Cnc3Game) -> dict[str, SakeColumn]:
    columns: dict[str, SakeColumn] = {}
    for stat in game.stats:
        for mode in game.modes:
            name = f"{stat.sake}_{SAKE_MODE[mode]}"
            columns[name] = SakeColumn(name, stat, mode, "", None)
        if not stat.per_faction:
            continue
        groups = (("parents", game.sake_parent), ("factions", game.sake_faction))
        for group, parts in groups:
            for faction, part in parts.items():
                for mode in game.modes:
                    name = f"{stat.sake}_{part}_{SAKE_MODE[mode]}"
                    columns[name] = SakeColumn(name, stat, mode, group, faction)
    return columns


SAKE_COLUMNS: dict[int, dict[str, SakeColumn]] = {game.game_id: _sake_columns(game) for game in GAMES.values()}
SAKE_COLUMNS_LOWER: dict[int, dict[str, SakeColumn]] = {
    game_id: {name.lower(): column for name, column in columns.items()} for game_id, columns in SAKE_COLUMNS.items()
}


def side_from_key(game: Cnc3Game, key: int) -> tuple[int, int] | None:
    """Returns (side, game type) of a player side key, or None for any other key. A side key is side * 5 + gt."""
    top = max(game.side_to_faction) * 5 + 5
    if 1 <= key <= top:
        return (key - 1) // 5, (key - 1) % 5 + 1
    return None


def player_key_name(game: Cnc3Game, key: int, gt: int) -> str:
    """Returns the name of a player section key."""
    side_gt = side_from_key(game, key)
    if side_gt is not None:
        side, side_mode = side_gt
        return f"side.{game.side_to_faction.get(side, side)}.{GT_TO_MODE.get(side_mode, '?')}"
    base = key - game.key_offset
    if base == PLAYER_KEY_CLAN_VALUE:
        return "clan_value"
    if base - gt == PLAYER_KEY_DURATION_BASE:
        return "duration_seconds"
    for stat in game.report_stats:
        if stat.report_base == base - gt:
            return stat.key
    return f"unknown_{key}"


def game_key_name(game: Cnc3Game, key: int) -> str:
    """Returns the name of a game section key."""
    base = key - game.key_offset
    gt = base - GAME_KEY_MODE_BASE
    if gt in GT_TO_MODE:
        return f"mode.{GT_TO_MODE[gt]}"
    return GAME_KEYS.get(base, f"unknown_{key}")
