"""
Utility functions for Generals/Zero Hour stats processing.

Handles the backslash-delimited key-value format used by the game's
persistent storage protocol, rank calculation, and battle honors evaluation.
"""

from app.util.logging_helper import get_logger

logger = get_logger(__name__)

# Rank thresholds: points needed for each rank level (0-9)
# Private(0), Corporal(1), Sergeant(2), Lieutenant(3), Captain(4),
# Major(5), Colonel(6), Brigadier General(7), General(8), Commander in Chief(9)
DEFAULT_RANK_THRESHOLDS = [0, 50, 150, 350, 700, 1200, 2000, 3500, 6000, 10000]

DEFAULT_WIN_MULTIPLIER = 3.0
DEFAULT_LOSS_MULTIPLIER = 0.0
DEFAULT_HOUR_MULTIPLIER = 1.0
DEFAULT_DISCONNECT_MULTIPLIER = -1.0

# General indices (0=Random, 1=Observer, 2-13 are the 12 playable sides)
# Evidence: side=GLAStealthGeneral → stat key losses13
USA_GENERAL_INDICES = {2, 5, 6, 7}  # USA, SuperWeapon, Laser, AirForce
CHINA_GENERAL_INDICES = {3, 8, 9, 10}  # China, Tank, Infantry, Nuke
GLA_GENERAL_INDICES = {4, 11, 12, 13}  # GLA, Toxin, Demo, Stealth

# All general indices (0-13)
ALL_GENERAL_INDICES = set(range(14))

# Side name to general index mapping
SIDE_TO_INDEX: dict[str, int] = {
    "USA": 2,
    "China": 3,
    "GLA": 4,
    "AmericaSuperWeaponGeneral": 5,
    "AmericaLaserGeneral": 6,
    "AmericaAirForceGeneral": 7,
    "ChinaTankGeneral": 8,
    "ChinaInfantryGeneral": 9,
    "ChinaNukeGeneral": 10,
    "GLAToxinGeneral": 11,
    "GLADemolitionGeneral": 12,
    "GLAStealthGeneral": 13,
}

# Battle honor bitmask values (from GeneralsMD/BattleHonors.h)
HONOR_STREAK = 0x000002
HONOR_BATTLE_TANK = 0x000080  # 50+ vehicles built (per-game, set by client)
HONOR_AIR_WING = 0x000100  # 20+ aircraft built (per-game, set by client)
HONOR_LOYALTY_USA = 0x000020
HONOR_LOYALTY_CHINA = 0x000040
HONOR_LOYALTY_GLA = 0x000200
HONOR_ENDURANCE = 0x000400
HONOR_BLITZ5 = 0x004000  # Won in <5 min (per-game, set by client)
HONOR_BLITZ10 = 0x008000  # Won in <10 min (per-game, set by client)
HONOR_FAIR_PLAY = 0x010000
HONOR_APOCALYPSE = 0x020000
HONOR_OFFICERSCLUB = 0x040000
HONOR_DOMINATION = 0x080000
HONOR_CHALLENGE_MODE = 0x100000
HONOR_ULTIMATE = 0x200000
HONOR_GLOBAL_GENERAL = 0x400000
HONOR_DOMINATION_ONLINE = 0x800000
HONOR_STREAK_ONLINE = 0x1000000


def parse_generals_kv(data: str) -> dict[str, str]:
    r"""
    Parse a Generals \key\value\ string into a dictionary.

    Example: "wins0\5\losses0\3" -> {"wins0": "5", "losses0": "3"}
    Handles leading/trailing backslashes gracefully.
    """
    if not data:
        return {}

    # Strip leading/trailing backslashes
    stripped = data.strip("\\")
    if not stripped:
        return {}

    parts = stripped.split("\\")
    result = {}
    i = 0
    while i < len(parts) - 1:
        key = parts[i]
        value = parts[i + 1]
        if key:
            result[key] = value
        i += 2

    return result


def format_generals_kv(stats: dict[str, str]) -> str:
    r"""
    Convert a dictionary to Generals \key\value\ format string.

    Example: {"wins0": "5", "losses0": "3"} -> "\\wins0\\5\\losses0\\3\\"
    """
    if not stats:
        return ""

    parts = []
    for key, value in stats.items():
        parts.append(f"\\{key}\\{value}")
    return "".join(parts) + "\\"


def merge_generals_kv(existing: str, incoming: str) -> str:
    r"""
    Merge incoming KV data into existing KV data.
    Incoming values overwrite existing keys; new keys are added.

    Returns the merged KV string.
    """
    existing_dict = parse_generals_kv(existing)
    incoming_dict = parse_generals_kv(incoming)
    existing_dict.update(incoming_dict)
    return format_generals_kv(existing_dict)


def _get_int(stats: dict[str, str], key: str, default: int = 0) -> int:
    """Safely get an integer value from the stats dict."""
    try:
        return int(stats.get(key, str(default)))
    except (ValueError, TypeError):
        return default


def _get_total_wins(stats: dict[str, str]) -> int:
    """Sum all wins across all generals (indices 0-13)."""
    return sum(_get_int(stats, f"wins{i}") for i in range(14))


def _get_total_losses(stats: dict[str, str]) -> int:
    """Sum all losses across all generals (indices 0-13)."""
    return sum(_get_int(stats, f"losses{i}") for i in range(14))


def _get_total_games_for_indices(stats: dict[str, str], indices: set[int]) -> int:
    """Get total games (wins + losses) for a set of general indices."""
    total = 0
    for i in indices:
        total += _get_int(stats, f"wins{i}")
        total += _get_int(stats, f"losses{i}")
    return total


def _get_total_games(stats: dict[str, str]) -> int:
    """Get total games across all generals."""
    return _get_total_games_for_indices(stats, ALL_GENERAL_INDICES)


def _get_total_duration_hours(stats: dict[str, str]) -> float:
    """Sum duration{N} across all general indices (0-13), convert minutes → hours."""
    minutes = sum(_get_int(stats, f"duration{i}") for i in range(14))
    return minutes / 60.0


def _get_total_disconnects(stats: dict[str, str]) -> int:
    """Sum discons{N} for N in 0..14 (game tracks 15 slots)."""
    return sum(_get_int(stats, f"discons{i}") for i in range(15))


def _get_total_desyncs(stats: dict[str, str]) -> int:
    """Sum desyncs{N} across all general indices (0-13)."""
    return sum(_get_int(stats, f"desyncs{i}") for i in range(14))


def calculate_rank(
    stats: dict[str, str],
    thresholds: list[int] | None = None,
    win_mul: float = DEFAULT_WIN_MULTIPLIER,
    loss_mul: float = DEFAULT_LOSS_MULTIPLIER,
    hour_mul: float = DEFAULT_HOUR_MULTIPLIER,
    dc_mul: float = DEFAULT_DISCONNECT_MULTIPLIER,
) -> int:
    """
    Calculate rank (0-9) from player stats.

    Formula: points = wins*winMul + losses*lossMul + hours*hourMul + (discons+desyncs)*dcMul
    Then map to thresholds.

    Returns rank level 0-9.
    """
    if thresholds is None:
        thresholds = DEFAULT_RANK_THRESHOLDS

    total_wins = _get_total_wins(stats)
    total_losses = _get_total_losses(stats)
    hours = _get_total_duration_hours(stats)
    disconnects = _get_total_disconnects(stats)
    desyncs = _get_total_desyncs(stats)

    points = total_wins * win_mul + total_losses * loss_mul + hours * hour_mul + (disconnects + desyncs) * dc_mul

    # Find highest rank where points meet threshold
    rank = 0
    for i, threshold in enumerate(thresholds):
        if points >= threshold:
            rank = i
        else:
            break

    return rank


def evaluate_battle_honors(stats: dict[str, str], rank: int | None = None) -> int:
    """
    Evaluate which battle honors a player has earned.

    Returns a 32-bit bitmask of earned honors.
    """
    honors = 0

    if rank is None:
        rank = calculate_rank(stats)

    total_wins = _get_total_wins(stats)
    total_losses = _get_total_losses(stats)
    total_games = total_wins + total_losses
    disconnects = _get_total_disconnects(stats)

    # STREAK: WinRowMax >= 5
    win_row_max = _get_int(stats, "WinRowMax")
    if win_row_max >= 5:
        honors |= HONOR_STREAK

    # STREAK_ONLINE: WinRowMax >= 3
    if win_row_max >= 3:
        honors |= HONOR_STREAK_ONLINE

    # LOYALTY checks: genInRow >= 20 consecutive games with the same faction general
    gen_in_row = _get_int(stats, "genInRow")
    last_gen = _get_int(stats, "lastGeneral")
    if gen_in_row >= 20:
        if last_gen in USA_GENERAL_INDICES:
            honors |= HONOR_LOYALTY_USA
        elif last_gen in CHINA_GENERAL_INDICES:
            honors |= HONOR_LOYALTY_CHINA
        elif last_gen in GLA_GENERAL_INDICES:
            honors |= HONOR_LOYALTY_GLA

    # FAIR_PLAY: disconnect ratio < 5%
    if total_games > 0:
        dc_ratio = disconnects / total_games
        if dc_ratio < 0.05:
            honors |= HONOR_FAIR_PLAY
    else:
        # No games played, fair play by default
        honors |= HONOR_FAIR_PLAY

    # APOCALYPSE: builtNuke > 0 AND builtSCUD > 0 AND builtCannon > 0
    built_nuke = _get_int(stats, "builtNuke")
    built_scud = _get_int(stats, "builtSCUD")
    built_cannon = _get_int(stats, "builtCannon")
    if built_nuke > 0 and built_scud > 0 and built_cannon > 0:
        honors |= HONOR_APOCALYPSE

    # OFFICERSCLUB: rank >= Colonel (6)
    if rank >= 6:
        honors |= HONOR_OFFICERSCLUB

    # DOMINATION: overall win ratio > 75% with 20+ games
    if total_games >= 20 and total_wins > total_games * 0.75:
        honors |= HONOR_DOMINATION

    # DOMINATION_ONLINE: same threshold as DOMINATION
    if total_games >= 20 and total_wins > total_games * 0.75:
        honors |= HONOR_DOMINATION_ONLINE

    # CHALLENGE_MODE: all challenge medals earned
    challenge_medals = _get_int(stats, "chlgMedals")
    if challenge_medals > 0:
        honors |= HONOR_CHALLENGE_MODE

    # GLOBAL_GENERAL: played with all 12 playable generals (indices 2-13)
    played_all = all(_get_int(stats, f"wins{i}") + _get_int(stats, f"losses{i}") > 0 for i in range(2, 14))
    if played_all:
        honors |= HONOR_GLOBAL_GENERAL

    # ENDURANCE: total play time >= 100 hours
    total_hours = _get_total_duration_hours(stats)
    if total_hours >= 100:
        honors |= HONOR_ENDURANCE

    # ULTIMATE: all server-computable honors earned
    required_for_ultimate = (
        HONOR_STREAK
        | HONOR_FAIR_PLAY
        | HONOR_APOCALYPSE
        | HONOR_OFFICERSCLUB
        | HONOR_DOMINATION
        | HONOR_GLOBAL_GENERAL
        | HONOR_ENDURANCE
        | HONOR_STREAK_ONLINE
        | HONOR_DOMINATION_ONLINE
    )
    if (honors & required_for_ultimate) == required_for_ultimate:
        honors |= HONOR_ULTIMATE

    return honors
