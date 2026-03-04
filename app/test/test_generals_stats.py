"""
Tests for app/util/generals_stats.py — Generals/Zero Hour stats processing.

Covers:
- KV parsing, formatting, and merging (including null-byte edge case from live data)
- General index sets and SIDE_TO_INDEX mapping
- Per-field aggregate helpers
- Rank calculation with correct multipliers/formula
- Each battle honor condition
- Full snapshots matching live database records from a real game session
"""

import pytest

from app.util.generals_stats import (
    ALL_GENERAL_INDICES,
    CHINA_GENERAL_INDICES,
    DEFAULT_DISCONNECT_MULTIPLIER,
    DEFAULT_LOSS_MULTIPLIER,
    DEFAULT_WIN_MULTIPLIER,
    GLA_GENERAL_INDICES,
    HONOR_AIR_WING,
    HONOR_APOCALYPSE,
    HONOR_BATTLE_TANK,
    HONOR_BLITZ5,
    HONOR_BLITZ10,
    HONOR_CHALLENGE_MODE,
    HONOR_DOMINATION,
    HONOR_DOMINATION_ONLINE,
    HONOR_ENDURANCE,
    HONOR_FAIR_PLAY,
    HONOR_GLOBAL_GENERAL,
    HONOR_LOYALTY_CHINA,
    HONOR_LOYALTY_GLA,
    HONOR_LOYALTY_USA,
    HONOR_OFFICERSCLUB,
    HONOR_STREAK,
    HONOR_STREAK_ONLINE,
    HONOR_ULTIMATE,
    PER_GAME_HONOR_MASK,
    SIDE_TO_INDEX,
    USA_GENERAL_INDICES,
    _get_int,
    _get_total_desyncs,
    _get_total_disconnects,
    _get_total_duration_hours,
    _get_total_games,
    _get_total_losses,
    _get_total_wins,
    calculate_rank,
    evaluate_battle_honors,
    extract_client_per_game_honors,
    format_generals_kv,
    merge_generals_kv,
    parse_generals_kv,
)

# =============================================================================
# Live DB fixtures — taken directly from the database after a real 2-player game
#
# Game: Generals Zero Hour, 2 human players, no AI
# Player 1 (persona_id=1): Won as ChinaTankGeneral (index 8)
#   Previously lost one game as GLAStealthGeneral (index 13)
# Player 3 (persona_id=3): Lost as AmericaLaserGeneral (index 6)
#   Previously won one game as AmericaLaserGeneral (index 6)
#
# The game's setpd payload ends with a C-string null byte (\x00).
# Python reads past this correctly; sqlite3 shell truncates display there.
# The null byte lands inside the value of the last key before the game-stats
# block, making DSRow's stored value "0\x00" — _get_int safely returns 0.
# =============================================================================

# Full raw_data for persona_id=1 as read by Python (null byte preserved)
_BEFORE_NULL_P1 = (
    r"\discons0\0\discons1\0\discons2\0\discons3\0\discons4\0"
    r"\discons5\0\discons6\0\discons7\0\discons8\0\discons9\0"
    r"\discons10\0\discons11\0\discons12\0\discons13\0\discons14\0"
    r"\lastGeneral\8\genInRow\1\builtCannon\0\builtNuke\0\builtSCUD\0"
    r"\WinRow\1\LossRow\0\DCRow\0\DSRow\0"
)
_AFTER_NULL_P1 = (
    r"\losses13\1\games13\1\duration13\2\unitsBuilt13\1\buildingsBuilt13\1"
    r"\gamesOf2p13\1\customGames13\1\random\1\systemSpec\LOD2\fps\1394.26"
    r"\LossRowMax\1\wins8\1\games8\1\duration8\3\unitsKilled8\1"
    r"\unitsBuilt8\11\buildingsKilled8\1\buildingsBuilt8\3"
    r"\gamesOf2p8\1\customGames8\1\battle\49152\WinRowMax\1\ "
)
# Trim the trailing space added for raw-string compatibility, add null+remainder
LIVE_RAW_P1 = _BEFORE_NULL_P1 + "\x00" + _AFTER_NULL_P1.rstrip()

# Full raw_data for persona_id=3 as read by Python (null byte preserved)
_BEFORE_NULL_P3 = (
    r"\discons0\0\discons1\0\discons2\0\discons3\0\discons4\0"
    r"\discons5\0\discons6\0\discons7\0\discons8\0\discons9\0"
    r"\discons10\0\discons11\0\discons12\0\discons13\0\discons14\0"
    r"\lastGeneral\6\genInRow\2\builtCannon\0\builtNuke\0\builtSCUD\0"
    r"\WinRow\0\LossRow\1\DCRow\0\DSRow\0"
)
_AFTER_NULL_P3 = (
    r"\wins6\1\games6\1\duration6\3\unitsBuilt6\1\buildingsBuilt6\1"
    r"\gamesOf2p6\1\customGames6\1\random\1\systemSpec\LOD2\fps\1216.1"
    r"\battle\49152\WinRowMax\1\losses6\1\unitsLost6\1\buildingsLost6\1"
    r"\LossRowMax\1\ "
)
LIVE_RAW_P3 = _BEFORE_NULL_P3 + "\x00" + _AFTER_NULL_P3.rstrip()


# =============================================================================
# Constants
# =============================================================================


class TestConstants:
    def test_default_loss_multiplier_is_zero(self):
        assert DEFAULT_LOSS_MULTIPLIER == 0.0

    def test_default_disconnect_multiplier_is_minus_one(self):
        assert DEFAULT_DISCONNECT_MULTIPLIER == -1.0

    def test_default_win_multiplier(self):
        assert DEFAULT_WIN_MULTIPLIER == 3.0

    def test_honor_fair_play_value(self):
        assert HONOR_FAIR_PLAY == 0x10000

    def test_honor_streak_value(self):
        assert HONOR_STREAK == 0x02

    def test_honor_streak_online_value(self):
        assert HONOR_STREAK_ONLINE == 0x1000000

    def test_honor_domination_online_value(self):
        assert HONOR_DOMINATION_ONLINE == 0x800000


# =============================================================================
# General index sets
# =============================================================================


class TestGeneralIndexSets:
    def test_usa_indices(self):
        assert USA_GENERAL_INDICES == {2, 5, 6, 7}

    def test_china_indices(self):
        assert CHINA_GENERAL_INDICES == {3, 8, 9, 10}

    def test_gla_indices(self):
        assert GLA_GENERAL_INDICES == {4, 11, 12, 13}

    def test_all_indices_range(self):
        assert ALL_GENERAL_INDICES == set(range(14))

    def test_factions_are_disjoint(self):
        assert USA_GENERAL_INDICES.isdisjoint(CHINA_GENERAL_INDICES)
        assert USA_GENERAL_INDICES.isdisjoint(GLA_GENERAL_INDICES)
        assert CHINA_GENERAL_INDICES.isdisjoint(GLA_GENERAL_INDICES)

    def test_playable_indices_covered(self):
        # Indices 2-13 are the 12 playable sides
        playable = set(range(2, 14))
        covered = USA_GENERAL_INDICES | CHINA_GENERAL_INDICES | GLA_GENERAL_INDICES
        assert covered == playable

    # Spot-check: log evidence maps GLAStealthGeneral → losses13
    def test_gla_stealth_general_is_index_13(self):
        assert 13 in GLA_GENERAL_INDICES
        assert SIDE_TO_INDEX["GLAStealthGeneral"] == 13

    def test_china_tank_general_is_index_8(self):
        assert 8 in CHINA_GENERAL_INDICES
        assert SIDE_TO_INDEX["ChinaTankGeneral"] == 8

    def test_america_laser_general_is_index_6(self):
        assert 6 in USA_GENERAL_INDICES
        assert SIDE_TO_INDEX["AmericaLaserGeneral"] == 6


class TestSideToIndex:
    EXPECTED = {
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

    def test_all_12_sides_present(self):
        assert len(SIDE_TO_INDEX) == 12

    def test_all_indices_correct(self):
        for side, expected_idx in self.EXPECTED.items():
            assert SIDE_TO_INDEX[side] == expected_idx, f"{side} should map to {expected_idx}"

    def test_indices_span_2_to_13(self):
        assert set(SIDE_TO_INDEX.values()) == set(range(2, 14))


# =============================================================================
# KV parsing
# =============================================================================


class TestParseGeneralsKv:
    def test_basic_parsing(self):
        result = parse_generals_kv(r"\wins0\5\losses0\3")
        assert result == {"wins0": "5", "losses0": "3"}

    def test_leading_trailing_backslashes(self):
        result = parse_generals_kv("\\wins0\\5\\")
        assert result["wins0"] == "5"

    def test_empty_string_returns_empty(self):
        assert parse_generals_kv("") == {}

    def test_only_backslashes_returns_empty(self):
        assert parse_generals_kv("\\\\") == {}

    def test_multiple_keys(self):
        result = parse_generals_kv(r"\wins0\1\losses0\2\duration0\10")
        assert result["wins0"] == "1"
        assert result["losses0"] == "2"
        assert result["duration0"] == "10"

    def test_null_byte_in_data_parses_subsequent_keys(self):
        # Game payload ends with \x00 (C string null terminator).
        # The null byte lands in the value of the last key before it,
        # but all keys after the null byte must still be parsed.
        data = r"\DCRow\0\DSRow\0" + "\x00" + r"\wins6\1\losses6\1"
        result = parse_generals_kv(data)
        # Keys after the null byte are accessible
        assert result["wins6"] == "1"
        assert result["losses6"] == "1"
        # The null byte contaminates DSRow's value (safe: _get_int returns 0)
        assert "\x00" in result["DSRow"]

    def test_live_data_p1_parses_wins8(self):
        result = parse_generals_kv(LIVE_RAW_P1)
        assert result["wins8"] == "1"

    def test_live_data_p1_parses_losses13(self):
        result = parse_generals_kv(LIVE_RAW_P1)
        assert result["losses13"] == "1"

    def test_live_data_p1_parses_duration(self):
        result = parse_generals_kv(LIVE_RAW_P1)
        assert result["duration8"] == "3"
        assert result["duration13"] == "2"

    def test_live_data_p3_parses_wins6_and_losses6(self):
        result = parse_generals_kv(LIVE_RAW_P3)
        assert result["wins6"] == "1"
        assert result["losses6"] == "1"

    def test_live_data_p3_parses_last_general(self):
        result = parse_generals_kv(LIVE_RAW_P3)
        assert result["lastGeneral"] == "6"

    def test_live_data_p1_win_row_max(self):
        result = parse_generals_kv(LIVE_RAW_P1)
        assert result["WinRowMax"] == "1"


class TestFormatGeneralsKv:
    def test_basic_formatting(self):
        result = format_generals_kv({"wins0": "5"})
        assert result == "\\wins0\\5\\"

    def test_empty_returns_empty_string(self):
        assert format_generals_kv({}) == ""

    def test_round_trip(self):
        original = {"wins0": "3", "losses0": "1", "duration0": "15"}
        assert parse_generals_kv(format_generals_kv(original)) == original


class TestMergeGeneralsKv:
    def test_merge_updates_existing_key(self):
        existing = r"\genInRow\1\lastGeneral\6"
        incoming = r"\genInRow\2"
        result = parse_generals_kv(merge_generals_kv(existing, incoming))
        assert result["genInRow"] == "2"
        assert result["lastGeneral"] == "6"

    def test_merge_adds_new_key(self):
        existing = r"\discons0\0"
        incoming = r"\wins8\1"
        result = parse_generals_kv(merge_generals_kv(existing, incoming))
        assert result["discons0"] == "0"
        assert result["wins8"] == "1"

    def test_merge_with_empty_existing(self):
        incoming = r"\wins6\1\losses6\1"
        result = parse_generals_kv(merge_generals_kv("", incoming))
        assert result["wins6"] == "1"
        assert result["losses6"] == "1"

    def test_merge_with_empty_incoming(self):
        existing = r"\wins6\1"
        result = parse_generals_kv(merge_generals_kv(existing, ""))
        assert result["wins6"] == "1"


# =============================================================================
# _get_int helper
# =============================================================================


class TestGetInt:
    def test_valid_int(self):
        assert _get_int({"wins0": "5"}, "wins0") == 5

    def test_missing_key_returns_default(self):
        assert _get_int({}, "wins0") == 0
        assert _get_int({}, "wins0", 99) == 99

    def test_non_numeric_value_returns_default(self):
        assert _get_int({"key": "LOD2"}, "key") == 0

    def test_null_byte_in_value_returns_default(self):
        # DSRow's value gets "0\x00" due to C null terminator in payload
        assert _get_int({"DSRow": "0\x00"}, "DSRow") == 0

    def test_zero_string(self):
        assert _get_int({"x": "0"}, "x") == 0


# =============================================================================
# Aggregate helpers
# =============================================================================


class TestGetTotalWins:
    def test_sums_across_all_indices(self):
        stats = {"wins2": "3", "wins8": "1", "wins13": "2"}
        assert _get_total_wins(stats) == 6

    def test_zero_when_no_wins(self):
        assert _get_total_wins({}) == 0

    def test_ignores_losses_keys(self):
        stats = {"losses6": "5", "wins6": "2"}
        assert _get_total_wins(stats) == 2

    def test_live_p1_total_wins(self):
        # Player 1: wins8=1, losses13=1 — total wins = 1
        stats = parse_generals_kv(LIVE_RAW_P1)
        assert _get_total_wins(stats) == 1

    def test_live_p3_total_wins(self):
        # Player 3: wins6=1, losses6=1 — total wins = 1
        stats = parse_generals_kv(LIVE_RAW_P3)
        assert _get_total_wins(stats) == 1


class TestGetTotalLosses:
    def test_sums_across_all_indices(self):
        stats = {"losses2": "1", "losses8": "2"}
        assert _get_total_losses(stats) == 3

    def test_zero_when_no_losses(self):
        assert _get_total_losses({}) == 0

    def test_live_p1_total_losses(self):
        stats = parse_generals_kv(LIVE_RAW_P1)
        assert _get_total_losses(stats) == 1

    def test_live_p3_total_losses(self):
        stats = parse_generals_kv(LIVE_RAW_P3)
        assert _get_total_losses(stats) == 1


class TestGetTotalGames:
    def test_sums_wins_and_losses(self):
        stats = {"wins6": "2", "losses6": "1", "wins8": "3"}
        assert _get_total_games(stats) == 6

    def test_live_p1_total_games(self):
        # wins8=1, losses13=1 → 2 total
        stats = parse_generals_kv(LIVE_RAW_P1)
        assert _get_total_games(stats) == 2

    def test_live_p3_total_games(self):
        # wins6=1, losses6=1 → 2 total
        stats = parse_generals_kv(LIVE_RAW_P3)
        assert _get_total_games(stats) == 2


class TestGetTotalDurationHours:
    def test_converts_minutes_to_hours(self):
        stats = {"duration0": "60"}
        assert _get_total_duration_hours(stats) == pytest.approx(1.0)

    def test_sums_across_all_indices(self):
        # duration8=3 + duration13=2 = 5 minutes = 5/60 hours
        stats = {"duration8": "3", "duration13": "2"}
        assert _get_total_duration_hours(stats) == pytest.approx(5 / 60)

    def test_zero_when_no_duration(self):
        assert _get_total_duration_hours({}) == pytest.approx(0.0)

    def test_live_p1_duration(self):
        # duration8=3 + duration13=2 = 5 minutes
        stats = parse_generals_kv(LIVE_RAW_P1)
        assert _get_total_duration_hours(stats) == pytest.approx(5 / 60)

    def test_live_p3_duration(self):
        # duration6=3 → 3 minutes
        stats = parse_generals_kv(LIVE_RAW_P3)
        assert _get_total_duration_hours(stats) == pytest.approx(3 / 60)


class TestGetTotalDisconnects:
    def test_sums_15_slots(self):
        stats = {f"discons{i}": "1" for i in range(15)}
        assert _get_total_disconnects(stats) == 15

    def test_zero_when_all_zero(self):
        stats = {f"discons{i}": "0" for i in range(15)}
        assert _get_total_disconnects(stats) == 0

    def test_live_p1_no_disconnects(self):
        stats = parse_generals_kv(LIVE_RAW_P1)
        assert _get_total_disconnects(stats) == 0

    def test_live_p3_no_disconnects(self):
        stats = parse_generals_kv(LIVE_RAW_P3)
        assert _get_total_disconnects(stats) == 0


class TestGetTotalDesyncs:
    def test_sums_14_slots(self):
        stats = {f"desyncs{i}": "2" for i in range(14)}
        assert _get_total_desyncs(stats) == 28

    def test_zero_when_absent(self):
        assert _get_total_desyncs({}) == 0


# =============================================================================
# Rank calculation
# =============================================================================


class TestCalculateRank:
    def test_zero_stats_gives_rank_zero(self):
        assert calculate_rank({}) == 0

    def test_wins_increase_points(self):
        # 17 wins * 3.0 = 51 points → just over threshold[1]=50 → rank 1
        stats = {"wins2": "17"}
        assert calculate_rank(stats) == 1

    def test_losses_do_not_add_points(self):
        # loss_multiplier=0.0, so losses contribute nothing
        stats = {"losses2": "100"}
        assert calculate_rank(stats) == 0

    def test_disconnects_subtract_points(self):
        # 20 wins = 60 pts → rank 1; 15 discons * -1 = -15 → 45 pts → rank 0
        stats = {"wins2": "20", "discons0": "15"}
        assert calculate_rank(stats) == 0

    def test_desyncs_also_penalise(self):
        # 20 wins = 60 pts; 15 desyncs * -1 = -15 → 45 pts → rank 0
        stats = {"wins2": "20", "desyncs0": "15"}
        assert calculate_rank(stats) == 0

    def test_duration_contributes_to_points(self):
        # 600 minutes = 10 hours * 1.0 = 10 pts (not enough to change rank alone)
        stats = {"duration0": "600"}
        assert calculate_rank(stats) == 0

    def test_live_p1_rank_zero(self):
        # wins=1 → 3pts, duration=5min → 0.083pts → total ~3.08, well below 50
        stats = parse_generals_kv(LIVE_RAW_P1)
        assert calculate_rank(stats) == 0

    def test_live_p3_rank_zero(self):
        stats = parse_generals_kv(LIVE_RAW_P3)
        assert calculate_rank(stats) == 0

    def test_custom_thresholds(self):
        stats = {"wins2": "5"}  # 15 pts
        assert calculate_rank(stats, thresholds=[0, 10, 100]) == 1

    def test_rank_capped_at_max_threshold_index(self):
        # Enough wins for max rank (9)
        stats = {"wins2": "5000"}  # 15000 pts → exceeds threshold[9]=10000
        assert calculate_rank(stats) == 9


# =============================================================================
# Battle honors
# =============================================================================


class TestEvaluateBattleHonors:
    # --- FAIR_PLAY ---

    def test_fair_play_no_games(self):
        honors = evaluate_battle_honors({})
        assert honors & HONOR_FAIR_PLAY

    def test_fair_play_zero_disconnects(self):
        stats = {"wins6": "10"}
        honors = evaluate_battle_honors(stats)
        assert honors & HONOR_FAIR_PLAY

    def test_fair_play_denied_above_5pct(self):
        # 1 disconnect in 10 games = 10% > 5%
        stats = {"wins6": "9", "discons0": "1"}
        honors = evaluate_battle_honors(stats)
        assert not (honors & HONOR_FAIR_PLAY)

    def test_fair_play_exactly_5pct_denied(self):
        # 1 discon in 20 games = 5% — NOT below 5%
        stats = {f"wins{i}": "1" for i in range(2, 22)}  # 20 wins
        stats["discons0"] = "1"
        honors = evaluate_battle_honors(stats)
        assert not (honors & HONOR_FAIR_PLAY)

    # --- STREAK ---

    def test_streak_requires_winrowmax_5(self):
        stats = {"WinRowMax": "5"}
        assert evaluate_battle_honors(stats) & HONOR_STREAK

    def test_streak_not_awarded_below_5(self):
        stats = {"WinRowMax": "4"}
        assert not (evaluate_battle_honors(stats) & HONOR_STREAK)

    # --- STREAK_ONLINE ---

    def test_streak_online_requires_winrowmax_3(self):
        stats = {"WinRowMax": "3"}
        assert evaluate_battle_honors(stats) & HONOR_STREAK_ONLINE

    def test_streak_online_not_awarded_below_3(self):
        stats = {"WinRowMax": "2"}
        assert not (evaluate_battle_honors(stats) & HONOR_STREAK_ONLINE)

    def test_streak_online_awarded_when_streak_earned(self):
        # WinRowMax=5 earns both STREAK and STREAK_ONLINE
        stats = {"WinRowMax": "5"}
        honors = evaluate_battle_honors(stats)
        assert honors & HONOR_STREAK
        assert honors & HONOR_STREAK_ONLINE

    # --- LOYALTY ---

    def test_loyalty_usa_requires_gen_in_row_20_usa_general(self):
        # AmericaLaserGeneral = index 6 ∈ USA
        stats = {"genInRow": "20", "lastGeneral": "6"}
        assert evaluate_battle_honors(stats) & HONOR_LOYALTY_USA

    def test_loyalty_china_requires_gen_in_row_20_china_general(self):
        # ChinaTankGeneral = index 8 ∈ China
        stats = {"genInRow": "20", "lastGeneral": "8"}
        assert evaluate_battle_honors(stats) & HONOR_LOYALTY_CHINA

    def test_loyalty_gla_requires_gen_in_row_20_gla_general(self):
        # GLAStealthGeneral = index 13 ∈ GLA (matches log evidence)
        stats = {"genInRow": "20", "lastGeneral": "13"}
        assert evaluate_battle_honors(stats) & HONOR_LOYALTY_GLA

    def test_loyalty_not_awarded_below_20(self):
        stats = {"genInRow": "19", "lastGeneral": "6"}
        assert not (evaluate_battle_honors(stats) & HONOR_LOYALTY_USA)

    def test_loyalty_not_awarded_for_non_playable_general(self):
        # index 0 = Random, index 1 = Observer — not in any faction set
        stats = {"genInRow": "20", "lastGeneral": "0"}
        honors = evaluate_battle_honors(stats)
        assert not (honors & HONOR_LOYALTY_USA)
        assert not (honors & HONOR_LOYALTY_CHINA)
        assert not (honors & HONOR_LOYALTY_GLA)

    def test_at_most_one_loyalty_awarded(self):
        # All loyalty honors are mutually exclusive (if-elif chain)
        stats = {"genInRow": "20", "lastGeneral": "8"}  # China
        honors = evaluate_battle_honors(stats)
        loyalty_flags = HONOR_LOYALTY_USA | HONOR_LOYALTY_CHINA | HONOR_LOYALTY_GLA
        earned = honors & loyalty_flags
        # Exactly one loyalty flag or none
        assert earned & (earned - 1) == 0  # at most one bit set

    # --- APOCALYPSE ---

    def test_apocalypse_requires_all_three_superweapons(self):
        stats = {"builtNuke": "1", "builtSCUD": "1", "builtCannon": "1"}
        assert evaluate_battle_honors(stats) & HONOR_APOCALYPSE

    def test_apocalypse_denied_if_any_missing(self):
        assert not (evaluate_battle_honors({"builtNuke": "1", "builtSCUD": "1"}) & HONOR_APOCALYPSE)
        assert not (evaluate_battle_honors({"builtNuke": "1", "builtCannon": "1"}) & HONOR_APOCALYPSE)
        assert not (evaluate_battle_honors({"builtSCUD": "1", "builtCannon": "1"}) & HONOR_APOCALYPSE)

    # --- OFFICERSCLUB ---

    def test_officersclub_at_rank_6(self):
        stats = {"wins2": "700"}  # 2100 pts → rank 6
        rank = calculate_rank(stats)
        assert rank == 6
        assert evaluate_battle_honors(stats, rank=rank) & HONOR_OFFICERSCLUB

    def test_officersclub_not_below_rank_6(self):
        assert not (evaluate_battle_honors({}, rank=5) & HONOR_OFFICERSCLUB)

    # --- DOMINATION ---

    def test_domination_requires_20_games_and_75pct(self):
        # 16 wins, 4 losses = 80% in 20 games
        stats = {"wins2": "16", "losses2": "4"}
        assert evaluate_battle_honors(stats) & HONOR_DOMINATION

    def test_domination_denied_below_20_games(self):
        stats = {"wins2": "16", "losses2": "3"}  # 19 games
        assert not (evaluate_battle_honors(stats) & HONOR_DOMINATION)

    def test_domination_denied_below_75pct(self):
        # Exactly 75% is NOT > 75%
        stats = {"wins2": "15", "losses2": "5"}  # 75% exactly
        assert not (evaluate_battle_honors(stats) & HONOR_DOMINATION)

    def test_domination_online_same_threshold(self):
        stats = {"wins2": "16", "losses2": "4"}
        honors = evaluate_battle_honors(stats)
        assert honors & HONOR_DOMINATION
        assert honors & HONOR_DOMINATION_ONLINE

    # --- CHALLENGE_MODE ---

    def test_challenge_mode_requires_medals(self):
        stats = {"chlgMedals": "1"}
        assert evaluate_battle_honors(stats) & HONOR_CHALLENGE_MODE

    def test_challenge_mode_not_awarded_zero_medals(self):
        assert not (evaluate_battle_honors({}) & HONOR_CHALLENGE_MODE)

    # --- GLOBAL_GENERAL ---

    def test_global_general_requires_all_12_played(self):
        # At least 1 game (win or loss) with each of indices 2-13
        stats = {}
        for i in range(2, 14):
            stats[f"wins{i}"] = "1"
        assert evaluate_battle_honors(stats) & HONOR_GLOBAL_GENERAL

    def test_global_general_denied_if_one_missing(self):
        stats = {}
        for i in range(2, 13):  # only 11 generals
            stats[f"wins{i}"] = "1"
        assert not (evaluate_battle_honors(stats) & HONOR_GLOBAL_GENERAL)

    def test_global_general_indices_0_and_1_not_required(self):
        # Random (0) and Observer (1) are not playable — ignored
        stats = {}
        for i in range(2, 14):
            stats[f"losses{i}"] = "1"
        stats["wins0"] = "100"  # irrelevant
        assert evaluate_battle_honors(stats) & HONOR_GLOBAL_GENERAL

    # --- ENDURANCE ---

    def test_endurance_requires_100_hours(self):
        stats = {"duration0": str(100 * 60)}  # 6000 minutes = 100 hours
        assert evaluate_battle_honors(stats) & HONOR_ENDURANCE

    def test_endurance_denied_below_100_hours(self):
        stats = {"duration0": str(99 * 60 + 59)}  # 99h59m
        assert not (evaluate_battle_honors(stats) & HONOR_ENDURANCE)

    # --- ULTIMATE ---

    def test_ultimate_requires_all_computable_honors(self):
        stats = {}
        # STREAK (WinRowMax >= 5) + STREAK_ONLINE (>= 3)
        stats["WinRowMax"] = "5"
        # FAIR_PLAY: no disconnects (default)
        # APOCALYPSE
        stats["builtNuke"] = "1"
        stats["builtSCUD"] = "1"
        stats["builtCannon"] = "1"
        # DOMINATION + DOMINATION_ONLINE: >75% with 20+ games
        for i in range(2, 5):  # 3 generals, 8 wins each = 24 wins, 0 losses
            stats[f"wins{i}"] = "8"
        # OFFICERSCLUB: rank >= 6 → need 2000 pts; 24 wins * 3 = 72 pts — not enough
        # Use a direct rank parameter instead
        # GLOBAL_GENERAL
        for i in range(2, 14):
            if f"wins{i}" not in stats:
                stats[f"wins{i}"] = "1"
        # ENDURANCE: 100+ hours
        stats["duration0"] = str(100 * 60)

        honors = evaluate_battle_honors(stats, rank=6)
        assert honors & HONOR_ULTIMATE

    def test_ultimate_denied_if_any_required_honor_missing(self):
        # Same as above but WinRowMax=0 → no STREAK/STREAK_ONLINE
        stats = {
            "builtNuke": "1",
            "builtSCUD": "1",
            "builtCannon": "1",
            "duration0": str(100 * 60),
        }
        for i in range(2, 14):
            stats[f"wins{i}"] = "8"
        honors = evaluate_battle_honors(stats, rank=6)
        assert not (honors & HONOR_ULTIMATE)

    # --- CLIENT-SENT battle FIELD IS NOT EVALUATED server-side ---

    def test_client_battle_field_is_ignored(self):
        # Game sends battle\49152 (BLITZ5|BLITZ10) — server must not include these
        stats = {"battle": "49152"}
        honors = evaluate_battle_honors(stats)
        # BLITZ5=0x4000, BLITZ10=0x8000 should not appear
        assert not (honors & 0x4000)
        assert not (honors & 0x8000)


# =============================================================================
# Live DB snapshots — end-to-end validation
# =============================================================================


class TestLiveDBSnapshots:
    """
    Validate that processing the actual stored raw_data produces the correct
    battle_honors value that matches what is stored in the database column.
    """

    def test_player1_battle_honors_is_fair_play(self):
        stats = parse_generals_kv(LIVE_RAW_P1)
        rank = calculate_rank(stats)
        honors = evaluate_battle_honors(stats, rank=rank)
        assert honors == HONOR_FAIR_PLAY, f"Expected HONOR_FAIR_PLAY (0x{HONOR_FAIR_PLAY:x}), got 0x{honors:x}"

    def test_player3_battle_honors_is_fair_play(self):
        stats = parse_generals_kv(LIVE_RAW_P3)
        rank = calculate_rank(stats)
        honors = evaluate_battle_honors(stats, rank=rank)
        assert honors == HONOR_FAIR_PLAY, f"Expected HONOR_FAIR_PLAY (0x{HONOR_FAIR_PLAY:x}), got 0x{honors:x}"

    def test_player1_rank_is_zero(self):
        stats = parse_generals_kv(LIVE_RAW_P1)
        assert calculate_rank(stats) == 0

    def test_player3_rank_is_zero(self):
        stats = parse_generals_kv(LIVE_RAW_P3)
        assert calculate_rank(stats) == 0

    def test_player1_last_general_is_china_tank(self):
        stats = parse_generals_kv(LIVE_RAW_P1)
        assert _get_int(stats, "lastGeneral") == 8
        assert 8 in CHINA_GENERAL_INDICES

    def test_player3_last_general_is_america_laser(self):
        stats = parse_generals_kv(LIVE_RAW_P3)
        assert _get_int(stats, "lastGeneral") == 6
        assert 6 in USA_GENERAL_INDICES

    def test_player3_gen_in_row_is_two(self):
        # Player 3 played 2 consecutive games with AmericaLaserGeneral
        stats = parse_generals_kv(LIVE_RAW_P3)
        assert _get_int(stats, "genInRow") == 2

    def test_player1_no_disconnects(self):
        stats = parse_generals_kv(LIVE_RAW_P1)
        assert _get_total_disconnects(stats) == 0

    def test_player3_no_disconnects(self):
        stats = parse_generals_kv(LIVE_RAW_P3)
        assert _get_total_disconnects(stats) == 0

    def test_player1_total_wins_and_losses(self):
        # wins8=1, losses13=1
        stats = parse_generals_kv(LIVE_RAW_P1)
        assert _get_total_wins(stats) == 1
        assert _get_total_losses(stats) == 1

    def test_player3_total_wins_and_losses(self):
        # wins6=1, losses6=1
        stats = parse_generals_kv(LIVE_RAW_P3)
        assert _get_total_wins(stats) == 1
        assert _get_total_losses(stats) == 1

    def test_player3_loyalty_not_yet_awarded(self):
        # genInRow=2 < 20: loyalty honor must NOT be awarded
        stats = parse_generals_kv(LIVE_RAW_P3)
        rank = calculate_rank(stats)
        honors = evaluate_battle_honors(stats, rank=rank)
        assert not (honors & HONOR_LOYALTY_USA)
        assert not (honors & HONOR_LOYALTY_CHINA)
        assert not (honors & HONOR_LOYALTY_GLA)

    def test_player1_loyalty_not_yet_awarded(self):
        # genInRow=1 < 20
        stats = parse_generals_kv(LIVE_RAW_P1)
        rank = calculate_rank(stats)
        honors = evaluate_battle_honors(stats, rank=rank)
        assert not (honors & HONOR_LOYALTY_USA)
        assert not (honors & HONOR_LOYALTY_CHINA)
        assert not (honors & HONOR_LOYALTY_GLA)

    def test_neither_player_earned_streak(self):
        # WinRowMax=1 for both — streak requires 5 (or 3 for online)
        for raw in (LIVE_RAW_P1, LIVE_RAW_P3):
            stats = parse_generals_kv(raw)
            honors = evaluate_battle_honors(stats)
            assert not (honors & HONOR_STREAK)
            assert not (honors & HONOR_STREAK_ONLINE)

    def test_dsrow_null_byte_does_not_break_honors(self):
        # DSRow value is "0\x00" due to game's null terminator;
        # verify this causes no exception and returns a clean honors value
        stats = parse_generals_kv(LIVE_RAW_P3)
        assert _get_int(stats, "DSRow") == 0  # null byte silently dropped
        honors = evaluate_battle_honors(stats)
        assert isinstance(honors, int)


# =============================================================================
# Per-game honor mask
# =============================================================================


class TestPerGameHonorMask:
    def test_mask_value(self):
        expected = HONOR_BATTLE_TANK | HONOR_AIR_WING | HONOR_BLITZ5 | HONOR_BLITZ10
        assert PER_GAME_HONOR_MASK == expected

    def test_mask_numeric_value(self):
        # 0x80 | 0x100 | 0x4000 | 0x8000 = 0xC180
        assert PER_GAME_HONOR_MASK == 0xC180

    def test_all_four_per_game_honors_included(self):
        assert PER_GAME_HONOR_MASK & HONOR_BATTLE_TANK
        assert PER_GAME_HONOR_MASK & HONOR_AIR_WING
        assert PER_GAME_HONOR_MASK & HONOR_BLITZ5
        assert PER_GAME_HONOR_MASK & HONOR_BLITZ10

    def test_no_overlap_with_server_honors(self):
        server_honors = (
            HONOR_STREAK
            | HONOR_LOYALTY_USA
            | HONOR_LOYALTY_CHINA
            | HONOR_LOYALTY_GLA
            | HONOR_ENDURANCE
            | HONOR_FAIR_PLAY
            | HONOR_APOCALYPSE
            | HONOR_OFFICERSCLUB
            | HONOR_DOMINATION
            | HONOR_CHALLENGE_MODE
            | HONOR_ULTIMATE
            | HONOR_GLOBAL_GENERAL
            | HONOR_DOMINATION_ONLINE
            | HONOR_STREAK_ONLINE
        )
        assert PER_GAME_HONOR_MASK & server_honors == 0


# =============================================================================
# extract_client_per_game_honors
# =============================================================================


class TestExtractClientPerGameHonors:
    def test_extracts_blitz_from_battle_49152(self):
        # 49152 = 0xC000 = BLITZ5 (0x4000) | BLITZ10 (0x8000)
        stats = {"battle": "49152"}
        result = extract_client_per_game_honors(stats)
        assert result & HONOR_BLITZ5
        assert result & HONOR_BLITZ10
        assert not (result & HONOR_BATTLE_TANK)
        assert not (result & HONOR_AIR_WING)

    def test_strips_non_per_game_bits(self):
        # Client sends battle value with server-computed honor bits injected
        injected = HONOR_BLITZ5 | HONOR_FAIR_PLAY | HONOR_OFFICERSCLUB
        stats = {"battle": str(injected)}
        result = extract_client_per_game_honors(stats)
        assert result == HONOR_BLITZ5
        assert not (result & HONOR_FAIR_PLAY)
        assert not (result & HONOR_OFFICERSCLUB)

    def test_handles_missing_battle_field(self):
        assert extract_client_per_game_honors({}) == 0

    def test_handles_zero_battle_field(self):
        assert extract_client_per_game_honors({"battle": "0"}) == 0

    def test_extracts_battle_tank(self):
        stats = {"battle": str(HONOR_BATTLE_TANK)}
        assert extract_client_per_game_honors(stats) == HONOR_BATTLE_TANK

    def test_extracts_air_wing(self):
        stats = {"battle": str(HONOR_AIR_WING)}
        assert extract_client_per_game_honors(stats) == HONOR_AIR_WING

    def test_all_four_per_game_honors(self):
        all_four = HONOR_BATTLE_TANK | HONOR_AIR_WING | HONOR_BLITZ5 | HONOR_BLITZ10
        stats = {"battle": str(all_four)}
        assert extract_client_per_game_honors(stats) == all_four

    def test_live_data_p1_has_blitz_honors(self):
        # Player 1 sent battle\49152 (BLITZ5|BLITZ10) — won in <5 min
        stats = parse_generals_kv(LIVE_RAW_P1)
        result = extract_client_per_game_honors(stats)
        assert result & HONOR_BLITZ5
        assert result & HONOR_BLITZ10

    def test_live_data_p3_has_blitz_honors(self):
        # Player 3 also sent battle\49152
        stats = parse_generals_kv(LIVE_RAW_P3)
        result = extract_client_per_game_honors(stats)
        assert result & HONOR_BLITZ5
        assert result & HONOR_BLITZ10
