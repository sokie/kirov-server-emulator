"""
Tests for Tiberium Wars and Kane's Wrath match reports, careers and Sake tables.

The two Tiberium Wars reports are the ones the game sent after two ranked 1v1 matches in which GDI beat Scrin.
The column fixtures are the PlayerStats tables of cnc3game.dat 1.10 and cnc3ep1.dat 1.3: column name, lobby
mode, faction bucket and stat id.
"""

import csv
import json
import os
import struct
import uuid

import pytest
from sqlalchemy import create_engine as _sa_create_engine
from sqlmodel import Session, SQLModel, select

import app.db.database as _db_module
from app.db import cnc3_career, cnc3_import
from app.db.crud import create_competition_session, finalize_match_from_report, get_player_level, get_player_stats
from app.models.cnc3_stats import (
    ALL_ONLINE,
    KW,
    SAKE_COLUMNS,
    TW,
    Cnc3Game,
    player_key_name,
)
from app.models.match_report import MatchReport, get_player_key_name
from app.models.models import CompetitionSession, MatchHistory, Persona
from app.models.ra3_stats import score_delta
from app.soap import cnc3_sake, sake_records

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")
GAMES = [TW, KW]

LOBBY_MODE = {3: "unranked", 4: "ranked_1v1", 5: "ranked_2v2", 6: "clan_1v1", 7: "clan_2v2", 8: ALL_ONLINE}
TW_BUCKETS = {0: ("factions", "gdi"), 1: ("factions", "nod"), 2: ("factions", "scrin"), 3: ("", None)}
KW_BUCKETS = {
    0: ("factions", "gdi"),
    1: ("factions", "nod"),
    2: ("factions", "scrin"),
    3: ("factions", "steel_talons"),
    4: ("factions", "zocom"),
    5: ("factions", "black_hand"),
    6: ("factions", "marked_of_kane"),
    7: ("factions", "reaper_17"),
    8: ("factions", "traveler_59"),
    9: ("", None),
    10: ("parents", "gdi"),
    11: ("parents", "nod"),
    12: ("parents", "scrin"),
}


def _fixture(game: Cnc3Game, name: str) -> bytes:
    with open(os.path.join(FIXTURES, game.name, name), "rb") as f:
        return f.read()


def _value(key: int, kind: str, value) -> bytes:
    if kind == "int":
        return struct.pack(">HHi", key, 0, value)
    if kind == "short":
        return struct.pack(">HHh", key, 1, value)
    if kind == "byte":
        return struct.pack(">HHB", key, 2, value)
    data = value.encode("utf-8")
    return struct.pack(">HHB", key, 3, len(data)) + data


def build_report(game: Cnc3Game, gt: int, players: list[dict], duration: int = 300, ended: bool = True) -> bytes:
    """Builds a report for mode index gt. Without ended, the game sends no game length."""
    off = game.key_offset
    roster = b"".join(p["guid"].bytes + struct.pack(">i", p.get("team", 0)) for p in players)
    auth = b"\0" * 16 * len(players)
    results = b"".join(struct.pack(">I", p["result"]) for p in players)
    game_values = [(72 + off + gt, "byte", 1), (61 + off, "string", "Test Map"), (63 + off, "string", "1.10")]
    if ended:
        game_values.append((62 + off, "int", duration))
    game_section = b"".join(_value(*v) for v in game_values)
    player = b""
    player_keys = 0
    for i, p in enumerate(players):
        values = [(p["side"] * 5 + gt, "short", 1)]
        if i == 0:
            values.append((15 + off + gt, "int", duration))
        counts = p.get("counts", {})
        values += [(stat.report_base + off + gt, "int", counts.get(stat.key, 0)) for stat in game.report_stats]
        player += struct.pack(">H", len(values)) + b"".join(_value(*v) for v in values)
        player_keys += len(values)
    developer = 100 if game is KW else 5
    header = struct.pack(
        ">II16sIIHHHHHH", 1, developer, b"\0" * 16, 0, 1, len(players), 0, len(game_values), player_keys, 0, 0
    )
    lengths = struct.pack(">6i", len(roster), len(auth), len(results), len(game_section), len(player), 0)
    return header + lengths + roster + auth + results + game_section + player


def guid(persona_id: int) -> uuid.UUID:
    return uuid.UUID(f"{persona_id:08x}-beef-cafe-0000-000000000000")


def settle_players(report: MatchReport) -> list[dict]:
    """The player list the Competition route hands to finalize_match_from_report."""
    return [
        {
            "persona_id": p.persona_id,
            "result": p.result,
            "faction": p.faction,
            "full_id": p.full_id,
            "counts": report.get_cnc3_counts(i),
        }
        for i, p in enumerate(report.get_player_list())
    ]


@pytest.fixture
def db():
    engine = _sa_create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    SQLModel.metadata.create_all(engine)
    original = _db_module.engine
    _db_module.engine = engine
    with Session(engine) as session:
        for name in ("one", "two", "three", "four"):
            session.add(Persona(name=name, user_id=1))
        session.commit()
        yield session
    _db_module.engine = original
    engine.dispose()


class TestCatalogue:
    @pytest.mark.parametrize(
        ("game", "csv_name", "buckets", "count"),
        [(TW, "playerstats_v5_columns.csv", TW_BUCKETS, 160), (KW, "playerstats_v100_columns.csv", KW_BUCKETS, 420)],
    )
    def test_columns_match_the_binary(self, game, csv_name, buckets, count):
        with open(os.path.join(FIXTURES, game.name, csv_name), encoding="ascii") as f:
            rows = list(csv.DictReader(f))
        assert len(rows) == count == len(SAKE_COLUMNS[game.game_id])
        for row in rows:
            column = SAKE_COLUMNS[game.game_id][row["name"]]
            want = (LOBBY_MODE[int(row["lobby_mode"])], *buckets[int(row["faction_bucket"])], int(row["stat_id"]))
            assert (column.mode, column.group, column.faction, column.stat.stat_id) == want, row["name"]

    def test_the_games_share_report_bases(self):
        assert [s.report_base for s in TW.report_stats] == [s.report_base for s in KW.report_stats]
        assert [s.report_base for s in TW.report_stats] == [20, 25, 30, 35, 40, 45, 50]


class TestReports:
    @pytest.mark.parametrize(
        ("name", "duration", "units_built"),
        [("report_ranked1v1_342s.bin", 342, 6), ("report_ranked1v1_468s.bin", 468, 5)],
    )
    def test_captured_reports_decode(self, name, duration, units_built):
        report = MatchReport.from_bytes(_fixture(TW, name), game_id=TW.game_id)
        assert (report.get_cnc3_mode(), report.get_duration(), report.get_map_path()) == (
            "ranked_1v1",
            duration,
            "Barstow Badlands (2)",
        )
        assert [(p.faction, p.result) for p in report.get_player_list()] == [("GDI", 0), ("Scrin", 1)]
        assert report.get_local_player_index() == 0
        winner = report.get_cnc3_counts(0)
        assert (winner["structures_built"], winner["structures_destroyed"], winner["units_built"]) == (
            2,
            1,
            units_built,
        )
        assert report.get_cnc3_counts(1)["structures_lost"] == 1

    def test_every_captured_key_has_a_name(self):
        for name in ("report_ranked1v1_342s.bin", "report_ranked1v1_468s.bin"):
            report = MatchReport.from_bytes(_fixture(TW, name), game_id=TW.game_id)
            gt = report.get_game_type_from_key()
            for section in report.player_section:
                for key in section:
                    assert not get_player_key_name(key, TW.game_id, gt).startswith("unknown_"), key

    @pytest.mark.parametrize("game", GAMES)
    @pytest.mark.parametrize("gt", [1, 2, 3, 4, 5])
    def test_keys_are_unique_in_every_mode(self, game, gt):
        off = game.key_offset
        sides = [side * 5 + gt for side in game.side_to_faction]
        keys = sides + [15 + off + gt, 72 + off] + [s.report_base + off + gt for s in game.report_stats]
        assert len(keys) == len(set(keys))
        for stat in game.report_stats:
            assert player_key_name(game, stat.report_base + off + gt, gt) == stat.key

    @pytest.mark.parametrize("game", GAMES)
    def test_clan_2v2_sides_and_counts(self, game):
        sides = sorted(game.side_to_faction)
        players = [
            {"guid": guid(1), "side": sides[0], "result": 0, "team": 1, "counts": {"units_killed": 9}},
            {"guid": guid(2), "side": sides[-1], "result": 1, "team": 2, "counts": {"structures_lost": 3}},
        ]
        report = MatchReport.from_bytes(build_report(game, 5, players), game_id=game.game_id)
        assert report.get_cnc3_mode() == "clan_2v2"
        factions = [p.faction for p in report.get_player_list()]
        assert factions == (["GDI", "Scrin"] if game is TW else ["GDI", "Traveler-59"])
        assert report.get_cnc3_counts(0)["units_killed"] == 9
        assert report.get_cnc3_counts(1)["structures_lost"] == 3
        assert report.get_local_player_index() == 0

    def test_kane_s_wrath_keys_are_45_higher(self):
        players = [{"guid": guid(1), "side": 3, "result": 0}, {"guid": guid(2), "side": 6, "result": 1}]
        report = MatchReport.from_bytes(build_report(KW, 2, players, duration=410), game_id=KW.game_id)
        assert report.is_kw and 106 in report.game_section and 107 in report.game_section
        assert (report.get_cnc3_mode(), report.get_duration(), report.get_map_path()) == ("ranked_1v1", 410, "Test Map")
        assert [p.faction for p in report.get_player_list()] == ["Steel Talons", "Black Hand"]
        assert 62 in report.player_section[0] and report.get_local_player_index() == 0


def _fold(game: Cnc3Game, matches: list[tuple]) -> dict:
    career: dict = {}
    for mode, faction, result, duration, counts in matches:
        career = cnc3_career.fold_match(game, career, mode, faction, result, duration, counts)
    return career


class TestCareers:
    def test_streaks_ratios_and_counts(self):
        career = _fold(
            TW,
            [
                ("ranked_1v1", "gdi", 0, 300, {"units_built": 5}),
                ("ranked_1v1", "gdi", 0, 200, {"units_built": 3}),
                ("ranked_1v1", "nod", 1, 100, {"units_lost": 4}),
                ("ranked_1v1", "gdi", 0, 400, {}),
            ],
        )
        total = career["ranked_1v1"]
        assert (total["total_matches"], total["wins"], total["losses"]) == (4, 3, 1)
        assert (total["current_win_streak"], total["longest_win_streak"]) == (1, 2)
        assert (total["current_loss_streak"], total["longest_loss_streak"]) == (0, 1)
        assert (total["total_time_played"], total["avg_game_length"]) == (1000, 250)
        assert (total["units_built"], total["units_lost"]) == (8, 4)
        assert total["factions"]["gdi"]["wins"] == 3 and total["factions"]["nod"]["losses"] == 1
        columns = SAKE_COLUMNS[TW.game_id]
        assert cnc3_career.column_value(career, columns["WinLossRatio_RANKED1V1"]) == 3.0
        assert cnc3_career.column_value(career, columns["WinLossRatio_NOD_RANKED1V1"]) == 0.0
        assert cnc3_career.column_value(career, columns["AverageGameLength_RANKED1V1"]) == 250.0
        assert cnc3_career.column_value(career, columns["UnitKillDeathRatio_RANKED1V1"]) == 0.0
        assert cnc3_career.column_value(career, columns["TotalMatches_GDI_RANKED1V1"]) == 3

    def test_kane_s_wrath_keeps_subfactions_parents_and_all_online(self):
        career = _fold(
            KW,
            [
                ("ranked_1v1", "steel_talons", 0, 300, {"units_killed": 2}),
                ("unranked", "zocom", 1, 100, {"units_killed": 1}),
            ],
        )
        columns = SAKE_COLUMNS[KW.game_id]
        value = cnc3_career.column_value
        assert value(career, columns["CareerWins_GDI_TALONS_RANKED1V1"]) == 1
        assert value(career, columns["CareerLosses_GDI_ZOCOM_UNRANKED"]) == 1
        assert value(career, columns["TotalMatches_GDI_ALLONLINE"]) == 2
        assert value(career, columns["TotalMatches_ALLONLINE"]) == 2
        assert value(career, columns["CareerUnitsKilled_ALLONLINE"]) == 3
        assert value(career, columns["TotalTimePlayed_ALLONLINE"]) == 400
        assert value(career, columns["CurrentLossStreak_ALLONLINE"]) == 1
        assert value(career, columns["LongestWinStreak_ALLONLINE"]) == 1
        assert value(career, columns["WinLossRatio_GDI_ALLONLINE"]) == 1.0
        assert value(career, columns["CareerInputCommands_ALLONLINE"]) == 0
        assert value(career, columns["AverageCareerInputCommands_RANKED1V1"]) == 0

    def test_disconnect_and_desync_count_as_losses(self):
        career = _fold(TW, [("unranked", "gdi", 3, 50, {}), ("unranked", "gdi", 4, 60, {})])
        total = career["unranked"]
        assert (total["losses"], total["disconnects"], total["desyncs"], total.get("wins", 0)) == (2, 1, 1, 0)


class TestSettling:
    @pytest.mark.parametrize("game", GAMES)
    def test_finalize_folds_once_and_rebuild_matches(self, db, game):
        sides = sorted(game.side_to_faction)
        players = [
            {"guid": guid(1), "side": sides[0], "result": 0, "counts": {"structures_built": 4}},
            {"guid": guid(2), "side": sides[1], "result": 1, "counts": {"units_lost": 7}},
        ]
        report = MatchReport.from_bytes(build_report(game, 2, players, duration=420), game_id=game.game_id)
        comp = create_competition_session(db, 1)
        args = (comp.csid, settle_players(report), report.get_db_game_type(), 420, game.game_id)
        assert finalize_match_from_report(db, *args, map_name="Test Map")
        assert not finalize_match_from_report(db, *args)

        match = db.exec(select(MatchHistory).where(MatchHistory.csid == comp.csid)).one()
        assert (match.game_id, match.mode, match.duration) == (game.game_id, "ranked_1v1", 420)
        winner = get_player_stats(db, 1, game.game_id)
        before = (json.dumps(winner.stats, sort_keys=True), get_player_level(db, 1, game.game_id).score)
        assert winner.stats["ranked_1v1"]["structures_built"] == 4
        assert get_player_stats(db, 2, game.game_id).stats["ranked_1v1"]["units_lost"] == 7
        assert before[1] == score_delta("ranked_1v1", True)
        assert get_player_level(db, 2, game.game_id).score == score_delta("ranked_1v1", False)
        assert winner.elo_ranked_1v1 > 1200

        assert cnc3_career.rebuild_careers(db, game) == 1
        db.expire_all()
        after = get_player_stats(db, 1, game.game_id)
        assert (json.dumps(after.stats, sort_keys=True), get_player_level(db, 1, game.game_id).score) == before
        assert after.elo_ranked_1v1 > 1200

    def test_a_failed_fold_applies_nothing_and_releases_the_claim(self, db, monkeypatch):
        players = [{"guid": guid(1), "side": 0, "result": 0}, {"guid": guid(2), "side": 2, "result": 1}]
        report = MatchReport.from_bytes(build_report(TW, 2, players), game_id=TW.game_id)
        comp = create_competition_session(db, 1)
        apply_player = cnc3_career._apply_player
        calls = []

        def fail_on_second_player(*args):
            calls.append(args)
            if len(calls) == 2:
                raise RuntimeError("injected failure")
            apply_player(*args)

        monkeypatch.setattr(cnc3_career, "_apply_player", fail_on_second_player)
        with pytest.raises(RuntimeError):
            finalize_match_from_report(db, comp.csid, settle_players(report), 1, 300, TW.game_id)
        db.expire_all()
        assert db.exec(select(MatchHistory)).all() == []
        assert get_player_stats(db, 1, TW.game_id) is None
        claim = db.exec(select(CompetitionSession).where(CompetitionSession.csid == comp.csid)).one()
        assert (claim.finalized, claim.status) == (False, "active")

        monkeypatch.setattr(cnc3_career, "_apply_player", apply_player)
        assert finalize_match_from_report(db, comp.csid, settle_players(report), 1, 300, TW.game_id)

    def test_record_match_ignores_a_stored_csid(self, db):
        assert cnc3_career.record_match(db, TW, "c1", "unranked", 60, []) is not None
        assert cnc3_career.record_match(db, KW, "c1", "unranked", 60, []) is None


class TestSake:
    @pytest.mark.parametrize("game", GAMES)
    def test_get_my_records_answers_every_column_by_name(self, db, game):
        sides = sorted(game.side_to_faction)
        faction = game.side_to_faction[sides[0]]
        players = [{"persona_id": 1, "result": 0, "faction": faction, "counts": {"units_killed": 6, "units_lost": 3}}]
        cnc3_career.record_match(db, game, "c1", "ranked_1v1", 300, players)
        db.commit()
        fields = list(SAKE_COLUMNS[game.game_id])
        values = cnc3_sake.get_my_records(db, game, 1, game.sake_table, fields)
        assert len(values) == len(fields)
        by_name = dict(zip(fields, values))
        for name, value in by_name.items():
            float_column = SAKE_COLUMNS[game.game_id][name].stat.sake_type == "float"
            assert (value.float_value is not None) == float_column, name
        assert by_name["CareerUnitsKilled_RANKED1V1"].int_value.value == 6
        assert by_name["UnitKillDeathRatio_RANKED1V1"].float_value.value == 2.0
        assert by_name["TotalTimePlayed_RANKED1V1"].int_value.value == 300

    def test_score_rank_and_rank_search(self, db):
        cnc3_career.record_match(db, TW, "c1", "ranked_1v1", 60, [{"persona_id": 2, "result": 0}])
        db.commit()
        score, rank = cnc3_sake.get_my_records(db, TW, 2, "PlayerStats_v5", ["Score", "Rank"])
        assert (score.int_value.value, rank.int_value.value) == (5, 2)
        rows = cnc3_sake.search(db, TW, "PlayerStats_v5", ["Rank", "ownerid"], filter_text="ownerid=2", sort="recordid")
        assert [[v.int_value.value for v in row] for row in rows] == [[2, 2]]

    def test_levels_and_scoring_multipliers(self, db):
        rows = cnc3_sake.search(db, KW, "Levels", ["Score"], filter_text="Level>0", sort="Level", max_rows=1000)
        assert len(rows) == 87 and rows[1][0].int_value.value == 5
        fields = ["UnrankedLosses", "UnrankedWins", "RankedLosses", "RankedWins"]
        (row,) = cnc3_sake.get_specific_records("ScoringMultipliers", [1], fields)
        assert [v.short_value.value for v in row] == [1, 2, 2, 5]

    def test_ratings_are_kept_per_game_and_found_by_the_game_s_search(self, db):
        match_values = [
            ("matchguid", "asciiStringValue", "guid-7"),
            ("compid", "intValue", "0"),
            ("mrating", "intValue", "4"),
            ("comrating", "intValue", "3"),
        ]
        sake_records.create_record(db, TW.game_id, 1, "RatingMatch", match_values)
        sake_records.create_record(db, TW.game_id, 1, "RatingMatch", [("matchguid", "asciiStringValue", "guid-8")])
        db.commit()
        fields = ["matchguid", "compid", "mrating", "comrating"]
        found = sake_records.search_records(
            sake_records.stored_records(db, TW.game_id, "RatingMatch"),
            fields,
            filter_text="matchguid='guid-7' and ownerid=1",
            sort="rate_datetime desc",
            max_rows=1,
        )
        assert [
            [v.ascii_string_value.value if v.ascii_string_value else v.int_value.value for v in r] for r in found
        ] == [["guid-7", 0, 4, 3]]
        assert sake_records.stored_records(db, KW.game_id, "RatingMatch") == []


class TestImport:
    def test_kane_s_wrath_import_takes_the_report_that_names_everyone(self, db, tmp_path):
        everyone = [
            {"guid": guid(1), "side": 1, "result": 0, "counts": {"units_built": 2}},
            {"guid": guid(2), "side": 9, "result": 3},
        ]
        saved = [
            ("a", build_report(KW, 1, [{"guid": guid(2), "side": 9, "result": 1}], ended=False), "2026-10-17T10:00:00"),
            ("b", build_report(KW, 1, everyone, duration=200), "2026-10-17T10:00:08"),
        ]
        for name, data, when in saved:
            (tmp_path / f"{name}.bin").write_bytes(data)
            (tmp_path / f"{name}.json").write_text(json.dumps({"csid": "kw1", "ccid": "", "save_time": when}))
        assert cnc3_import.import_saved_reports(db, KW, str(tmp_path)) == (1, 0)
        match = db.exec(select(MatchHistory).where(MatchHistory.csid == "kw1")).one()
        assert (match.mode, match.duration) == ("unranked", 200)
        assert [(p["persona_id"], p["faction"], p["result"]) for p in match.players] == [(1, "gdi", 0), (2, "scrin", 3)]
        assert cnc3_career.rebuild_careers(db, KW) == 1
        assert get_player_stats(db, 2, KW.game_id).stats["unranked"]["disconnects"] == 1
