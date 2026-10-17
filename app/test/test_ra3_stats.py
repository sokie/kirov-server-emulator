"""
Tests for Red Alert 3 match reports, careers and Sake tables.

The two fixtures are the reports both clients sent after one 2-player unranked match:
persona 1 (Soviet) won, persona 2 (Allied) lost.
"""

import os
import struct
import uuid

import pytest
from sqlalchemy import create_engine as _sa_create_engine
from sqlmodel import Session, SQLModel, select

import app.db.crud as crud
import app.db.database as _db_module
from app.db import ra3_career, ra3_import
from app.db.crud import (
    create_competition_session,
    finalize_match_from_report,
    get_player_level,
    get_player_stats,
    set_report_intention,
)
from app.models.game_config import GAME_ID_RA, SAGE_LEVEL_THRESHOLDS
from app.models.match_report import Faction, MatchReport, get_player_key_name
from app.models.models import CompetitionSession, MatchHistory, Persona
from app.models.ra3_stats import (
    GT_TO_MODE,
    REPORT_STATS,
    SAKE_COLUMNS,
    player_key_name,
    score_delta,
)
from app.soap import ra3_sake
from app.soap.sake_filter import FilterError, compile_filter

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures", "ra3")


def _fixture(name: str) -> bytes:
    with open(os.path.join(FIXTURES, name), "rb") as f:
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


def build_report(gt: int, players: list[dict], duration: int = 300) -> bytes:
    """Builds an RA3 report for mode index gt with the given players."""
    roster = b"".join(p["guid"].bytes + struct.pack(">i", p.get("team", 0)) for p in players)
    auth = b"\0" * 16 * len(players)
    results = b"".join(struct.pack(">I", p["result"]) for p in players)
    game_values = [(72 + gt, "byte", 1), (61, "string", "Test Map"), (63, "string", "1.13"), (62, "int", duration)]
    game = b"".join(_value(*v) for v in game_values)
    player = b""
    player_keys = 0
    for i, p in enumerate(players):
        values = [(p["side"] * 5 + gt, "short", 1)]
        if i == 0:
            values.append((15 + gt, "int", duration))
        values += [(stat.report_base + gt, "int", p.get("counts", {}).get(stat.key, 0)) for stat in REPORT_STATS]
        player += struct.pack(">H", len(values)) + b"".join(_value(*v) for v in values)
        player_keys += len(values)
    header = struct.pack(">II16sIIHHHHHH", 2, 5, b"\0" * 16, 0, 1, len(players), 0, len(game_values), player_keys, 0, 0)
    lengths = struct.pack(">6i", len(roster), len(auth), len(results), len(game), len(player), 0)
    return header + lengths + roster + auth + results + game + player


def _guid(persona_id: int) -> uuid.UUID:
    return uuid.UUID(f"{persona_id:08x}-beef-cafe-0000-000000000000")


@pytest.fixture
def db():
    engine = _sa_create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    SQLModel.metadata.create_all(engine)
    original = _db_module.engine
    _db_module.engine = engine
    with Session(engine) as session:
        for name in ("alpha", "bravo", "charlie", "delta"):
            session.add(Persona(name=name))
        session.commit()
        yield session
    _db_module.engine = original
    engine.dispose()


class TestCapturedReports:
    def test_winner_report_decodes(self):
        report = MatchReport.from_bytes(_fixture("report_unranked_2p_winner.bin"), game_id=GAME_ID_RA)
        assert (report.protocol_version, report.developer_version) == (2, 5)
        assert report.flags == 1  # authoritative
        assert report.get_game_type_from_key() == 1
        assert report.get_ra3_mode() == "unranked"
        assert report.get_map_path() == "Battlebase Beta (2)"
        assert report.get_duration() == 167
        assert report.get_local_player_index() == 0

        players = report.get_player_list()
        assert [(p.persona_id, p.faction, p.result) for p in players] == [
            (1, Faction.SOVIET, 0),
            (2, Faction.ALLIED, 1),
        ]
        assert report.get_ra3_counts(0)["structures_built"] == 1
        assert report.get_ra3_counts(0)["structures_captured"] == 1
        assert report.get_ra3_counts(0)["units_built"] == 1
        assert sum(report.get_ra3_counts(1).values()) == 0

    def test_every_captured_key_has_a_name(self):
        for name in ("report_unranked_2p_winner.bin", "report_unranked_2p_loser.bin"):
            report = MatchReport.from_bytes(_fixture(name), game_id=GAME_ID_RA)
            gt = report.get_game_type_from_key()
            for section in report.player_section:
                for key in section:
                    assert not get_player_key_name(key, GAME_ID_RA, gt).startswith("unknown_"), key

    def test_loser_report_lists_its_own_player_first(self):
        report = MatchReport.from_bytes(_fixture("report_unranked_2p_loser.bin"), game_id=GAME_ID_RA)
        assert [p.persona_id for p in report.get_player_list()] == [2, 1]
        assert report.get_local_player_index() == 0


class TestReportKeys:
    @pytest.mark.parametrize("gt", sorted(GT_TO_MODE))
    def test_keys_are_unique_in_every_mode(self, gt):
        keys = [stat.report_base + gt for stat in REPORT_STATS] + [15 + gt] + [side * 5 + gt for side in range(3)]
        assert len(keys) == len(set(keys))
        names = {player_key_name(key, gt) for key in keys}
        assert len(names) == len(keys)

    def test_clan_2v2_sides_and_counts(self):
        players = [
            {"guid": _guid(1), "team": 1, "result": 0, "side": 0, "counts": {"units_killed": 7}},
            {"guid": _guid(2), "team": 1, "result": 0, "side": 1},
            {"guid": _guid(3), "team": 2, "result": 1, "side": 2, "counts": {"units_lost_value": 900}},
        ]
        report = MatchReport.from_bytes(build_report(5, players), game_id=GAME_ID_RA)
        assert report.get_ra3_mode() == "clan_2v2"
        assert [p.faction for p in report.get_player_list()] == [Faction.ALLIED, Faction.SOVIET, Faction.EMPIRE]
        assert report.get_ra3_counts(0)["units_killed"] == 7
        assert report.get_ra3_counts(2)["units_lost_value"] == 900
        assert report.get_local_player_index() == 0


class TestCareerFold:
    def test_streaks_ratios_and_factions(self):
        career: dict = {}
        for result in (0, 0, 1):
            career = ra3_career.fold_match(career, "ranked_1v1", "allied", result, 600, {"units_killed": 3})
        total = career["ranked_1v1"]
        assert (total["wins"], total["losses"], total["total_matches"]) == (2, 1, 3)
        assert (total["current_win_streak"], total["current_loss_streak"]) == (0, 1)
        assert (total["longest_win_streak"], total["longest_loss_streak"]) == (2, 1)
        assert total["units_killed"] == 9
        assert total["total_time_played"] == 1800 and total["avg_game_length"] == 600
        assert total["factions"]["allied"]["wins"] == 2

        column = SAKE_COLUMNS["WinLossRatio_ALLIED_RANKED1V1"]
        assert ra3_career.column_value(career, column) == 2.0
        assert ra3_career.column_value(career, SAKE_COLUMNS["UnitKillDeathRatio_RANKED1V1"]) == 9.0

    def test_disconnect_and_desync_count_as_losses(self):
        career = ra3_career.fold_match({}, "unranked", None, 3, 60, {})
        career = ra3_career.fold_match(career, "unranked", None, 4, 60, {})
        total = career["unranked"]
        assert (total["losses"], total["disconnects"], total["desyncs"]) == (2, 1, 1)
        assert "factions" not in total

    def test_score_delta_matches_scoring_multipliers(self):
        assert score_delta("unranked", True) == 2
        assert score_delta("unranked", False) == 1
        assert score_delta("ranked_2v2", True) == 5
        assert score_delta("clan_1v1", False) == 2


class TestMatchHistory:
    def _players(self):
        report = MatchReport.from_bytes(_fixture("report_unranked_2p_winner.bin"), game_id=GAME_ID_RA)
        players = [
            {"persona_id": p.persona_id, "result": p.result, "faction": p.faction, "full_id": p.full_id}
            for p in report.get_player_list()
        ]
        for i, p in enumerate(players):
            p["counts"] = report.get_ra3_counts(i)
        return report, players

    def test_finalize_folds_once_and_rebuild_matches(self, db):
        report, players = self._players()
        comp = create_competition_session(db, 1)
        assert finalize_match_from_report(db, comp.csid, players, report.get_db_game_type(), 167, GAME_ID_RA)
        assert not finalize_match_from_report(db, comp.csid, players, report.get_db_game_type(), 167, GAME_ID_RA)

        winner = get_player_stats(db, 1, GAME_ID_RA).stats["unranked"]
        loser = get_player_stats(db, 2, GAME_ID_RA).stats["unranked"]
        assert (winner["wins"], winner["structures_built"], winner["factions"]["soviet"]["wins"]) == (1, 1, 1)
        assert (loser["losses"], loser["factions"]["allied"]["losses"]) == (1, 1)
        assert get_player_level(db, 1, GAME_ID_RA).score == 2
        assert get_player_level(db, 2, GAME_ID_RA).score == 1
        assert len(db.exec(select(MatchHistory)).all()) == 1

        before = {pid: get_player_stats(db, pid, GAME_ID_RA).stats for pid in (1, 2)}
        assert ra3_career.rebuild_careers(db) == 1
        db.expire_all()
        assert {pid: get_player_stats(db, pid, GAME_ID_RA).stats for pid in (1, 2)} == before
        assert get_player_level(db, 1, GAME_ID_RA).score == 2

    def _assert_nothing_applied(self, db, csid):
        db.expire_all()
        assert db.exec(select(MatchHistory)).all() == []
        assert get_player_stats(db, 1, GAME_ID_RA) is None
        assert get_player_level(db, 1, GAME_ID_RA) is None
        claim = db.exec(select(CompetitionSession).where(CompetitionSession.csid == csid)).one()
        assert (claim.finalized, claim.status) == (False, "active")

    def test_a_failed_fold_applies_nothing_and_releases_the_claim(self, db, monkeypatch):
        report, players = self._players()
        comp = create_competition_session(db, 1)
        apply_player = ra3_career._apply_player
        calls = []

        def fail_on_second_player(*args):
            calls.append(args)
            if len(calls) == 2:
                raise RuntimeError("injected failure")
            apply_player(*args)

        monkeypatch.setattr(ra3_career, "_apply_player", fail_on_second_player)
        with pytest.raises(RuntimeError):
            finalize_match_from_report(db, comp.csid, players, report.get_db_game_type(), 167, GAME_ID_RA)
        self._assert_nothing_applied(db, comp.csid)

        monkeypatch.setattr(ra3_career, "_apply_player", apply_player)
        assert finalize_match_from_report(db, comp.csid, players, report.get_db_game_type(), 167, GAME_ID_RA)
        assert get_player_stats(db, 1, GAME_ID_RA).stats["unranked"]["wins"] == 1

    def test_a_failed_elo_update_rolls_back_the_fold(self, db, monkeypatch):
        _report, players = self._players()
        comp = create_competition_session(db, 1)
        update_player_elo = crud.update_player_elo
        calls = []

        def fail_on_second_player(*args, **kwargs):
            calls.append(args)
            if len(calls) == 2:
                raise RuntimeError("injected failure")
            return update_player_elo(*args, **kwargs)

        monkeypatch.setattr(crud, "update_player_elo", fail_on_second_player)
        with pytest.raises(RuntimeError):
            finalize_match_from_report(db, comp.csid, players, 1, 167, GAME_ID_RA)
        self._assert_nothing_applied(db, comp.csid)
        assert len(calls) == 2

        monkeypatch.setattr(crud, "update_player_elo", update_player_elo)
        assert finalize_match_from_report(db, comp.csid, players, 1, 167, GAME_ID_RA)
        stats = get_player_stats(db, 1, GAME_ID_RA)
        assert (stats.games_ranked_1v1, stats.stats["ranked_1v1"]["wins"]) == (1, 1)

    def test_record_match_ignores_a_stored_csid(self, db):
        _report, players = self._players()
        assert ra3_career.record_match(db, "csid-1", "unranked", 167, players) is not None
        assert ra3_career.record_match(db, "csid-1", "unranked", 167, players) is None
        assert get_player_stats(db, 1, GAME_ID_RA).stats["unranked"]["wins"] == 1

    def test_rank_follows_levels(self, db):
        players = [{"persona_id": 1, "result": 0, "faction": "japan", "counts": {}}]
        for n in range(3):
            ra3_career.record_match(db, f"csid-{n}", "ranked_1v1", 100, players)
        level = get_player_level(db, 1, GAME_ID_RA)
        assert level.score == 15
        assert level.rank == ra3_career.rank_from_score(15) == 3
        assert SAGE_LEVEL_THRESHOLDS[2] <= 15 < SAGE_LEVEL_THRESHOLDS[3]


class TestSake:
    def test_get_my_records_answers_every_column_by_name(self, db):
        ra3_career.record_match(
            db, "c1", "ranked_1v1", 120, [{"persona_id": 1, "result": 0, "faction": "soviet", "counts": {}}]
        )
        fields = list(SAKE_COLUMNS)
        values = ra3_sake.get_my_records(db, 1, "PlayerStats_v5", fields)
        assert len(values) == 190
        by_name = dict(zip(fields, values))
        assert by_name["CareerWins_SOVIET_RANKED1V1"].int_value.value == 1
        assert by_name["WinLossRatio_RANKED1V1"].float_value.value == 1.0
        assert by_name["TotalTimePlayed_RANKED1V1"].int_value.value == 120
        assert by_name["CareerWins_UNRANKED"].int_value.value == 0

        score_rank = ra3_sake.get_my_records(db, 1, "PlayerStats_v5", ["Score", "Rank"])
        assert [v.int_value.value for v in score_rank] == [5, 2]

    def test_new_player_reads_zeroes_and_rank_one(self, db):
        values = ra3_sake.get_my_records(db, 3, "PlayerStats_v5", ["Score", "Rank", "CareerWins_UNRANKED"])
        assert [v.int_value.value for v in values] == [0, 1, 0]

    def test_rank_search_by_ownerid(self, db):
        ra3_career.record_match(db, "c1", "clan_1v1", 60, [{"persona_id": 2, "result": 0, "counts": {}}])
        rows = ra3_sake.search(db, "PlayerStats_v5", ["Rank", "ownerid"], "ownerid=2", "recordid", 0, 1)
        assert [[v.int_value.value for v in row] for row in rows] == [[2, 2]]

    def test_levels_search(self, db):
        rows = ra3_sake.search(db, "Levels", ["Score"], "Level>0", "Level", 0, 1000)
        assert len(rows) == len(SAGE_LEVEL_THRESHOLDS)
        assert [rows[0][0].int_value.value, rows[1][0].int_value.value] == [0, 5]

    def test_sort_paging_and_surrounding(self, db):
        for pid, wins in ((1, 1), (2, 3), (3, 2)):
            for n in range(wins):
                ra3_career.record_match(db, f"c{pid}-{n}", "ranked_1v1", 60, [{"persona_id": pid, "result": 0}])
        fields = ["ownerid", "row"]
        rows = ra3_sake.search(db, "PlayerStats_v5", fields, "Score>0", "Score desc", 1, 1)
        assert [[v.int_value.value for v in row] for row in rows] == [[3, 2]]
        rows = ra3_sake.search(
            db, "PlayerStats_v5", fields, "Score>0", "Score desc", surrounding=1, target_filter="ownerid=3"
        )
        assert [[v.int_value.value for v in row] for row in rows] == [[2, 1], [3, 2], [1, 3]]

    def test_scoring_multipliers_by_field_name(self):
        rows = ra3_sake.get_specific_records("ScoringMultipliers", [1], ["RankedWins", "UnrankedLosses"])
        assert [v.short_value.value for v in rows[0]] == [5, 1]

    def test_bad_filter_raises(self):
        with pytest.raises(FilterError):
            compile_filter("Score >")


class TestReportIntention:
    def test_a_ccid_sent_again_stays_the_same(self, db):
        comp = create_competition_session(db, 1)
        first = set_report_intention(db, comp.csid, "", 1)
        again = set_report_intention(db, comp.csid, first.ccid, 1)
        assert again.ccid == first.ccid
        other = set_report_intention(db, comp.csid, first.ccid, 2)
        assert other.ccid != first.ccid


class TestImportSavedReports:
    def _save(self, folder, name, data, csid, ccid, time):
        (folder / f"{name}.bin").write_bytes(data)
        (folder / f"{name}.json").write_text(f'{{"csid": "{csid}", "ccid": "{ccid}", "save_time": "{time}"}}')

    def test_names_players_from_each_client_report(self, db, tmp_path):
        mac1, mac2 = uuid.uuid4(), uuid.uuid4()
        winner = bytearray(_fixture("report_unranked_2p_winner.bin"))
        loser = bytearray(_fixture("report_unranked_2p_loser.bin"))
        # Roster GUIDs the server did not mint: each client is first in its own report.
        winner[0x44:0x54], winner[0x58:0x68] = mac1.bytes, mac2.bytes
        loser[0x44:0x54], loser[0x58:0x68] = mac2.bytes, mac1.bytes
        self._save(
            tmp_path, "w", bytes(winner), "csid-old", "00000001-BEEF-CAFE-0000-000000000001", "2026-07-27T22:00:52"
        )
        self._save(
            tmp_path, "l", bytes(loser), "csid-old", "00000002-BEEF-CAFE-0000-000000000002", "2026-07-27T22:00:53"
        )

        assert ra3_import.import_saved_reports(db, str(tmp_path)) == (1, 0)
        assert ra3_import.import_saved_reports(db, str(tmp_path)) == (0, 1)
        assert get_player_stats(db, 1, GAME_ID_RA) is None

        assert ra3_career.rebuild_careers(db) == 1
        db.expire_all()
        assert get_player_stats(db, 1, GAME_ID_RA).stats["unranked"]["wins"] == 1
        assert get_player_stats(db, 2, GAME_ID_RA).stats["unranked"]["losses"] == 1
