"""
Tiberium Wars and Kane's Wrath requests as the games send them, through the Sake and Competition routes.

The Sake fixtures are SOAP bodies the games sent. The Competition bodies are the RA3 ones with the game id changed:
the three games send the same Competition requests.
"""

import os
import re
import struct

import pytest
from sqlalchemy import create_engine as _sa_create_engine
from sqlmodel import Session, SQLModel, select

import app.db.database as _db_module
import app.soap.competition_service as competition_service
from app.db import cnc3_career
from app.db.crud import get_player_stats
from app.models.cnc3_stats import KW, SAKE_COLUMNS, TW
from app.models.game_config import SAGE_LEVEL_THRESHOLDS
from app.models.models import MatchHistory, Persona
from app.soap.competition_service import competition_handler
from app.soap.sake_service import sake_storage_handler
from app.test.test_cnc3_stats import build_report, guid
from app.test.test_ra3_wire import _post, _rows, _text

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")
SAKE = "http://gamespy.net/sake/"
COMPETITION = "http://gamespy.net/competition/"


def _fixture(folder: str, name: str) -> bytes:
    with open(os.path.join(FIXTURES, folder, name), "rb") as f:
        return f.read()


def _report_record(report: bytes) -> bytes:
    """The DIME record header before the report bytes: last record, ID "report", type "application/bin"."""
    return b"\x0a\x10\x00\x00\x00\x06\x00\x0f" + struct.pack(">I", len(report)) + b"report\0\0application/bin\0"


def _create_record(game_id: int, table: str, fields: list[tuple[str, str, str]]) -> bytes:
    values = "".join(
        f"<ns1:RecordField><ns1:name>{name}</ns1:name><ns1:value><ns1:{kind}><ns1:value>{text}</ns1:value>"
        f"</ns1:{kind}></ns1:value></ns1:RecordField>"
        for name, kind, text in fields
    )
    return (
        '<?xml version="1.0" encoding="UTF-8"?><SOAP-ENV:Envelope '
        'xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/" xmlns:ns1="http://gamespy.net/sake">'
        f"<SOAP-ENV:Body><ns1:CreateRecord><ns1:gameid>{game_id}</ns1:gameid><ns1:secretKey>E4F3HB</ns1:secretKey>"
        "<ns1:loginTicket>MXwxfHRlc3Q=</ns1:loginTicket>"
        f"<ns1:tableid>{table}</ns1:tableid><ns1:values>{values}</ns1:values></ns1:CreateRecord>"
        "</SOAP-ENV:Body></SOAP-ENV:Envelope>"
    ).encode()


@pytest.fixture
def db(tmp_path, monkeypatch):
    engine = _sa_create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    SQLModel.metadata.create_all(engine)
    monkeypatch.setattr(_db_module, "engine", engine)
    monkeypatch.setattr(competition_service, "REPORT_DIR", str(tmp_path))
    with Session(engine) as session:
        for name in ("test", "other"):
            session.add(Persona(name=name, user_id=1))
        session.commit()
        yield session
    engine.dispose()


class TestSakeRequests:
    @pytest.mark.parametrize(
        ("game", "name", "floats"),
        [(TW, "sake_getmyrecords_playerstats_v5.xml", 30), (KW, "sake_getmyrecords_playerstats_v100.xml", 96)],
    )
    def test_career_read_follows_the_request(self, db, game, name, floats):
        request = _fixture(game.name, name).decode()
        fields = re.findall(r"<ns1:string>(.*?)</ns1:string>", request)
        assert sorted(fields) == sorted(SAKE_COLUMNS[game.game_id])

        faction = game.side_to_faction[min(game.side_to_faction)]
        player = {"persona_id": 1, "result": 0, "faction": faction, "counts": {"structures_built": 3}}
        cnc3_career.record_match(db, game, "c1", "ranked_1v1", 300, [player])
        db.commit()
        rows = _rows(_post(sake_storage_handler, SAKE + "GetMyRecords", request.encode()))
        assert len(rows) == 1 and len(rows[0]) == len(fields)
        by_field = dict(zip(fields, rows[0]))
        assert by_field["CareerWins_RANKED1V1"] == ("intValue", "1")
        assert by_field["TotalTimePlayed_RANKED1V1"] == ("intValue", "300")
        assert by_field["CareerStructuresCreated_RANKED1V1"] == ("intValue", "3")
        assert by_field["CareerWins_GDI_RANKED1V1"] == ("intValue", "1")
        assert by_field["WinLossRatio_RANKED1V1"] == ("floatValue", "1.0")
        assert sum(1 for kind, _ in rows[0] if kind == "floatValue") == floats

    @pytest.mark.parametrize("game", [TW, KW])
    def test_score_rank_multipliers_and_levels(self, db, game):
        rows = _rows(
            _post(sake_storage_handler, SAKE + "GetMyRecords", _fixture(game.name, "sake_getmyrecords_score_rank.xml"))
        )
        assert rows == [[("intValue", "0"), ("intValue", "1")]]
        body = _fixture(game.name, "sake_getspecificrecords_scoringmultipliers.xml")
        rows = _rows(_post(sake_storage_handler, SAKE + "GetSpecificRecords", body))
        assert rows == [[("shortValue", "1"), ("shortValue", "2"), ("shortValue", "2"), ("shortValue", "5")]]
        rows = _rows(
            _post(sake_storage_handler, SAKE + "SearchForRecords", _fixture(game.name, "sake_search_levels.xml"))
        )
        assert [int(row[0][1]) for row in rows] == SAGE_LEVEL_THRESHOLDS

    def test_news_ticker_and_ticker_settings(self, db):
        rows = _rows(
            _post(sake_storage_handler, SAKE + "SearchForRecords", _fixture("tw", "sake_search_newsticker.xml"))
        )
        assert (
            rows and rows[0][0][0] == "unicodeStringValue" and rows[0][1:] == [("intValue", "0"), ("shortValue", "1")]
        )
        body = _fixture("tw", "sake_getspecificrecords_tickermgmt.xml")
        rows = _rows(_post(sake_storage_handler, SAKE + "GetSpecificRecords", body))
        assert [kind for kind, _ in rows[0]] == ["floatValue", "shortValue", "floatValue", "floatValue", "floatValue"]

    def test_a_player_rating_comes_back_from_the_game_s_search(self, db):
        search = _fixture("tw", "sake_search_ratingplayer.xml")
        assert _rows(_post(sake_storage_handler, SAKE + "SearchForRecords", search)) == []

        fields = [
            ("matchguid", "asciiStringValue", "guid-1"),
            ("pid", "intValue", "2"),
            ("skrating", "intValue", "4"),
            ("ssrating", "intValue", "5"),
        ]
        created = _post(sake_storage_handler, SAKE + "CreateRecord", _create_record(TW.game_id, "RatingPlayer", fields))
        assert _text(created, "CreateRecordResult") == "Success" and int(_text(created, "recordid")) > 0

        rows = _rows(_post(sake_storage_handler, SAKE + "SearchForRecords", search))
        assert rows == [[("asciiStringValue", "guid-1"), ("intValue", "2"), ("intValue", "4"), ("intValue", "5")]]

    def test_an_operation_no_game_sends_is_a_fault(self, db):
        body = _create_record(TW.game_id, "RatingPlayer", []).replace(b"CreateRecord", b"DeleteRecord")
        with pytest.raises(AssertionError):
            _post(sake_storage_handler, SAKE + "DeleteRecord", body)


class TestCompetitionRequests:
    def _session(self, game_id: int) -> tuple[str, str]:
        created = _post(competition_handler, COMPETITION + "CreateSession", _fixture("ra3", "comp_createsession.xml"))
        csid = _text(created, "csid")
        body = _fixture("ra3", "comp_setreportintention_1.xml").decode().replace("Cb6pKEKzLyiEOGEBRyUarw", csid)
        body = re.sub(r"<gsc:ccid>[^<]*</gsc:ccid>", "<gsc:ccid></gsc:ccid>", body)
        reply = _post(competition_handler, COMPETITION + "SetReportIntention", body.encode())
        return csid, _text(reply, "ccid")

    def _submit(self, game_id: int, csid: str, ccid: str, report: bytes) -> None:
        envelope = _fixture("ra3", "comp_submitreport.xml").decode().replace("Cb6pKEKzLyiEOGEBRyUarw", csid)
        envelope = re.sub(r"<gsc:ccid>[^<]*</gsc:ccid>", f"<gsc:ccid>{ccid}</gsc:ccid>", envelope)
        envelope = envelope.replace("<gsc:gameid>2128</gsc:gameid>", f"<gsc:gameid>{game_id}</gsc:gameid>")
        reply = _post(
            competition_handler, COMPETITION + "SubmitReport", envelope.encode() + _report_record(report) + report
        )
        assert _text(reply, "result") == "0"

    def test_a_tiberium_wars_report_settles_the_match(self, db):
        csid, ccid = self._session(TW.game_id)
        players = [
            {"guid": guid(1), "side": 0, "result": 0, "counts": {"units_killed": 4}},
            {"guid": guid(2), "side": 2, "result": 1, "counts": {"units_lost": 4}},
        ]
        self._submit(TW.game_id, csid, ccid, build_report(TW, 2, players, duration=342))

        match = db.exec(select(MatchHistory).where(MatchHistory.csid == csid)).one()
        assert (match.game_id, match.mode, match.duration, match.map_name) == (
            TW.game_id,
            "ranked_1v1",
            342,
            "Test Map",
        )
        db.expire_all()
        assert get_player_stats(db, 1, TW.game_id).stats["ranked_1v1"]["units_killed"] == 4
        assert get_player_stats(db, 2, TW.game_id).stats["ranked_1v1"]["factions"]["scrin"]["losses"] == 1

    def test_kane_s_wrath_settles_from_the_report_that_names_everyone(self, db):
        csid, ccid = self._session(KW.game_id)
        leaver = [{"guid": guid(2), "side": 5, "result": 1}]
        self._submit(KW.game_id, csid, ccid, build_report(KW, 1, leaver, ended=False))
        assert db.exec(select(MatchHistory).where(MatchHistory.csid == csid)).first() is None

        everyone = [{"guid": guid(1), "side": 3, "result": 0}, {"guid": guid(2), "side": 5, "result": 3}]
        self._submit(KW.game_id, csid, ccid, build_report(KW, 1, everyone, duration=95))
        match = db.exec(select(MatchHistory).where(MatchHistory.csid == csid)).one()
        assert (match.mode, match.duration) == ("unranked", 95)
        db.expire_all()
        winner = get_player_stats(db, 1, KW.game_id).stats
        assert winner["unranked"]["parents"]["gdi"]["wins"] == 1
        assert winner["all_online"]["factions"]["steel_talons"]["wins"] == 1
        assert get_player_stats(db, 2, KW.game_id).stats["unranked"]["disconnects"] == 1
