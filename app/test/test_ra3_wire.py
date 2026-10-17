"""
RA3 requests as the game sends them, through the Sake and Competition routes.

The fixtures are SOAP bodies the game sent, with the login ticket and the certificate keys replaced.
"""

import asyncio
import os
import re
import xml.etree.ElementTree as ET

import pytest
from sqlalchemy import create_engine as _sa_create_engine
from sqlmodel import Session, SQLModel, select
from starlette.requests import Request

import app.db.database as _db_module
import app.soap.competition_service as competition_service
from app.db import ra3_career
from app.db.crud import get_player_stats
from app.models.game_config import GAME_ID_RA, SAGE_LEVEL_THRESHOLDS
from app.models.models import MatchHistory, Persona
from app.models.ra3_stats import SAKE_COLUMNS
from app.soap.competition_service import competition_handler
from app.soap.sake_service import sake_storage_handler

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures", "ra3")

# DIME record header before the report bytes: last record, ID "report", type "application/bin".
REPORT_RECORD = b"\x0a\x10\x00\x00\x00\x06\x00\x0f\x00\x00\x01\xc4report\x00\x00application/bin\x00"


def _fixture(name: str) -> bytes:
    with open(os.path.join(FIXTURES, name), "rb") as f:
        return f.read()


def _post(handler, action: str, body: bytes) -> str:
    async def receive():
        return {"type": "http.request", "body": body, "more_body": False}

    scope = {
        "type": "http",
        "method": "POST",
        "path": "/",
        "query_string": b"",
        "headers": [(b"soapaction", f'"{action}"'.encode())],
    }
    response = asyncio.run(handler(Request(scope, receive)))
    assert response.status_code == 200
    return response.body.decode("utf-8")


def _local(tag: str) -> str:
    return tag.split("}")[-1]


def _rows(xml: str) -> list[list[tuple[str, str]]]:
    """(value type, text) per RecordValue, per ArrayOfRecordValue."""
    root = ET.fromstring(xml)
    rows = []
    for array in root.iter():
        if _local(array.tag) != "ArrayOfRecordValue":
            continue
        row = []
        for record in array:
            typed = record[0]
            row.append((_local(typed.tag), typed[0].text or ""))
        rows.append(row)
    return rows


def _text(xml: str, tag: str) -> str:
    for node in ET.fromstring(xml).iter():
        if _local(node.tag) == tag:
            return node.text or ""
    return ""


@pytest.fixture
def db(tmp_path, monkeypatch):
    engine = _sa_create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    SQLModel.metadata.create_all(engine)
    monkeypatch.setattr(_db_module, "engine", engine)
    monkeypatch.setattr(competition_service, "REPORT_DIR", str(tmp_path))
    with Session(engine) as session:
        for name in ("test", "other"):
            session.add(Persona(name=name))
        session.commit()
        yield session
    engine.dispose()


class TestSakeRequests:
    def test_career_read_follows_the_request(self, db):
        request = _fixture("sake_getmyrecords_playerstats_v5.xml").decode()
        fields = re.findall(r"<ns1:string>(.*?)</ns1:string>", request)
        assert fields == list(SAKE_COLUMNS)

        ra3_career.record_match(db, "c1", "unranked", 167, [{"persona_id": 1, "result": 0, "faction": "soviet"}])
        db.commit()
        rows = _rows(_post(sake_storage_handler, "http://gamespy.net/sake/GetMyRecords", request.encode()))
        assert len(rows) == 1 and len(rows[0]) == 190
        by_field = dict(zip(fields, rows[0]))
        assert by_field["CareerWins_SOVIET_UNRANKED"] == ("intValue", "1")
        assert by_field["TotalTimePlayed_UNRANKED"] == ("intValue", "167")
        assert by_field["WinLossRatio_UNRANKED"][0] == "floatValue"
        assert sum(1 for kind, _ in rows[0] if kind == "floatValue") == 25

    def test_score_and_rank(self, db):
        body = _fixture("sake_getmyrecords_score_rank.xml")
        rows = _rows(_post(sake_storage_handler, "http://gamespy.net/sake/GetMyRecords", body))
        assert rows == [[("intValue", "0"), ("intValue", "1")]]

    def test_scoring_multipliers(self, db):
        body = _fixture("sake_getspecificrecords_scoringmultipliers.xml")
        rows = _rows(_post(sake_storage_handler, "http://gamespy.net/sake/GetSpecificRecords", body))
        assert rows == [[("shortValue", "1"), ("shortValue", "2"), ("shortValue", "2"), ("shortValue", "5")]]

    def test_levels(self, db):
        body = _fixture("sake_search_levels.xml")
        rows = _rows(_post(sake_storage_handler, "http://gamespy.net/sake/SearchForRecords", body))
        assert [int(row[0][1]) for row in rows] == SAGE_LEVEL_THRESHOLDS

    def test_rank_of_another_player(self, db):
        ra3_career.record_match(db, "c1", "ranked_1v1", 60, [{"persona_id": 2, "result": 0}])
        db.commit()
        body = _fixture("sake_search_playerstats_ownerid.xml")
        rows = _rows(_post(sake_storage_handler, "http://gamespy.net/sake/SearchForRecords", body))
        assert rows == [[("intValue", "2"), ("intValue", "2")]]


class TestCompetitionRequests:
    def test_session_intentions_and_report(self, db):
        created = _post(
            competition_handler, "http://gamespy.net/competition/CreateSession", _fixture("comp_createsession.xml")
        )
        csid = _text(created, "csid")
        assert csid and _text(created, "result") == "0"

        def intention(name: str, ccid: str) -> str:
            body = _fixture(name).decode().replace("Cb6pKEKzLyiEOGEBRyUarw", csid)
            body = re.sub(r"<gsc:ccid>[^<]*</gsc:ccid>", f"<gsc:ccid>{ccid}</gsc:ccid>", body)
            reply = _post(competition_handler, "http://gamespy.net/competition/SetReportIntention", body.encode())
            assert _text(reply, "result") == "0" and _text(reply, "csid") == csid
            return _text(reply, "ccid")

        first = intention("comp_setreportintention_1.xml", "")
        assert first.startswith("00000001-BEEF-CAFE-")
        assert intention("comp_setreportintention_2.xml", first) == first

        envelope = _fixture("comp_submitreport.xml").decode().replace("Cb6pKEKzLyiEOGEBRyUarw", csid)
        envelope = re.sub(r"<gsc:ccid>[^<]*</gsc:ccid>", f"<gsc:ccid>{first}</gsc:ccid>", envelope)
        body = envelope.encode() + REPORT_RECORD + _fixture("report_unranked_2p_winner.bin")
        reply = _post(competition_handler, "http://gamespy.net/competition/SubmitReport", body)
        assert _text(reply, "result") == "0"

        match = db.exec(select(MatchHistory).where(MatchHistory.csid == csid)).one()
        assert (match.mode, match.duration, match.map_name) == ("unranked", 167, "Battlebase Beta (2)")
        db.expire_all()
        assert get_player_stats(db, 1, GAME_ID_RA).stats["unranked"]["wins"] == 1
        assert get_player_stats(db, 2, GAME_ID_RA).stats["unranked"]["losses"] == 1
