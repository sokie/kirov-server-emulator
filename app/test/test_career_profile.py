"""
Tests for the player profile: the lifetime stats of every game, per mode and in total, and the page that shows them.
"""

import asyncio

import pytest
from sqlalchemy import create_engine as _sa_create_engine
from sqlmodel import Session, SQLModel
from starlette.requests import Request

from app.db import cnc3_career, ra3_career
from app.db.career_profile import MODES, career_profile, duration_text
from app.models.cnc3_stats import KW, TW
from app.models.game_config import GAME_ID_RA
from app.models.models import Persona
from app.web.routes import player_profile_page


@pytest.fixture
def db():
    engine = _sa_create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    SQLModel.metadata.create_all(engine)
    with Session(engine) as session:
        session.add(Persona(name="player", user_id=1))
        session.commit()
        yield session
    engine.dispose()


def _row(profile: dict, key: str) -> dict:
    """Returns one stat row of the profile as {mode: text}."""
    row = next(s for s in profile["stats"] if s["key"] == key)
    return dict(zip(MODES, row["values"]))


def _play(db: Session, matches: list[tuple]) -> None:
    for csid, mode, faction, result, duration, counts in matches:
        player = {"persona_id": 1, "result": result, "faction": faction, "counts": counts}
        cnc3_career.record_match(db, TW, csid, mode, duration, [player])
    db.commit()


class TestTotals:
    def test_all_online_adds_counts_and_keeps_streaks_in_match_order(self, db):
        _play(
            db,
            [
                ("c1", "ranked_1v1", "gdi", 0, 300, {"units_killed": 6, "units_lost": 3}),
                ("c2", "unranked", "nod", 0, 200, {"units_killed": 1}),
                ("c3", "ranked_1v1", "gdi", 0, 100, {"units_lost": 2}),
                ("c4", "unranked", "gdi", 1, 400, {}),
            ],
        )
        profile = career_profile(db, 1, TW.game_id)
        assert profile["total"] == profile["modes"][0]
        assert (profile["total"]["matches"], profile["total"]["wins"], profile["total"]["losses"]) == (4, 3, 1)
        assert profile["total"]["win_percent"] == 75.0

        # Three wins in a row across two modes: neither mode alone has a streak of three.
        longest = _row(profile, "longest_win_streak")
        assert (longest["all_online"], longest["ranked_1v1"], longest["unranked"]) == ("3", "2", "1")
        assert _row(profile, "current_loss_streak")["all_online"] == "1"
        assert _row(profile, "current_win_streak")["all_online"] == "0"

        assert _row(profile, "units_killed")["all_online"] == "7"
        assert _row(profile, "units_lost")["all_online"] == "5"
        assert _row(profile, "unit_kill_death_ratio")["all_online"] == "1.40"
        assert _row(profile, "win_loss_ratio")["all_online"] == "3.00"
        assert _row(profile, "win_loss_ratio")["unranked"] == "1.00"
        assert _row(profile, "total_time_played")["all_online"] == "16m 40s"
        assert _row(profile, "avg_game_length")["all_online"] == "4m 10s"
        assert _row(profile, "avg_game_length")["ranked_1v1"] == "3m 20s"
        assert (profile["time_played"], profile["avg_game_length"]) == ("16m 40s", "4m 10s")

        gdi = next(f for f in profile["factions"] if f["name"] == "GDI")
        assert (gdi["matches"], gdi["wins"], gdi["losses"], gdi["modes"]["ranked_1v1"]["wins"]) == (3, 2, 1, 2)
        assert profile["score"] == 5 + 2 + 5 + 1

    def test_kane_s_wrath_shows_parents_and_subfactions(self, db):
        for csid, faction in (("k1", "steel_talons"), ("k2", "zocom")):
            cnc3_career.record_match(
                db, KW, csid, "ranked_2v2", 60, [{"persona_id": 1, "result": 0, "faction": faction}]
            )
        db.commit()
        profile = career_profile(db, 1, KW.game_id)
        by_name = {f["name"]: f for f in profile["factions"]}
        assert by_name["GDI (all)"]["parent"] and by_name["GDI (all)"]["wins"] == 2
        assert by_name["Steel Talons"]["wins"] == 1 and by_name["ZOCOM"]["modes"]["ranked_2v2"]["wins"] == 1
        assert not any(s["key"] == "input_commands" for s in profile["stats"])

    def test_red_alert_3_lists_every_stat(self, db):
        ra3_career.record_match(db, "r1", "clan_1v1", 90, [{"persona_id": 1, "result": 0, "faction": "japan"}])
        db.commit()
        profile = career_profile(db, 1, GAME_ID_RA)
        assert len(profile["stats"]) == 27
        assert _row(profile, "total_matches")["clan_1v1"] == "1"
        assert profile["modes"][4]["elo"] == 1200

    def test_no_career_gives_none(self, db):
        assert career_profile(db, 1, TW.game_id) is None

    def test_duration_text(self):
        assert (duration_text(59), duration_text(3600 + 125)) == ("0m 59s", "1h 02m")


def test_the_profile_page_renders_every_game(db):
    _play(db, [("c1", "ranked_1v1", "scrin", 0, 300, {"structures_built": 4})])
    cnc3_career.record_match(db, KW, "k1", "unranked", 60, [{"persona_id": 1, "result": 1, "faction": "black_hand"}])
    ra3_career.record_match(db, "r1", "unranked", 90, [{"persona_id": 1, "result": 0, "faction": "soviet"}])
    db.commit()

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    scope = {"type": "http", "method": "GET", "path": "/players/1", "query_string": b"", "headers": []}
    response = asyncio.run(player_profile_page(Request(scope, receive), 1, db, None))
    html = response.body.decode("utf-8")
    assert response.status_code == 200
    for text in ("Lifetime Stats", "Structures built", "Black Hand", "Nod (all)", "Soviet", "All online"):
        assert text in html, text
