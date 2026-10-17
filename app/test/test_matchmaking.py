"""
ELO ratings, the QuickMatch ladder the Kane's Wrath and Tiberium Wars clients read, and the RA3 matchbot's
search. All three use one rating per game and mode.
"""

import asyncio
import base64
import math

import pytest
from sqlalchemy import create_engine as _sa_create_engine
from sqlmodel import Session, SQLModel

import app.db.database as _db_module
from app.db.crud import create_competition_session, finalize_match_from_report, get_player_stats
from app.models.game_config import GAME_ID_KW, GAME_ID_TW
from app.models.ladder import LADDER_SIZE, SEARCH_WINDOW
from app.models.models import Persona, PlayerStats
from app.servers.automatch.games import ra3 as ra3_games
from app.servers.automatch.games.ra3 import RA3GameFactory
from app.soap.clan_service import kw_get_player_ladder_ratings, tw_get_player_ladder_ratings

RANKED_1V1 = 1
RANKED_2V2 = 2


@pytest.fixture
def db():
    engine = _sa_create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    SQLModel.metadata.create_all(engine)
    original = _db_module.engine
    _db_module.engine = engine
    with Session(engine) as session:
        for name in ("alpha", "bravo", "charlie", "delta"):
            session.add(Persona(name=name, user_id=1))
        session.commit()
        yield session
    _db_module.engine = original
    engine.dispose()


def set_rating(db, persona_id: int, game_id: int, mode: str, elo: int, games: int = 0):
    stats = get_player_stats(db, persona_id, game_id=game_id) or PlayerStats(persona_id=persona_id, game_id=game_id)
    setattr(stats, f"elo_{mode}", elo)
    setattr(stats, f"games_{mode}", games)
    db.add(stats)
    db.commit()


def rating(db, persona_id: int, game_id: int, mode: str) -> int:
    db.expire_all()
    return getattr(get_player_stats(db, persona_id, game_id=game_id), f"elo_{mode}")


def settle(db, results: dict[int, int], game_type: int, game_id: int = GAME_ID_KW) -> bool:
    comp = create_competition_session(db, 1)
    players = [{"persona_id": pid, "result": result, "faction": "", "counts": {}} for pid, result in results.items()]
    return finalize_match_from_report(db, comp.csid, players, game_type, 300, game_id)


class TestElo:
    def test_an_even_1v1(self, db):
        assert settle(db, {1: 0, 2: 1}, RANKED_1V1)
        assert (rating(db, 1, GAME_ID_KW, "ranked_1v1"), rating(db, 2, GAME_ID_KW, "ranked_1v1")) == (1220, 1180)

    def test_a_2v2_side_shares_its_expected_score(self, db):
        for pid, elo in ((1, 1800), (2, 1000), (3, 1400), (4, 1400)):
            set_rating(db, pid, GAME_ID_KW, "ranked_2v2", elo)
        assert settle(db, {1: 0, 2: 0, 3: 1, 4: 1}, RANKED_2V2)
        # Both sides average 1400: an even match, so every player moves by K/2.
        assert [rating(db, pid, GAME_ID_KW, "ranked_2v2") for pid in (1, 2, 3, 4)] == [1820, 1020, 1380, 1380]

    def test_modes_keep_separate_ratings(self, db):
        settle(db, {1: 0, 2: 1}, RANKED_2V2)
        assert rating(db, 1, GAME_ID_KW, "ranked_1v1") == 1200
        assert rating(db, 1, GAME_ID_KW, "ranked_2v2") == 1220

    def test_a_disconnect_loses_more(self, db):
        settle(db, {1: 0, 2: 3}, RANKED_1V1)
        assert rating(db, 2, GAME_ID_KW, "ranked_1v1") == 1170

    def test_a_desync_changes_no_rating(self, db):
        assert settle(db, {1: 0, 2: 4}, RANKED_1V1)
        stats = get_player_stats(db, 1, game_id=GAME_ID_KW)
        assert (stats.elo_ranked_1v1, stats.games_ranked_1v1) == (1200, 0)
        assert stats.stats["ranked_1v1"]["wins"] == 1

    def test_unranked_changes_no_rating(self, db):
        settle(db, {1: 0, 2: 1}, 0)
        assert get_player_stats(db, 1, game_id=GAME_ID_KW).games_ranked_1v1 == 0


def ticket(persona_id: int) -> str:
    return base64.b64encode(f"1|{persona_id}|test".encode()).decode()


def quickmatch_window(body: str, ladder_id: int) -> tuple[int, int]:
    """The rank window the QuickMatch menu builds from the ladder line, as QM_BuildStartRequest does."""
    tokens = body.strip(",").split(",")
    groups = {int(tokens[i]): tokens[i : i + 4] for i in range(0, len(tokens), 4)}
    total, rank = int(groups[ladder_id][1]), int(groups[ladder_id][2])
    return max(1, rank - math.ceil(total / 8)), min(total, rank + total // 8)


class TestQuickMatchLadder:
    def test_kane_s_wrath_reads_its_elo_as_the_rank(self, db):
        set_rating(db, 1, GAME_ID_KW, "ranked_1v1", 1350)
        set_rating(db, 1, GAME_ID_KW, "ranked_2v2", 1100)
        body = asyncio.run(kw_get_player_ladder_ratings(gp=ticket(1))).body.decode()
        assert body.startswith(f"52177,{LADDER_SIZE},1350,1350,52178,{LADDER_SIZE},1100,1100,52180,")
        assert quickmatch_window(body, 52177) == (1350 - SEARCH_WINDOW, 1350 + SEARCH_WINDOW)

    def test_tiberium_wars_ladders(self, db):
        set_rating(db, 2, GAME_ID_TW, "ranked_2v2", 1640)
        body = asyncio.run(tw_get_player_ladder_ratings(gp=ticket(2))).body.decode()
        assert body.startswith(f"43738,{LADDER_SIZE},1200,1200,43783,{LADDER_SIZE},1640,1640,")
        assert quickmatch_window(body, 43783) == (1240, 2040)

    def test_a_new_player_searches_around_the_initial_rating(self, db):
        body = asyncio.run(kw_get_player_ladder_ratings(gp="")).body.decode()
        assert quickmatch_window(body, 52177) == (800, 1600)


@pytest.fixture
def ra3_ratings(monkeypatch):
    ratings: dict[int, int] = {}
    monkeypatch.setattr(ra3_games, "ladder_elo", lambda profile_id, ladder_id: ratings[profile_id])
    return ratings


def queue(factory: RA3GameFactory, ratings: dict, players: list[tuple[int, int, str, str]]):
    """players: (profile id, rating, LadID, PointRange)."""
    pool = {}
    for n, (pid, elo, ladder, point_range) in enumerate(players):
        ratings[pid] = elo
        nick = f"p{pid}"
        infos = {
            "LadID": ladder,
            "NumPlayers": "2" if ladder == "1" else "4",
            "Maps": "1111",
            "PointRange": point_range,
        }
        if ladder == "3":
            infos["teammate1"] = f"p{pid + 1}" if n % 2 == 0 else f"p{pid - 1}"
        pool[nick] = factory.build_player(nick, pid, infos)
        pool[nick].queued_at = n
    return pool


class TestRa3Matchbot:
    def test_the_closest_ratings_meet(self, ra3_ratings):
        factory = RA3GameFactory()
        pool = queue(factory, ra3_ratings, [(1, 1200, "1", "400"), (2, 1900, "1", "1000"), (3, 1260, "1", "100")])
        ((players, message),) = factory.try_match(pool)
        assert {p.nickname for p in players} == {"p1", "p3"}
        assert " p1 0 -1 -1 0 -1 1200 " in message + " "

    def test_a_window_the_other_player_does_not_reach_blocks_the_match(self, ra3_ratings):
        factory = RA3GameFactory()
        pool = queue(factory, ra3_ratings, [(1, 1200, "1", "100"), (2, 1350, "1", "1000")])
        assert factory.try_match(pool) is None

    def test_random_2v2_balances_the_teams(self, ra3_ratings):
        factory = RA3GameFactory()
        pool = queue(
            factory,
            ra3_ratings,
            [(1, 1000, "2", "1000"), (2, 1500, "2", "1000"), (3, 1200, "2", "1000"), (4, 1300, "2", "1000")],
        )
        ((players, message),) = factory.try_match(pool)
        assert [p.points for p in players] == [1000, 1500, 1200, 1300]
        assert message.split()[-1] == "1" and message.split()[11] == "0"

    def test_team_2v2_pairs_the_closest_teams(self, ra3_ratings):
        factory = RA3GameFactory()
        pool = queue(
            factory,
            ra3_ratings,
            [
                (1, 1200, "3", "400"),
                (2, 1300, "3", "400"),
                (3, 2000, "3", "400"),
                (4, 2100, "3", "400"),
                (5, 1250, "3", "400"),
                (6, 1250, "3", "400"),
            ],
        )
        ((players, _),) = factory.try_match(pool)
        assert {p.nickname for p in players} == {"p1", "p2", "p5", "p6"}
