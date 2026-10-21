"""Tests for The Battle for Middle-earth: the matchbot, the servserv files, FESL Hello, the rooms and GameStats."""

import hashlib
from pathlib import Path
from unittest.mock import MagicMock, patch

from sqlalchemy import create_engine
from sqlmodel import Session, SQLModel

from app.db.crud import create_preauth_ticket, validate_and_consume_preauth_ticket
from app.models.fesl_types import CLIENT_STRING_MAP, HelloClient, HelloServer, MemcheckServer, client_data_var
from app.servers.automatch.cinfo_parser import parse_cinfo
from app.servers.automatch.games.bfme import BfmeGameFactory
from app.servers.fesl_handlers import FeslHandlers
from app.servers.fesl_server import parse_game_data
from app.servers.gamestats_server import GameStatsServer
from app.servers.query_master_parsing import create_rooms_by_game
from app.util.cipher import gs_chresp_num

SERVSERV = Path(__file__).parents[2] / "static" / "servserv" / "lotrbfme"
EXE_103 = "-1391131738"
INI_103 = "1352759826"
NO_RANK = (-1, 2147483647, 2147483647)


def cinfo(
    ip: int, exe: str = EXE_103, ini: str = INI_103, maps: str = "1111", ladder: tuple[int, int, int] = NO_RANK
) -> str:
    """Returns a CINFO with the keys of lotrbfme.exe, in its order. ladder is (Points, PointsMin, PointsMax)."""
    points, points_min, points_max = ladder
    return (
        f"\\CINFO\\Widen\\0\\LadID\\0\\LadPass\\0\\PointsMin\\{points_min}\\PointsMax\\{points_max}"
        f"\\Points\\{points}\\Discons\\10000\\DisconMax\\2147483647\\NumPlayers\\2\\PingMax\\1000\\Pings\\FFFF"
        f"\\IP\\{ip}\\Side\\-1\\Color\\-1\\NAT\\1\\EXE\\{exe}\\INI\\{ini}\\CMD\\-1\\Maps\\{maps}"
    )


def queue(factory: BfmeGameFactory, entries: list[tuple[str, str]]) -> dict:
    return {
        nick: factory.build_player(nick, profile_id, parse_cinfo(text))
        for profile_id, (nick, text) in enumerate(entries, start=1)
    }


class TestBfmeMatchbot:
    def test_matched_has_six_fields_per_player(self):
        factory = BfmeGameFactory()
        players = queue(factory, [("frodo", cinfo(0x0A000002)), ("sam", cinfo(0x0A000003))])

        [(matched, message)] = factory.try_match(players)

        tokens = message.split(" ")
        assert [p.nickname for p in matched] == ["frodo", "sam"]
        assert tokens[0] == "MBOT:MATCHED"
        assert len(tokens) == 3 + 6 * 2
        assert tokens[3:9] == ["frodo", str(0x0A000002), "-1", "-1", "1", "-1"]
        assert tokens[9:15] == ["sam", str(0x0A000003), "-1", "-1", "1", "-1"]

    def test_players_on_different_builds_do_not_meet(self):
        factory = BfmeGameFactory()
        players = queue(factory, [("frodo", cinfo(1)), ("sam", cinfo(2, exe="12345"))])

        assert factory.try_match(players) is None

    def test_players_on_the_same_build_meet(self):
        factory = BfmeGameFactory()
        players = queue(factory, [("frodo", cinfo(1)), ("sam", cinfo(2, ini="999")), ("pippin", cinfo(3))])

        [(matched, _)] = factory.try_match(players)

        assert sorted(p.nickname for p in matched) == ["frodo", "pippin"]

    def test_ranked_players_meet_inside_each_others_window(self):
        factory = BfmeGameFactory()
        players = queue(factory, [("frodo", cinfo(1, ladder=(7, 1, 20))), ("sam", cinfo(2, ladder=(9, 1, 20)))])

        [(_, message)] = factory.try_match(players)

        tokens = message.split(" ")
        assert (tokens[8], tokens[14]) == ("7", "9")

    def test_ranks_outside_each_others_window_do_not_meet(self):
        factory = BfmeGameFactory()
        players = queue(factory, [("frodo", cinfo(1, ladder=(10, 5, 15))), ("sam", cinfo(2, ladder=(100, 90, 110)))])

        assert factory.try_match(players) is None

    def test_a_widened_search_ignores_the_rank_window(self):
        factory = BfmeGameFactory()
        players = queue(factory, [("frodo", cinfo(1, ladder=(10, 5, 15))), ("sam", cinfo(2, ladder=(100, 90, 110)))])
        for player in players.values():
            factory.handle_extra_command("WIDEN", player)

        assert factory.try_match(players) is not None

    def test_a_widened_search_keeps_the_map_bitfield(self):
        factory = BfmeGameFactory()
        players = queue(factory, [("frodo", cinfo(1, maps="1100")), ("sam", cinfo(2, maps="0011"))])
        for player in players.values():
            factory.handle_extra_command("WIDEN", player)

        assert [p.map_bitset for p in players.values()] == ["1100", "0011"]
        assert factory.try_match(players) is None

    def test_a_player_without_checksums_is_not_matched(self):
        factory = BfmeGameFactory()
        players = queue(factory, [("frodo", cinfo(1, exe="")), ("sam", cinfo(2, exe=""))])

        assert factory.try_match(players) is None

    def test_a_ranked_player_does_not_meet_a_player_without_a_rank(self):
        factory = BfmeGameFactory()
        players = queue(factory, [("frodo", cinfo(1, ladder=(10, 5, 15))), ("sam", cinfo(2))])

        assert factory.try_match(players) is None

    def test_bot_waits_in_the_quickmatch_room(self):
        rooms = create_rooms_by_game()["lotrbme"]
        quickmatch = [room for room in rooms if room.hostname == "QuickMatch"]

        assert [(room.room_id, room.room_type) for room in quickmatch] == [(662, 0)]
        assert BfmeGameFactory.channels == ["#GPG!662"]


class TestServserv:
    def test_bot_profile_id_is_the_config_qmbot_id(self):
        config = (SERVSERV / "config.txt").read_text()
        qmbot = config.split("<QMBot>")[1].split("</QMBot>")[0]

        assert qmbot.strip().lower() == "id=" + BfmeGameFactory.username.split("|")[1]

    def test_config_is_long_enough_for_the_game(self):
        assert (SERVSERV / "config.txt").stat().st_size >= 100

    def test_every_release_finds_an_empty_patch_list(self):
        for version in range(65536, 65543):
            assert (SERVSERV / f"english-{version}.txt").read_bytes() == b""
        assert (SERVSERV / "maps-65536.txt").read_bytes() == b""
        assert (SERVSERV / "MOTD-english.txt").stat().st_size > 0


class TestFeslHello:
    def test_bfme_hello_with_the_reply_tag_is_a_client_hello(self):
        payload = b"TXN=Hello\nclientString=bfme\nsku=14744\nlocale=en_US\nclientVersion=1.0\nSDKVersion=2.0\n\0"
        packet = b"fsys" + bytes([0x80, 0, 0, 1]) + (12 + len(payload)).to_bytes(4, "big") + payload

        _, model = parse_game_data(packet)

        assert isinstance(model, HelloClient)
        assert model.clientString == "bfme"

    def test_bfme_gets_no_memcheck(self):
        client_data_var.set({"active_game": CLIENT_STRING_MAP["bfme"]})

        responses = FeslHandlers.handle_hello(HelloClient(txn="Hello", clientString="bfme"))

        assert [type(r) for r in responses] == [HelloServer]

    def test_other_games_still_get_memcheck(self):
        client_data_var.set({"active_game": CLIENT_STRING_MAP["cnc3-ep1-pc"]})

        responses = FeslHandlers.handle_hello(HelloClient(txn="Hello", clientString="cnc3-ep1-pc"))

        assert [type(r) for r in responses] == [HelloServer, MemcheckServer]


def bfme_stats_server() -> GameStatsServer:
    server = GameStatsServer()
    server._db_session = MagicMock()
    server.gamename = "lotrbme"
    server.authenticated_game = True
    return server


class TestGameStats:
    def test_auth_stores_the_game_name_in_lower_case(self):
        server = GameStatsServer()
        server._db_session = MagicMock()
        server.server_challenge = "CHALLENGE01"
        response = hashlib.md5(f"{gs_chresp_num('CHALLENGE01')}h3D7Lc".encode()).hexdigest()

        with patch("app.servers.gamestats_server.app_config") as config:
            config.game.gamekeys.get.return_value = "h3D7Lc"
            server._handle_auth({"gamename": "LOTRBME", "response": response, "id": "1"})

        assert server.gamename == "lotrbme"
        assert server._is_bfme_game()

    def test_getpd_returns_empty_data(self):
        result = bfme_stats_server()._handle_getpd({"pid": "5", "lid": "2", "id": "1"})

        assert result == "\\getpdr\\1\\lid\\2\\pid\\5\\mod\\0\\length\\0\\data\\\\final\\"

    def test_setpd_is_acknowledged_and_not_stored(self):
        server = bfme_stats_server()
        server.persona_id = 5
        server.authenticated_player = True

        with patch("app.servers.gamestats_server.create_or_update_generals_stats") as store:
            result = server._handle_setpd({"pid": "5", "lid": "2", "data": "\\wins0\\1", "id": "1"})

        store.assert_not_called()
        assert "\\setpdr\\1" in result
        assert "\\pid\\5" in result

    def test_authp_accepts_the_ticket_the_gamespy_login_used(self):
        engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
        SQLModel.metadata.create_all(engine)
        with Session(engine) as session:
            ticket = create_preauth_ticket(session, user_id=2, persona_id=7).ticket
            assert validate_and_consume_preauth_ticket(session, ticket) is not None
            server = bfme_stats_server()
            server._db_session = session

            result = server._handle_authp({"authtoken": ticket, "resp": "x", "lid": "2", "id": "1"})

        engine.dispose()
        assert "\\pauthr\\7" in result
        assert server.authenticated_player
