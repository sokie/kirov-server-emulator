"""
Tests for app/servers/gamestats_server.py

Covers:
- _parse_request: basic KV, length-delimited JSON (RA3/CNC3),
  length-delimited KV with embedded backslashes (Generals/ZH),
  and null-byte handling from the live game payload
- _format_response / _format_error
- _is_generals_game routing flag
- _handle_auth: game challenge-response validation
- _handle_authp: two paths — authtoken (RA3/CNC3) and pid (Generals/ZH)
- _handle_getpd: auth guards, routing, Generals KV and RA3 JSON variants
- _handle_setpd: auth guards, pid ownership check, routing, both variants
- _handle_newgame / _handle_updgame: acknowledgment
- Live data: actual setpd payload from the log verifies honors and routing

RA3/CNC3 compatibility is explicitly tested so future Generals changes cannot
silently break JSON-based games.
"""

import hashlib
import json
from datetime import datetime
from unittest.mock import MagicMock, patch

from app.servers.gamestats_server import GameStatsServer
from app.util.cipher import gs_chresp_num, gs_xor

# =============================================================================
# Constants
# =============================================================================

_GAMESPY_KEY = b"GameSpy3D"

# Actual Generals/ZH setpd data payload from a live game (player 3, lost as
# AmericaLaserGeneral index 6). Ends with C-string null byte \x00.
LIVE_GENERALS_SETPD_DATA = (
    "\\losses6\\1\\games6\\1\\duration6\\3\\unitsLost6\\1\\unitsBuilt6\\1"
    "\\buildingsLost6\\1\\buildingsBuilt6\\1"
    "\\discons0\\0\\discons1\\0\\discons2\\0\\discons3\\0\\discons4\\0"
    "\\discons5\\0\\discons6\\0\\discons7\\0\\discons8\\0\\discons9\\0"
    "\\discons10\\0\\discons11\\0\\discons12\\0\\discons13\\0\\discons14\\0"
    "\\gamesOf2p6\\1\\customGames6\\1\\random\\1\\systemSpec\\LOD2\\fps\\1216.1"
    "\\lastGeneral\\6\\genInRow\\2\\builtCannon\\0\\builtNuke\\0\\builtSCUD\\0"
    "\\WinRow\\0\\LossRow\\1\\LossRowMax\\1\\DCRow\\0\\DSRow\\0\x00"
)

# Minimal RA3 stats JSON that mirrors what the game sends in setpd
LIVE_RA3_SETPD_JSON = json.dumps(
    {
        "wins_ranked_1v1": 5,
        "losses_ranked_1v1": 2,
        "wins_ranked_2v2": 1,
        "losses_ranked_2v2": 0,
        "disconnects_ranked_1v1": 0,
        "total_matches_online": 8,
    }
)


# =============================================================================
# Test infrastructure
# =============================================================================


class MockTransport:
    """Captures bytes written by the server."""

    def __init__(self):
        self.written: list[bytes] = []
        self.closed = False

    def write(self, data: bytes):
        self.written.append(data)

    def get_extra_info(self, key):
        if key == "peername":
            return ("127.0.0.1", 12345)
        return None

    def close(self):
        self.closed = True

    @property
    def last_response_text(self) -> str:
        """Decode and return the most recent XOR-encrypted response."""
        if not self.written:
            return ""
        data = self.written[-1]
        # The server appends b"\\final\\" (7 bytes) in plaintext after XOR payload
        payload = data[:-7]
        return gs_xor(payload).decode("latin-1") + "\\final\\"

    def last_response_kv(self) -> dict[str, str]:
        """Parse the most recent response into a key-value dict."""
        text = self.last_response_text.replace("\\final\\", "").strip("\\")
        if not text:
            return {}
        parts = text.split("\\")
        result: dict[str, str] = {}
        for i in range(0, len(parts) - 1, 2):
            if parts[i]:
                result[parts[i]] = parts[i + 1]
        return result


def _make_server(gamename: str | None = None) -> tuple[GameStatsServer, MockTransport]:
    """Create a GameStatsServer with a mock transport and mocked DB session."""
    server = GameStatsServer()
    transport = MockTransport()
    server.transport = transport
    server.peername = ("127.0.0.1", 12345)
    server._db_session = MagicMock()  # prevent real DB connection

    if gamename is not None:
        server.gamename = gamename
        server.authenticated_game = True

    return server, transport


def _authed_server(gamename: str, pid: int) -> tuple[GameStatsServer, MockTransport]:
    """Server authenticated as both game and player."""
    server, transport = _make_server(gamename)
    server.persona_id = pid
    server.authenticated_player = True
    return server, transport


# =============================================================================
# Request parsing
# =============================================================================


class TestParseRequest:
    """_parse_request handles both plain KV and length-delimited data fields."""

    def setup_method(self):
        self.server, _ = _make_server()

    def test_basic_kv_no_data_field(self):
        result = self.server._parse_request("\\ka\\\\id\\1\\final\\")
        assert result.get("ka") == ""
        assert result.get("id") == "1"

    def test_final_marker_stripped(self):
        result = self.server._parse_request("\\pid\\42\\final\\")
        assert "pid" in result
        assert "final" not in result

    def test_empty_value_preserved(self):
        result = self.server._parse_request("\\authp\\\\pid\\99\\final\\")
        assert result.get("authp") == ""
        assert result.get("pid") == "99"

    # --- Length-delimited data field (RA3/CNC3: JSON, no internal backslashes) ---

    def test_ra3_json_data_field_parsed(self):
        payload = '{"wins":3}'
        msg = f"\\setpd\\\\pid\\1\\length\\{len(payload)}\\data\\{payload}\\final\\"
        result = self.server._parse_request(msg)
        assert result.get("data") == payload
        assert result.get("length") == str(len(payload))
        assert result.get("pid") == "1"

    def test_ra3_json_keys_outside_data_still_parsed(self):
        payload = '{"wins":1}'
        msg = f"\\setpd\\\\pid\\7\\lid\\0\\length\\{len(payload)}\\data\\{payload}\\final\\"
        result = self.server._parse_request(msg)
        assert result.get("pid") == "7"
        assert result.get("lid") == "0"
        assert result.get("data") == payload

    # --- Length-delimited data field (Generals/ZH: KV with backslashes) ---

    def test_generals_kv_data_field_parsed(self):
        # The data field itself contains backslashes — this is the Generals format
        payload = "\\wins8\\1\\losses6\\1\\"
        msg = f"\\setpd\\\\pid\\3\\length\\{len(payload)}\\data\\{payload}\\final\\"
        result = self.server._parse_request(msg)
        assert result.get("data") == payload
        assert result.get("pid") == "3"

    def test_generals_data_field_exact_length_respected(self):
        # Keys embedded INSIDE the data blob must not become top-level keys,
        # even though they look like valid KV pairs.
        inner = "\\hidden\\value\\"
        payload = "\\wins8\\1\\" + inner
        msg = f"\\setpd\\\\length\\{len(payload)}\\data\\{payload}\\final\\"
        result = self.server._parse_request(msg)
        assert result.get("data") == payload
        assert "hidden" not in result
        assert "wins8" not in result

    def test_generals_live_setpd_payload_parsed(self):
        """Full live setpd payload (including null byte) is parsed correctly."""
        data = LIVE_GENERALS_SETPD_DATA
        msg = f"\\setpd\\\\pid\\3\\length\\{len(data)}\\data\\{data}\\final\\"
        result = self.server._parse_request(msg)
        assert result.get("pid") == "3"
        assert result.get("data") == data
        assert result.get("length") == str(len(data))

    def test_zero_length_data_field(self):
        msg = "\\setpd\\\\pid\\1\\length\\0\\data\\\\final\\"
        result = self.server._parse_request(msg)
        assert result.get("data") == ""
        assert result.get("length") == "0"


# =============================================================================
# Response formatting
# =============================================================================


class TestFormatResponse:
    def setup_method(self):
        self.server, _ = _make_server()

    def test_format_response_ends_with_final(self):
        assert self.server._format_response({"lc": "2"}).endswith("\\final\\")

    def test_format_response_contains_all_keys(self):
        r = self.server._format_response({"lc": "2", "sesskey": "123"})
        assert "\\lc\\2" in r
        assert "\\sesskey\\123" in r

    def test_format_error_structure(self):
        r = self.server._format_error("bad request", "5")
        assert "\\error\\" in r
        assert "\\errmsg\\bad request" in r
        assert "\\id\\5" in r
        assert r.endswith("\\final\\")

    def test_send_response_xor_encrypts(self):
        server, transport = _make_server()
        server._send_response("\\ka\\\\final\\")
        assert len(transport.written) == 1
        raw = transport.written[0]
        # last 7 bytes should be plaintext \final\
        assert raw.endswith(b"\\final\\")
        # payload is NOT plaintext
        payload = raw[:-7]
        assert payload != b"\\ka\\"
        # but XOR decode gives back the original
        assert gs_xor(payload) == b"\\ka\\"

    def test_send_response_roundtrip(self):
        server, transport = _make_server()
        original = "\\lc\\2\\sesskey\\999\\"
        server._send_response(original + "\\final\\")
        decoded = transport.last_response_text
        assert "\\lc\\2" in decoded
        assert "\\sesskey\\999" in decoded


# =============================================================================
# Game detection
# =============================================================================


class TestIsGeneralsGame:
    def test_ccgenzh_is_generals(self):
        server, _ = _make_server("ccgenzh")
        assert server._is_generals_game()

    def test_ccgenerals_is_generals(self):
        server, _ = _make_server("ccgenerals")
        assert server._is_generals_game()

    def test_redalert3pc_is_not_generals(self):
        server, _ = _make_server("redalert3pc")
        assert not server._is_generals_game()

    def test_cnc3pc_is_not_generals(self):
        server, _ = _make_server("cnc3pc")
        assert not server._is_generals_game()

    def test_cncra3pc_is_not_generals(self):
        server, _ = _make_server("cncra3pc")
        assert not server._is_generals_game()

    def test_no_gamename_is_not_generals(self):
        server, _ = _make_server()
        assert not server._is_generals_game()


# =============================================================================
# _handle_auth
# =============================================================================


class TestHandleAuth:
    """Game authentication via challenge-response."""

    def _compute_response(self, challenge: str, gamekey: str) -> str:
        chresp = gs_chresp_num(challenge)
        return hashlib.md5(f"{chresp}{gamekey}".encode()).hexdigest()

    def test_auth_success_sets_authenticated_game(self):
        server, _ = _make_server()
        server.server_challenge = "TESTCHALLNG"
        self._handle_auth_with(server, "ccgenzh", "testkey123")
        assert server.authenticated_game
        assert server.gamename == "ccgenzh"

    def _handle_auth_with(self, server, gamename, gamekey):
        challenge = server.server_challenge
        response = self._compute_response(challenge, gamekey)

        with patch("app.servers.gamestats_server.app_config") as mock_cfg:
            mock_cfg.game.gamekeys.get.return_value = gamekey
            return server._handle_auth({"gamename": gamename, "response": response, "id": "1"})

    def test_auth_success_response_contains_sesskey(self):
        server, _ = _make_server()
        server.server_challenge = "CHALLENGE01"
        result = self._handle_auth_with(server, "ccgenzh", "key1")
        assert "\\sesskey\\" in result
        assert "\\lc\\2" in result

    def test_auth_wrong_response_is_rejected(self):
        server, _ = _make_server()
        server.server_challenge = "CHALLENGE01"

        with patch("app.servers.gamestats_server.app_config") as mock_cfg:
            mock_cfg.game.gamekeys.get.return_value = "realkey"
            result = server._handle_auth({"gamename": "ccgenzh", "response": "wronghash", "id": "1"})

        assert "\\error\\" in result
        assert not server.authenticated_game

    def test_auth_missing_gamename_returns_error(self):
        server, _ = _make_server()
        with patch("app.servers.gamestats_server.app_config"):
            result = server._handle_auth({"response": "abc", "id": "1"})
        assert "\\error\\" in result

    def test_auth_unknown_game_returns_error(self):
        server, _ = _make_server()
        with patch("app.servers.gamestats_server.app_config") as mock_cfg:
            mock_cfg.game.gamekeys.get.return_value = ""
            result = server._handle_auth({"gamename": "unknowngame", "response": "abc", "id": "1"})
        assert "\\error\\" in result

    def test_auth_ra3_game_accepted(self):
        server, _ = _make_server()
        server.server_challenge = "RACH00001"
        result = self._handle_auth_with(server, "redalert3pc", "ra3key")
        assert "\\sesskey\\" in result
        assert server.gamename == "redalert3pc"


# =============================================================================
# _handle_authp
# =============================================================================


class TestHandleAuthp:
    """Player authentication — two paths: authtoken (RA3) and pid (Generals)."""

    def test_generals_pid_path_succeeds(self):
        server, _ = _make_server("ccgenzh")
        result = server._handle_authp({"pid": "42", "lid": "0", "id": "1"})
        assert "\\pauthr\\42" in result
        assert "\\lid\\0" in result
        assert server.authenticated_player
        assert server.persona_id == 42

    def test_generals_pid_path_invalid_pid_returns_error(self):
        server, _ = _make_server("ccgenzh")
        result = server._handle_authp({"pid": "notanumber", "lid": "0", "id": "1"})
        assert "\\error\\" in result
        assert not server.authenticated_player

    def test_ra3_authtoken_path_success(self):
        server, _ = _make_server("redalert3pc")
        mock_ticket_result = (100, 200, "ticket_data")

        with patch("app.servers.gamestats_server.validate_and_consume_preauth_ticket") as mock_v:
            mock_v.return_value = mock_ticket_result
            result = server._handle_authp({"authtoken": "valid_token", "lid": "1", "id": "1"})

        assert "\\pauthr\\200" in result
        assert server.authenticated_player
        assert server.persona_id == 200

    def test_ra3_authtoken_path_invalid_token(self):
        server, _ = _make_server("redalert3pc")

        with patch("app.servers.gamestats_server.validate_and_consume_preauth_ticket") as mock_v:
            mock_v.return_value = None
            result = server._handle_authp({"authtoken": "bad_token", "lid": "1", "id": "1"})

        assert "\\pauthr\\-1" in result
        assert not server.authenticated_player

    def test_missing_both_authtoken_and_pid_returns_error(self):
        server, _ = _make_server("ccgenzh")
        result = server._handle_authp({"lid": "0", "id": "1"})
        assert "\\error\\" in result

    def test_lid_echoed_in_response(self):
        server, _ = _make_server("ccgenzh")
        result = server._handle_authp({"pid": "7", "lid": "3", "id": "1"})
        assert "\\lid\\3" in result


# =============================================================================
# _handle_getpd — auth guards and routing
# =============================================================================


class TestHandleGetpd:
    def test_getpd_requires_game_auth(self):
        server, transport = _make_server()
        server.authenticated_game = False
        server._process_message("\\getpd\\\\pid\\1\\lid\\0\\id\\1\\final\\")
        kv = transport.last_response_kv()
        assert "error" in kv

    def test_getpd_missing_pid_returns_error(self):
        server, transport = _make_server("ccgenzh")
        server._process_message("\\getpd\\\\lid\\0\\id\\1\\final\\")
        kv = transport.last_response_kv()
        assert "error" in kv

    def test_getpd_invalid_pid_returns_error(self):
        server, transport = _make_server("ccgenzh")
        server._process_message("\\getpd\\\\pid\\notanumber\\lid\\0\\id\\1\\final\\")
        kv = transport.last_response_kv()
        assert "error" in kv

    def test_getpd_routes_generals_to_kv_handler(self):
        server, transport = _make_server("ccgenzh")
        with patch.object(server, "_handle_getpd_generals", return_value="\\getpdr\\1\\final\\") as mock_h:
            server._handle_getpd({"pid": "1", "lid": "0", "id": "1"})
        mock_h.assert_called_once()

    def test_getpd_routes_ra3_to_json_handler(self):
        server, transport = _make_server("redalert3pc")
        with patch.object(server, "_handle_getpd_json", return_value="\\getpdr\\1\\final\\") as mock_h:
            server._handle_getpd({"pid": "1", "lid": "0", "id": "1"})
        mock_h.assert_called_once()

    def test_getpd_cnc3_routes_to_json_handler(self):
        server, transport = _make_server("cnc3pc")
        with patch.object(server, "_handle_getpd_json", return_value="\\getpdr\\1\\final\\") as mock_h:
            server._handle_getpd({"pid": "1", "lid": "0", "id": "1"})
        mock_h.assert_called_once()


# =============================================================================
# _handle_getpd_generals
# =============================================================================


class TestHandleGetpdGenerals:
    """Generals/ZH getpd: returns raw KV data with injected battle and rank."""

    def _make_fake_stats(self, raw_data: str, battle_honors: int = 65536):
        stats = MagicMock()
        stats.raw_data = raw_data
        stats.battle_honors = battle_honors
        stats.updated_at = datetime(2026, 3, 3, 17, 11, 9)
        return stats

    def test_no_existing_stats_returns_empty_data(self):
        server, transport = _make_server("ccgenzh")
        with patch("app.servers.gamestats_server.get_generals_player_stats", return_value=None):
            response = server._handle_getpd_generals(3, "0", "1", {})
        assert "\\length\\0" in response
        assert "\\getpdr\\1" in response

    def test_existing_stats_injects_battle_honors(self):
        server, transport = _make_server("ccgenzh")
        raw = "\\wins8\\1\\lastGeneral\\8\\"
        fake_stats = self._make_fake_stats(raw, battle_honors=65536)

        with patch("app.servers.gamestats_server.get_generals_player_stats", return_value=fake_stats):
            response = server._handle_getpd_generals(1, "0", "1", {})

        assert "\\battle\\65536" in response

    def test_existing_stats_injects_rank(self):
        server, transport = _make_server("ccgenzh")
        raw = "\\wins8\\1\\"
        fake_stats = self._make_fake_stats(raw)

        with patch("app.servers.gamestats_server.get_generals_player_stats", return_value=fake_stats):
            response = server._handle_getpd_generals(1, "0", "1", {})

        assert "\\rank\\" in response

    def test_response_contains_pid_and_lid(self):
        server, transport = _make_server("ccgenzh")
        with patch("app.servers.gamestats_server.get_generals_player_stats", return_value=None):
            response = server._handle_getpd_generals(42, "7", "1", {})
        assert "\\pid\\42" in response
        assert "\\lid\\7" in response

    def test_data_length_matches_actual_data(self):
        server, transport = _make_server("ccgenzh")
        raw = "\\wins8\\1\\losses13\\1\\"
        fake_stats = self._make_fake_stats(raw)

        with patch("app.servers.gamestats_server.get_generals_player_stats", return_value=fake_stats):
            response = server._handle_getpd_generals(1, "0", "1", {})

        # Extract length and data from the response
        # response format: \getpdr\1\lid\0\pid\1\mod\N\length\L\data\D\final\
        length_marker = "\\length\\"
        data_marker = "\\data\\"
        length_pos = response.find(length_marker) + len(length_marker)
        data_pos = response.find(data_marker) + len(data_marker)
        final_pos = response.find("\\final\\")

        # Parse the declared length
        length_end = response.find("\\", length_pos)
        declared_length = int(response[length_pos:length_end])

        # The actual data is from data_marker to \final\
        actual_data = response[data_pos:final_pos]
        assert len(actual_data) == declared_length

    def test_battle_field_uses_stored_honors_not_raw_data(self):
        # Verify the stored battle_honors column value is used,
        # not the client-sent \battle\ field in raw_data
        server, transport = _make_server("ccgenzh")
        raw = "\\wins8\\1\\battle\\49152\\"  # client sent BLITZ5|BLITZ10
        fake_stats = self._make_fake_stats(raw, battle_honors=65536)  # stored: FAIR_PLAY

        with patch("app.servers.gamestats_server.get_generals_player_stats", return_value=fake_stats):
            response = server._handle_getpd_generals(1, "0", "1", {})

        # Should use stored value 65536, overwriting the client's 49152
        assert "\\battle\\65536" in response
        assert "\\battle\\49152" not in response

    def test_null_bytes_stripped_from_response(self):
        """Null bytes in stored raw_data are stripped so the C client sees all fields."""
        server, _ = _make_server("ccgenzh")
        # DSRow value has embedded \x00; wins8 and battle come after it
        raw = r"\DSRow\0" + "\x00" + r"\wins8\5\losses8\2"
        fake_stats = self._make_fake_stats(raw, battle_honors=65536)

        with patch("app.servers.gamestats_server.get_generals_player_stats", return_value=fake_stats):
            response = server._handle_getpd_generals(1, "0", "1", {})

        # No null bytes anywhere in the response
        assert "\x00" not in response
        # Fields after the original null byte are visible
        assert "\\wins8\\5" in response
        assert "\\losses8\\2" in response
        assert "\\battle\\65536" in response

    def test_live_p3_data_produces_fair_play_in_response(self):
        """End-to-end: live raw_data → getpd response contains HONOR_FAIR_PLAY."""
        from app.util.generals_stats import HONOR_FAIR_PLAY

        # Build the raw_data as it would be stored after merging two setpds
        before_null = (
            r"\discons0\0\discons1\0\discons2\0\discons3\0\discons4\0"
            r"\discons5\0\discons6\0\discons7\0\discons8\0\discons9\0"
            r"\discons10\0\discons11\0\discons12\0\discons13\0\discons14\0"
            r"\lastGeneral\6\genInRow\2\builtCannon\0\builtNuke\0\builtSCUD\0"
            r"\WinRow\0\LossRow\1\DCRow\0\DSRow\0"
        )
        after_null = r"\wins6\1\games6\1\duration6\3\losses6\1\WinRowMax\1\LossRowMax\1"
        raw = before_null + "\x00" + after_null

        fake_stats = self._make_fake_stats(raw, battle_honors=HONOR_FAIR_PLAY)
        server, _ = _make_server("ccgenzh")

        with patch("app.servers.gamestats_server.get_generals_player_stats", return_value=fake_stats):
            response = server._handle_getpd_generals(3, "0", "1", {})

        assert f"\\battle\\{HONOR_FAIR_PLAY}" in response


# =============================================================================
# _handle_getpd_json (RA3 / CNC3)
# =============================================================================


class TestHandleGetpdJson:
    """RA3/CNC3 getpd: returns JSON-encoded stats."""

    def test_no_stats_returns_empty_json(self):
        server, _ = _make_server("redalert3pc")
        with patch("app.servers.gamestats_server.get_player_stats", return_value=None):
            result = server._handle_getpd_json(1, "0", "1", {})

        assert "\\getpdr\\1" in result
        length_marker = "\\length\\"
        l_pos = result.find(length_marker) + len(length_marker)
        l_end = result.find("\\", l_pos)
        assert int(result[l_pos:l_end]) > 0  # even empty JSON has some length

    def test_existing_stats_returned_as_json(self):
        server, _ = _make_server("redalert3pc")
        mock_stats = MagicMock()
        mock_stats.stats = {
            "ranked_1v1": {
                "wins": 5,
                "losses": 2,
                "disconnects": 0,
                "desyncs": 0,
                "avg_game_length": 0,
                "win_ratio": 0.0,
            },
            "ranked_2v2": {
                "wins": 0,
                "losses": 0,
                "disconnects": 0,
                "desyncs": 0,
                "avg_game_length": 0,
                "win_ratio": 0.0,
            },
            "unranked": {
                "wins": 0,
                "losses": 0,
                "disconnects": 0,
                "desyncs": 0,
                "avg_game_length": 0,
                "win_ratio": 0.0,
            },
            "clan_1v1": {
                "wins": 0,
                "losses": 0,
                "disconnects": 0,
                "desyncs": 0,
                "avg_game_length": 0,
                "win_ratio": 0.0,
            },
            "clan_2v2": {
                "wins": 0,
                "losses": 0,
                "disconnects": 0,
                "desyncs": 0,
                "avg_game_length": 0,
                "win_ratio": 0.0,
            },
        }
        mock_stats.total_matches_online = 7

        with patch("app.servers.gamestats_server.get_player_stats", return_value=mock_stats):
            result = server._handle_getpd_json(1, "0", "1", {})

        # Extract JSON from response
        data_marker = "\\data\\"
        data_pos = result.find(data_marker) + len(data_marker)
        final_pos = result.find("\\final\\")
        data_str = result[data_pos:final_pos]
        parsed = json.loads(data_str)

        assert parsed["wins_ranked_1v1"] == 5
        assert parsed["losses_ranked_1v1"] == 2
        assert parsed["total_matches_online"] == 7

    def test_response_does_not_contain_generals_kv_fields(self):
        """RA3 response must never contain Generals-style wins8/losses6 fields."""
        server, _ = _make_server("redalert3pc")
        with patch("app.servers.gamestats_server.get_player_stats", return_value=None):
            result = server._handle_getpd_json(1, "0", "1", {})
        assert "\\wins8\\" not in result
        assert "\\losses6\\" not in result
        assert "\\battle\\" not in result
        assert "\\rank\\" not in result


# =============================================================================
# _handle_setpd — auth guards, pid ownership, routing
# =============================================================================


class TestHandleSetpd:
    def test_setpd_requires_game_auth(self):
        server, transport = _make_server()
        server.authenticated_game = False
        server._process_message("\\setpd\\\\pid\\1\\lid\\0\\length\\0\\data\\\\id\\1\\final\\")
        kv = transport.last_response_kv()
        assert "error" in kv

    def test_setpd_requires_player_auth(self):
        server, transport = _make_server("ccgenzh")
        server.authenticated_player = False
        server._process_message("\\setpd\\\\pid\\1\\lid\\0\\length\\0\\data\\\\id\\1\\final\\")
        kv = transport.last_response_kv()
        assert "error" in kv

    def test_setpd_rejects_wrong_pid(self):
        server, transport = _authed_server("ccgenzh", pid=1)
        # Request to modify pid=99, but authenticated as pid=1
        server._process_message("\\setpd\\\\pid\\99\\lid\\0\\length\\0\\data\\\\id\\1\\final\\")
        kv = transport.last_response_kv()
        assert "error" in kv

    def test_setpd_routes_generals_to_kv_handler(self):
        server, transport = _authed_server("ccgenzh", pid=3)
        with patch.object(server, "_handle_setpd_generals", return_value="\\setpdr\\1\\final\\") as mock_h:
            server._handle_setpd({"pid": "3", "data": "\\wins8\\1\\", "lid": "0", "id": "1"})
        mock_h.assert_called_once()

    def test_setpd_routes_ra3_to_json_handler(self):
        server, transport = _authed_server("redalert3pc", pid=1)
        with patch.object(server, "_handle_setpd_json", return_value="\\setpdr\\1\\final\\") as mock_h:
            server._handle_setpd({"pid": "1", "data": "{}", "lid": "0", "id": "1"})
        mock_h.assert_called_once()

    def test_setpd_cnc3_routes_to_json_handler(self):
        server, transport = _authed_server("cnc3pc", pid=1)
        with patch.object(server, "_handle_setpd_json", return_value="\\setpdr\\1\\final\\") as mock_h:
            server._handle_setpd({"pid": "1", "data": "{}", "lid": "0", "id": "1"})
        mock_h.assert_called_once()


# =============================================================================
# _handle_setpd_generals
# =============================================================================


class TestHandleSetpdGenerals:
    """Generals/ZH setpd: saves KV data, recalculates honors, returns ack."""

    def test_returns_setpdr_1(self):
        server, _ = _authed_server("ccgenzh", pid=3)
        with patch("app.servers.gamestats_server.create_or_update_generals_stats"):
            result = server._handle_setpd_generals(3, "\\wins8\\1\\", "0", "1")
        assert "\\setpdr\\1" in result

    def test_pid_and_lid_echoed(self):
        server, _ = _authed_server("ccgenzh", pid=3)
        with patch("app.servers.gamestats_server.create_or_update_generals_stats"):
            result = server._handle_setpd_generals(3, "\\wins8\\1\\", "5", "1")
        assert "\\pid\\3" in result
        assert "\\lid\\5" in result

    def test_calls_create_or_update_with_correct_args(self):
        server, _ = _authed_server("ccgenzh", pid=3)
        data = "\\wins8\\1\\"
        with patch("app.servers.gamestats_server.create_or_update_generals_stats") as mock_save:
            server._handle_setpd_generals(3, data, "0", "1")
        mock_save.assert_called_once_with(server._db_session, 3, data)

    def test_empty_data_not_saved(self):
        server, _ = _authed_server("ccgenzh", pid=3)
        with patch("app.servers.gamestats_server.create_or_update_generals_stats") as mock_save:
            server._handle_setpd_generals(3, "", "0", "1")
        mock_save.assert_not_called()

    def test_live_generals_payload_saved(self):
        """Actual setpd payload from the live game is passed to the DB layer."""
        server, _ = _authed_server("ccgenzh", pid=3)
        with patch("app.servers.gamestats_server.create_or_update_generals_stats") as mock_save:
            server._handle_setpd_generals(3, LIVE_GENERALS_SETPD_DATA, "0", "1")
        mock_save.assert_called_once_with(server._db_session, 3, LIVE_GENERALS_SETPD_DATA)


# =============================================================================
# _handle_setpd_json (RA3 / CNC3)
# =============================================================================


class TestHandleSetpdJson:
    """RA3/CNC3 setpd: saves JSON stats, does NOT touch Generals KV store."""

    def test_returns_setpdr_1(self):
        server, _ = _authed_server("redalert3pc", pid=1)
        with patch("app.servers.gamestats_server.create_or_update_player_stats"):
            result = server._handle_setpd_json(1, LIVE_RA3_SETPD_JSON, "0", "1")
        assert "\\setpdr\\1" in result

    def test_pid_and_lid_echoed(self):
        server, _ = _authed_server("redalert3pc", pid=1)
        with patch("app.servers.gamestats_server.create_or_update_player_stats"):
            result = server._handle_setpd_json(1, "{}", "3", "1")
        assert "\\pid\\1" in result
        assert "\\lid\\3" in result

    def test_calls_player_stats_not_generals_stats(self):
        server, _ = _authed_server("redalert3pc", pid=1)
        with (
            patch("app.servers.gamestats_server.create_or_update_player_stats") as mock_ps,
            patch("app.servers.gamestats_server.create_or_update_generals_stats") as mock_gs,
        ):
            server._handle_setpd_json(1, LIVE_RA3_SETPD_JSON, "0", "1")
        mock_ps.assert_called_once()
        mock_gs.assert_not_called()

    def test_empty_data_skips_save(self):
        # _handle_setpd_json skips the CRUD call when the parsed dict is empty.
        # This matches the production code: `if stats_data: create_or_update(...)`.
        server, _ = _authed_server("redalert3pc", pid=1)
        with patch("app.servers.gamestats_server.create_or_update_player_stats") as mock_ps:
            result = server._handle_setpd_json(1, "", "0", "1")
        mock_ps.assert_not_called()
        assert "\\setpdr\\1" in result  # still returns a valid ack

    def test_invalid_json_does_not_crash(self):
        server, _ = _authed_server("redalert3pc", pid=1)
        with patch("app.servers.gamestats_server.create_or_update_player_stats"):
            result = server._handle_setpd_json(1, "not_json{{", "0", "1")
        assert "\\setpdr\\1" in result


# =============================================================================
# _handle_newgame / _handle_updgame
# =============================================================================


class TestHandleGameSnapshots:
    def test_newgame_returns_acknowledgment(self):
        server, _ = _make_server("ccgenzh")
        result = server._handle_newgame({"id": "1"})
        assert "\\newgame\\" in result
        assert result.endswith("\\final\\")

    def test_updgame_returns_acknowledgment(self):
        server, _ = _make_server("ccgenzh")
        result = server._handle_updgame({"id": "1"})
        assert "\\updgame\\" in result
        assert result.endswith("\\final\\")

    def test_newgame_ra3_also_acknowledged(self):
        server, _ = _make_server("redalert3pc")
        result = server._handle_newgame({"id": "5"})
        assert "\\newgame\\" in result

    def test_updgame_id_echoed(self):
        server, _ = _make_server("ccgenzh")
        result = server._handle_updgame({"id": "42"})
        assert "\\id\\42" in result


# =============================================================================
# Full Generals flow — process_message end-to-end
# =============================================================================


class TestGeneralsFullFlow:
    """
    Simulate a complete Generals/ZH session:
    auth → authp (pid path) → setpd → getpd
    """

    def test_ka_always_responded(self):
        server, transport = _make_server()
        server._process_message("\\ka\\\\id\\1\\final\\")
        assert "\\ka\\" in transport.last_response_text

    def test_generals_setpd_then_getpd_via_process_message(self):
        """setpd followed by getpd returns the same KV data with battle/rank injected."""
        from app.util.generals_stats import HONOR_FAIR_PLAY

        kv_data = "\\wins8\\1\\discons0\\0\\"
        fake_stored = MagicMock()
        fake_stored.raw_data = kv_data
        fake_stored.battle_honors = HONOR_FAIR_PLAY
        fake_stored.updated_at = datetime(2026, 3, 3, 17, 0, 0)

        server, transport = _authed_server("ccgenzh", pid=1)

        # setpd
        setpd_msg = f"\\setpd\\\\pid\\1\\length\\{len(kv_data)}\\data\\{kv_data}\\id\\1\\final\\"
        with patch("app.servers.gamestats_server.create_or_update_generals_stats"):
            server._process_message(setpd_msg)
        assert "\\setpdr\\1" in transport.last_response_text

        # getpd
        getpd_msg = "\\getpd\\\\pid\\1\\lid\\0\\id\\1\\final\\"
        with patch("app.servers.gamestats_server.get_generals_player_stats", return_value=fake_stored):
            server._process_message(getpd_msg)

        response_text = transport.last_response_text
        assert "\\getpdr\\1" in response_text
        assert f"\\battle\\{HONOR_FAIR_PLAY}" in response_text
        assert "\\rank\\0" in response_text

    def test_unknown_command_returns_error(self):
        server, transport = _make_server("ccgenzh")
        server._process_message("\\unknowncmd\\\\id\\1\\final\\")
        kv = transport.last_response_kv()
        assert "error" in kv


# =============================================================================
# RA3/CNC3 backward compatibility
# =============================================================================


class TestRA3BackwardCompat:
    """
    Verify that RA3/CNC3 games continue to use the JSON path and are never
    affected by Generals/ZH KV logic.
    """

    def test_ra3_getpd_never_calls_generals_handler(self):
        server, _ = _make_server("redalert3pc")
        with (
            patch.object(server, "_handle_getpd_generals") as mock_gen,
            patch.object(server, "_handle_getpd_json", return_value="\\getpdr\\1\\final\\") as mock_json,
        ):
            server._handle_getpd({"pid": "1", "lid": "0", "id": "1"})
        mock_gen.assert_not_called()
        mock_json.assert_called_once()

    def test_ra3_setpd_never_calls_generals_handler(self):
        server, _ = _authed_server("redalert3pc", pid=1)
        with (
            patch.object(server, "_handle_setpd_generals") as mock_gen,
            patch.object(server, "_handle_setpd_json", return_value="\\setpdr\\1\\final\\") as mock_json,
        ):
            server._handle_setpd({"pid": "1", "data": "{}", "lid": "0", "id": "1"})
        mock_gen.assert_not_called()
        mock_json.assert_called_once()

    def test_cnc3_getpd_never_calls_generals_handler(self):
        server, _ = _make_server("cnc3pc")
        with (
            patch.object(server, "_handle_getpd_generals") as mock_gen,
            patch.object(server, "_handle_getpd_json", return_value="\\getpdr\\1\\final\\"),
        ):
            server._handle_getpd({"pid": "1", "lid": "0", "id": "1"})
        mock_gen.assert_not_called()

    def test_generals_getpd_never_calls_json_handler(self):
        server, _ = _make_server("ccgenzh")
        with (
            patch.object(server, "_handle_getpd_json") as mock_json,
            patch.object(server, "_handle_getpd_generals", return_value="\\getpdr\\1\\final\\"),
        ):
            server._handle_getpd({"pid": "1", "lid": "0", "id": "1"})
        mock_json.assert_not_called()

    def test_ra3_getpd_response_parseable_as_json(self):
        server, _ = _make_server("redalert3pc")
        with patch("app.servers.gamestats_server.get_player_stats", return_value=None):
            result = server._handle_getpd_json(1, "0", "1", {})

        data_pos = result.find("\\data\\") + len("\\data\\")
        final_pos = result.find("\\final\\")
        data_str = result[data_pos:final_pos]
        parsed = json.loads(data_str)
        assert isinstance(parsed, dict)

    def test_generals_and_ra3_setpd_same_pid_ownership_check(self):
        """Both games reject modifying another player's stats."""
        for gamename in ("ccgenzh", "redalert3pc"):
            server, transport = _authed_server(gamename, pid=1)
            server._process_message("\\setpd\\\\pid\\99\\lid\\0\\length\\2\\data\\{}\\id\\1\\final\\")
            kv = transport.last_response_kv()
            assert "error" in kv, f"Expected error for {gamename} cross-pid write"
