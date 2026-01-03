"""
Tests for the GameSpy Protocol Server.

These tests cover:
1. Legacy login response generation (backwards compatibility)
2. Request parsing
3. Response formatting
4. Command handling (login, getprofile, status, logout)
5. Protocol flow validation based on real example data
"""

import base64
import hashlib
from unittest.mock import MagicMock, patch

from app.servers.gp_server import (
    TEST_SECRET as GP_TEST_SECRET,
)
from app.servers.gp_server import (
    TEST_UNIQUENICK as GP_TEST_UNIQUENICK,
)
from app.servers.gp_server import (
    TEST_USER_ID as GP_TEST_USER_ID,
)
from app.servers.gp_server import (
    GpServer,
    generate_login_response,
)

# Test constants (sanitized dummy data)
TEST_USER_ID = "100001"
TEST_PROFILE_ID = "200001"
TEST_UNIQUENICK = "testplayer"
TEST_SESSKEY = "123456789"
TEST_CHALLENGE = "TestChallengeString1234"
TEST_AUTHTOKEN = base64.b64encode(b"100001|200001|TestSecretToken123").decode()


class MockSessionManager:
    """Mock session manager for testing."""

    def __init__(self):
        self.users = {}
        self.users_by_persona = {}

    def register_user(self, sesskey, protocol):
        self.users[sesskey] = protocol
        if hasattr(protocol, "persona_id") and protocol.persona_id:
            self.users_by_persona[protocol.persona_id] = protocol

    async def unregister_user(self, sesskey):
        if sesskey in self.users:
            del self.users[sesskey]

    def get_user_by_persona_id(self, persona_id):
        return self.users_by_persona.get(persona_id)

    def is_user_online(self, persona_id):
        return persona_id in self.users_by_persona


class MockTransport:
    """Mock transport for testing."""

    def __init__(self):
        self.written = []
        self.closed = False

    def write(self, data):
        self.written.append(data)

    def get_extra_info(self, name):
        if name == "peername":
            return ("127.0.0.1", 12345)
        return None

    def close(self):
        self.closed = True


class TestGpServerLegacy:
    """Test class for legacy GpServer methods (backwards compatibility)."""

    def test_generate_login_response_basic(self):
        """Test basic login response generation with minimal request data."""
        request_data = {"challenge": "test_challenge", "id": "123"}

        response = generate_login_response(request_data)

        # Verify response structure
        assert response.startswith("\\")
        assert response.endswith("\\final\\")

        # Parse response parts
        parts = response.strip().split("\\")
        parts = [p for p in parts if p and p != "final"]
        response_parts = {parts[i]: parts[i + 1] for i in range(0, len(parts) - 1, 2)}

        # Check required fields
        assert "lc" in response_parts
        assert "sesskey" in response_parts
        assert "proof" in response_parts
        assert "userid" in response_parts
        assert "profileid" in response_parts
        assert "uniquenick" in response_parts
        assert "lt" in response_parts
        assert "id" in response_parts

    def test_generate_login_response_static_values(self):
        """Test that static values are correctly set in the response."""
        request_data = {"challenge": "test_challenge", "id": "456"}

        response = generate_login_response(request_data)
        parts = response.strip().split("\\")
        parts = [p for p in parts if p and p != "final"]
        response_parts = {parts[i]: parts[i + 1] for i in range(0, len(parts) - 1, 2)}

        # Check login code is success (2)
        assert response_parts["lc"] == "2"
        # Check sesskey is present
        assert "sesskey" in response_parts

    def test_generate_login_response_proof_calculation(self):
        """Test that proof is correctly calculated from challenge."""
        challenge = "test_challenge_123"
        # Use dummy test values from generate_login_response defaults
        userid = GP_TEST_USER_ID
        uniquenick = GP_TEST_UNIQUENICK
        request_data = {"challenge": challenge, "id": "789", "userid": userid, "uniquenick": uniquenick}

        response = generate_login_response(request_data)
        parts = response.strip().split("\\")
        parts = [p for p in parts if p and p != "final"]
        response_parts = {parts[i]: parts[i + 1] for i in range(0, len(parts) - 1, 2)}

        # Calculate expected proof using test secret
        secret = GP_TEST_SECRET
        expected_proof_string = f"{userid}{uniquenick}{challenge}{secret}".encode()
        expected_proof = hashlib.md5(expected_proof_string).hexdigest()

        assert response_parts["proof"] == expected_proof

    def test_generate_login_response_lt_base64_encoding(self):
        """Test that lt field is correctly base64 encoded."""
        request_data = {"challenge": "test", "id": "999"}

        response = generate_login_response(request_data)
        parts = response.strip().split("\\")
        parts = [p for p in parts if p and p != "final"]
        response_parts = {parts[i]: parts[i + 1] for i in range(0, len(parts) - 1, 2)}

        # Decode the base64 lt value
        decoded_lt = base64.b64decode(response_parts["lt"]).decode("utf-8")

        # Check it matches expected format (userid|profileid|secret)
        assert "|" in decoded_lt
        parts = decoded_lt.split("|")
        assert len(parts) == 3

    def test_generate_login_response_id_preservation(self):
        """Test that the id from request is preserved in response."""
        test_id = "custom_id_123"
        request_data = {"challenge": "test", "id": test_id}

        response = generate_login_response(request_data)
        parts = response.strip().split("\\")
        parts = [p for p in parts if p and p != "final"]
        response_parts = {parts[i]: parts[i + 1] for i in range(0, len(parts) - 1, 2)}

        assert response_parts["id"] == test_id


class TestGpServerMethods:
    """Test class for GpServer instance methods."""

    def setup_method(self):
        """Set up test fixtures before each test method."""
        self.mock_session_manager = MockSessionManager()
        self.gp_server = GpServer(self.mock_session_manager)
        self.gp_server.transport = MockTransport()
        self.gp_server.peername = ("127.0.0.1", 12345)

    def test_parse_request_basic(self):
        """Test parsing a basic GameSpy request."""
        request = "\\login\\\\challenge\\abc123\\id\\1\\final\\"

        result = self.gp_server.parse_request(request)

        assert "login" in result
        assert result.get("challenge") == "abc123"
        assert result.get("id") == "1"

    def test_parse_request_empty(self):
        """Test parsing an empty request."""
        request = "\\final\\"

        result = self.gp_server.parse_request(request)

        assert result == {}

    def test_parse_request_with_empty_values(self):
        """Test parsing request with empty values (common in GameSpy)."""
        request = "\\status\\\\sesskey\\123456\\statstring\\Online\\locstring\\\\final\\"

        result = self.gp_server.parse_request(request)

        assert result.get("sesskey") == "123456"
        assert result.get("statstring") == "Online"

    def test_format_response_basic(self):
        """Test formatting a basic response."""
        data = {"lc": "2", "sesskey": "12345"}

        result = self.gp_server.format_response(data)

        assert result.endswith("\\final\\")
        assert "\\lc\\2" in result
        assert "\\sesskey\\12345" in result

    def test_format_response_preserves_order(self):
        """Test that response formatting preserves key order."""
        from collections import OrderedDict

        data = OrderedDict([("lc", "2"), ("sesskey", "12345"), ("proof", "abc")])

        result = self.gp_server.format_response(data)

        # Keys should appear in order
        lc_pos = result.find("\\lc\\")
        sesskey_pos = result.find("\\sesskey\\")
        proof_pos = result.find("\\proof\\")

        assert lc_pos < sesskey_pos < proof_pos

    def test_format_error(self):
        """Test formatting an error response."""
        result = self.gp_server.format_error("Test error", "123")

        assert "\\error\\" in result
        assert "\\errmsg\\Test error" in result
        assert "\\id\\123" in result
        assert result.endswith("\\final\\")

    def test_calculate_proof(self):
        """Test proof calculation with new GameSpy format."""
        # Using the verified formula from real data
        password = "segztxkf"  # FESL challenge
        authtoken = "MTAwODU1MXwxMDAxMjcxMzI5fEdRR0w5SG5EUExpMFU1VkVGMTh5"
        server_challenge = "RKSUWPOCWX"
        client_challenge = "llrrc04O5dKCxoYwkESNCQzc1dhqtcgA"
        expected_proof = "a25c61a3929cc6ccfeb1eab242d3a669"

        proof = self.gp_server.calculate_proof(
            password=password, authtoken=authtoken, client_challenge=client_challenge, server_challenge=server_challenge
        )

        assert proof == expected_proof

    def test_calculate_proof_consistency(self):
        """Test that proof calculation is consistent across calls."""
        proof1 = self.gp_server.calculate_proof("password", "authtoken", "client_chal", "server_chal")
        proof2 = self.gp_server.calculate_proof("password", "authtoken", "client_chal", "server_chal")

        assert proof1 == proof2

    def test_calculate_proof_different_challenges(self):
        """Test that different challenges produce different proofs."""
        proof1 = self.gp_server.calculate_proof("password", "authtoken", "client_chal1", "server_chal")
        proof2 = self.gp_server.calculate_proof("password", "authtoken", "client_chal2", "server_chal")

        assert proof1 != proof2

    def test_calculate_client_response(self):
        """Test client response calculation (challenges swapped)."""
        password = "segztxkf"
        authtoken = "MTAwODU1MXwxMDAxMjcxMzI5fEdRR0w5SG5EUExpMFU1VkVGMTh5"
        server_challenge = "RKSUWPOCWX"
        client_challenge = "llrrc04O5dKCxoYwkESNCQzc1dhqtcgA"
        expected_response = "43575edbb342e4ef667e8d34d4df3584"

        response = self.gp_server.calculate_client_response(
            password=password, authtoken=authtoken, client_challenge=client_challenge, server_challenge=server_challenge
        )

        assert response == expected_response


class TestGpServerParsing:
    """Test parsing of GameSpy protocol messages."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_session_manager = MockSessionManager()
        self.gp_server = GpServer(self.mock_session_manager)

    def test_parse_login_request(self):
        """Test parsing a login request (based on real example data)."""
        # Using sanitized dummy data
        authtoken = base64.b64encode(b"100001|200001|TestToken").decode()
        request = (
            f"\\login\\\\challenge\\{TEST_CHALLENGE}\\"
            f"authtoken\\{authtoken}\\"
            "partnerid\\0\\response\\00000000000000000000000000000000\\"
            "firewall\\1\\port\\0\\productid\\11419\\gamename\\redalert3pc\\"
            "namespaceid\\1\\sdkrevision\\11\\quiet\\0\\id\\1\\final\\"
        )

        result = self.gp_server.parse_request(request)

        assert result.get("challenge") == TEST_CHALLENGE
        assert result.get("authtoken") == authtoken
        assert result.get("partnerid") == "0"
        assert result.get("productid") == "11419"
        assert result.get("gamename") == "redalert3pc"
        assert result.get("namespaceid") == "1"
        assert result.get("sdkrevision") == "11"
        assert result.get("firewall") == "1"
        assert result.get("port") == "0"
        assert result.get("quiet") == "0"
        assert result.get("id") == "1"

    def test_parse_getprofile_request(self):
        """Test parsing a getprofile request."""
        request = f"\\getprofile\\\\profileid\\{TEST_PROFILE_ID}\\sesskey\\{TEST_SESSKEY}\\id\\2\\final\\"

        result = self.gp_server.parse_request(request)

        assert result.get("profileid") == TEST_PROFILE_ID
        assert result.get("sesskey") == TEST_SESSKEY
        assert result.get("id") == "2"

    def test_parse_status_request_online(self):
        """Test parsing a status request (Online)."""
        request = f"\\status\\\\sesskey\\{TEST_SESSKEY}\\statstring\\Online\\locstring\\\\final\\"

        result = self.gp_server.parse_request(request)

        assert result.get("sesskey") == TEST_SESSKEY
        assert result.get("statstring") == "Online"

    def test_parse_status_request_chatting(self):
        """Test parsing a status request (Chatting in channel)."""
        request = f"\\status\\4\\sesskey\\{TEST_SESSKEY}\\statstring\\Chatting\\locstring\\2166\\final\\"

        result = self.gp_server.parse_request(request)

        assert result.get("sesskey") == TEST_SESSKEY
        assert result.get("statstring") == "Chatting"
        assert result.get("locstring") == "2166"

    def test_parse_status_request_staging(self):
        """Test parsing a status request (Staging for game)."""
        request = f"\\status\\3\\sesskey\\{TEST_SESSKEY}\\statstring\\Staging\\locstring\\{TEST_UNIQUENICK}\\final\\"

        result = self.gp_server.parse_request(request)

        assert result.get("sesskey") == TEST_SESSKEY
        assert result.get("statstring") == "Staging"
        assert result.get("locstring") == TEST_UNIQUENICK

    def test_parse_addbuddy_request(self):
        """Test parsing an addbuddy request."""
        request = f"\\addbuddy\\\\sesskey\\{TEST_SESSKEY}\\newprofileid\\300001\\reason\\\\final\\"

        result = self.gp_server.parse_request(request)

        assert result.get("sesskey") == TEST_SESSKEY
        assert result.get("newprofileid") == "300001"

    def test_parse_authadd_request(self):
        """Test parsing an authadd (authorize buddy) request."""
        request = (
            f"\\authadd\\\\sesskey\\{TEST_SESSKEY}\\fromprofileid\\300001\\"
            "sig\\00000000000000000000000000000000\\final\\"
        )

        result = self.gp_server.parse_request(request)

        assert result.get("sesskey") == TEST_SESSKEY
        assert result.get("fromprofileid") == "300001"
        assert result.get("sig") == "00000000000000000000000000000000"

    def test_parse_pinvite_request(self):
        """Test parsing a pinvite (game invite) request."""
        location = f"2166 219975299 0 PW: #HOST:{TEST_UNIQUENICK} {TEST_UNIQUENICK} #FROM:{TEST_UNIQUENICK} #CHAN:#GSP!redalert3pc!TestLobby"
        request = (
            f"\\pinvite\\\\sesskey\\{TEST_SESSKEY}\\profileid\\300001\\productid\\11419\\location\\{location}\\final\\"
        )

        result = self.gp_server.parse_request(request)

        assert result.get("sesskey") == TEST_SESSKEY
        assert result.get("profileid") == "300001"
        assert result.get("productid") == "11419"
        assert "#GSP!redalert3pc!" in result.get("location", "")

    def test_parse_logout_request(self):
        """Test parsing a logout request."""
        request = f"\\logout\\\\sesskey\\{TEST_SESSKEY}\\final\\"

        result = self.gp_server.parse_request(request)

        assert result.get("sesskey") == TEST_SESSKEY


class TestGpServerStatusHandling:
    """Test status command handling."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_session_manager = MockSessionManager()
        self.gp_server = GpServer(self.mock_session_manager)
        self.gp_server.transport = MockTransport()
        self.gp_server.peername = ("127.0.0.1", 12345)
        self.gp_server.sesskey = TEST_SESSKEY

    def test_handle_status_online(self):
        """Test handling status update to Online.

        Per GameSpy protocol, status updates don't return a response.
        The server updates the database and notifies buddies instead.
        """
        request_data = {"sesskey": TEST_SESSKEY, "statstring": "Online", "locstring": ""}

        response = self.gp_server.handle_status(request_data)

        # Status command returns empty string - no response needed per protocol
        assert response == ""

    def test_handle_status_chatting(self):
        """Test handling status update to Chatting.

        Per GameSpy protocol, status updates don't return a response.
        """
        request_data = {"sesskey": TEST_SESSKEY, "statstring": "Chatting", "locstring": "2166"}

        response = self.gp_server.handle_status(request_data)

        # Status command returns empty string - no response needed per protocol
        assert response == ""

    def test_handle_status_staging(self):
        """Test handling status update to Staging (game lobby).

        Per GameSpy protocol, status updates don't return a response.
        """
        request_data = {"sesskey": TEST_SESSKEY, "statstring": "Staging", "locstring": TEST_UNIQUENICK}

        response = self.gp_server.handle_status(request_data)

        # Status command returns empty string - no response needed per protocol
        assert response == ""


class TestGpServerLogout:
    """Test logout command handling."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_session_manager = MockSessionManager()
        self.gp_server = GpServer(self.mock_session_manager)
        self.gp_server.transport = MockTransport()
        self.gp_server.peername = ("127.0.0.1", 12345)
        # Don't set sesskey so unregister_user won't be called
        self.gp_server.user_id = 100001
        self.gp_server.persona_id = 200001
        self.gp_server.uniquenick = TEST_UNIQUENICK

    def test_handle_logout_clears_state(self):
        """Test that logout clears session state."""
        request_data = {"sesskey": TEST_SESSKEY}

        self.gp_server.handle_logout(request_data)

        assert self.gp_server.user_id is None
        assert self.gp_server.persona_id is None
        assert self.gp_server.sesskey is None
        assert self.gp_server.uniquenick is None

    def test_handle_logout_returns_empty(self):
        """Test that logout returns empty response."""
        request_data = {"sesskey": TEST_SESSKEY}

        response = self.gp_server.handle_logout(request_data)

        assert response == ""


class TestGpServerProtocolFlow:
    """Test complete protocol flows based on real example data."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_session_manager = MockSessionManager()
        self.gp_server = GpServer(self.mock_session_manager)
        self.gp_server.transport = MockTransport()
        self.gp_server.peername = ("127.0.0.1", 12345)

    def test_login_response_structure(self):
        """Test that login response has correct structure (based on example)."""
        # Example from PDF: \lc\2\sesskey\877562875\proof\...\userid\...\profileid\...\uniquenick\...\lt\...\id\1\final\

        response = generate_login_response({"challenge": TEST_CHALLENGE, "id": "1"})

        # Parse response
        parts = response.strip().split("\\")
        parts = [p for p in parts if p and p != "final"]
        response_parts = {}
        for i in range(0, len(parts) - 1, 2):
            response_parts[parts[i]] = parts[i + 1]

        # Verify structure matches example
        assert response_parts["lc"] == "2"  # Success
        assert "sesskey" in response_parts
        assert "proof" in response_parts
        assert "userid" in response_parts
        assert "profileid" in response_parts
        assert "uniquenick" in response_parts
        assert "lt" in response_parts
        assert response_parts["id"] == "1"

    def test_getprofile_response_structure(self):
        """Test getprofile response structure (based on example)."""
        # Example: \pi\\profileid\...\nick\...\userid\...\sig\...\uniquenick\...\pid\...\lon\...\lat\...\loc\\id\2\final\

        # Set up server state
        self.gp_server.sesskey = TEST_SESSKEY

        # Mock database calls
        with (
            patch("app.servers.gp_server.create_session"),
            patch("app.servers.gp_server.get_persona_by_id") as mock_persona,
            patch("app.servers.gp_server.get_user_by_id") as mock_user,
        ):
            mock_persona_obj = MagicMock()
            mock_persona_obj.id = 200001
            mock_persona_obj.name = TEST_UNIQUENICK
            mock_persona_obj.user_id = 100001
            mock_persona.return_value = mock_persona_obj

            mock_user_obj = MagicMock()
            mock_user_obj.id = 100001
            mock_user.return_value = mock_user_obj

            response = self.gp_server.handle_getprofile({"profileid": "200001", "sesskey": TEST_SESSKEY, "id": "2"})

        # Verify response structure
        assert response.startswith("\\pi\\")
        assert "\\profileid\\" in response
        assert "\\nick\\" in response
        assert "\\userid\\" in response
        assert "\\uniquenick\\" in response
        assert "\\sig\\" in response
        assert "\\lon\\" in response
        assert "\\lat\\" in response
        assert "\\id\\2" in response
        assert response.endswith("\\final\\")

    def test_status_codes(self):
        """Test that status codes match expected values from example."""
        # From example:
        # status 1 = Online
        # status 3 = Staging
        # status 4 = Chatting
        # status 0 = Offline (in bm messages)

        status_map = {
            "1": "Online",
            "3": "Staging",
            "4": "Chatting",
        }

        for code, expected_string in status_map.items():
            request = (
                f"\\status\\{code}\\sesskey\\{TEST_SESSKEY}\\statstring\\{expected_string}\\locstring\\test\\final\\"
            )
            result = self.gp_server.parse_request(request)
            assert result.get("statstring") == expected_string

    def test_complete_session_flow(self):
        """Test a complete session flow: login response -> status -> logout."""
        # Step 1: Generate login response
        login_response = generate_login_response({"challenge": TEST_CHALLENGE, "id": "1"})
        assert "\\lc\\2" in login_response

        # Step 2: Status update (don't set sesskey to avoid async task in logout)
        status_response = self.gp_server.handle_status(
            {"sesskey": TEST_SESSKEY, "statstring": "Online", "locstring": ""}
        )
        # Status updates return empty string per GameSpy protocol
        assert status_response == ""

        # Step 3: Logout (sesskey is None, so no async unregister call)
        self.gp_server.user_id = 100001  # Set some state to clear
        logout_response = self.gp_server.handle_logout({"sesskey": TEST_SESSKEY})
        assert logout_response == ""
        assert self.gp_server.user_id is None


class TestGpServerErrorHandling:
    """Test error handling."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_session_manager = MockSessionManager()
        self.gp_server = GpServer(self.mock_session_manager)
        self.gp_server.transport = MockTransport()
        self.gp_server.peername = ("127.0.0.1", 12345)

    def test_getprofile_missing_profileid(self):
        """Test getprofile with missing profileid returns error."""
        response = self.gp_server.handle_getprofile({"sesskey": TEST_SESSKEY, "id": "2"})

        assert "\\error\\" in response
        assert "Missing profileid" in response

    def test_getprofile_invalid_profileid(self):
        """Test getprofile with invalid profileid returns error."""
        response = self.gp_server.handle_getprofile({"profileid": "not_a_number", "sesskey": TEST_SESSKEY, "id": "2"})

        assert "\\error\\" in response
        assert "Invalid profileid" in response

    def test_login_missing_authtoken(self):
        """Test login with missing authtoken returns error."""
        response = self.gp_server.handle_login({"challenge": TEST_CHALLENGE, "id": "1"})

        assert "\\error\\" in response
        assert "Missing authtoken" in response


class TestGpServerNewHandlers:
    """Test new GP server handlers (addbuddy, authadd, pinvite, ka)."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_session_manager = MockSessionManager()
        self.gp_server = GpServer(self.mock_session_manager)
        self.gp_server.transport = MockTransport()
        self.gp_server.peername = ("127.0.0.1", 12345)
        self.gp_server.sesskey = TEST_SESSKEY
        self.gp_server.persona_id = 200001
        self.gp_server.user_id = 100001

    def test_handle_addbuddy_returns_bm4(self):
        """Test addbuddy returns bm type 4 acknowledgment."""
        with (
            patch("app.servers.gp_server.create_session"),
            patch("app.servers.gp_server.create_buddy_request"),
            patch("app.servers.gp_server.get_persona_by_id"),
        ):
            response = self.gp_server.handle_addbuddy({"sesskey": TEST_SESSKEY, "newprofileid": "300001", "reason": ""})

            assert "\\bm\\4" in response
            assert "300001" in response

    def test_handle_addbuddy_without_persona_id_returns_empty(self):
        """Test addbuddy without persona_id returns empty."""
        self.gp_server.persona_id = None

        response = self.gp_server.handle_addbuddy({"sesskey": TEST_SESSKEY, "newprofileid": "300001"})

        assert response == ""

    def test_handle_authadd_calls_accept_buddy_request(self):
        """Test authadd calls accept_buddy_request."""
        with (
            patch("app.servers.gp_server.create_session"),
            patch("app.servers.gp_server.accept_buddy_request") as mock_accept,
        ):
            mock_accept.return_value = True

            response = self.gp_server.handle_authadd(
                {"sesskey": TEST_SESSKEY, "fromprofileid": "300001", "sig": "00000000000000000000000000000000"}
            )

            mock_accept.assert_called_once()
            assert response == ""

    def test_handle_pinvite_creates_invite(self):
        """Test pinvite creates game invite."""
        with (
            patch("app.servers.gp_server.create_session"),
            patch("app.servers.gp_server.create_game_invite") as mock_invite,
        ):
            response = self.gp_server.handle_pinvite(
                {
                    "sesskey": TEST_SESSKEY,
                    "profileid": "300001",
                    "productid": "11419",
                    "location": "2166 219975299 0 PW: #HOST:testplayer",
                }
            )

            mock_invite.assert_called_once()
            assert response == ""

    def test_handle_pinvite_without_persona_id_returns_empty(self):
        """Test pinvite without persona_id returns empty."""
        self.gp_server.persona_id = None

        response = self.gp_server.handle_pinvite(
            {"sesskey": TEST_SESSKEY, "profileid": "300001", "productid": "11419", "location": "test"}
        )

        assert response == ""

    def test_parse_addbuddy_request(self):
        """Test parsing addbuddy request."""
        request = f"\\addbuddy\\\\sesskey\\{TEST_SESSKEY}\\newprofileid\\300001\\reason\\\\final\\"

        result = self.gp_server.parse_request(request)

        assert result.get("sesskey") == TEST_SESSKEY
        assert result.get("newprofileid") == "300001"

    def test_parse_authadd_request(self):
        """Test parsing authadd request."""
        request = f"\\authadd\\\\sesskey\\{TEST_SESSKEY}\\fromprofileid\\300001\\sig\\00000000000000000000000000000000\\final\\"

        result = self.gp_server.parse_request(request)

        assert result.get("sesskey") == TEST_SESSKEY
        assert result.get("fromprofileid") == "300001"
        assert result.get("sig") == "00000000000000000000000000000000"

    def test_parse_pinvite_request(self):
        """Test parsing pinvite request."""
        location = "2166 219975299 0 PW: #HOST:testplayer testplayer #FROM:testplayer #CHAN:#GSP!redalert3pc!TestLobby"
        request = (
            f"\\pinvite\\\\sesskey\\{TEST_SESSKEY}\\profileid\\300001\\productid\\11419\\location\\{location}\\final\\"
        )

        result = self.gp_server.parse_request(request)

        assert result.get("sesskey") == TEST_SESSKEY
        assert result.get("profileid") == "300001"
        assert result.get("productid") == "11419"
        assert "#GSP!redalert3pc!" in result.get("location", "")


class TestGpServerConnection:
    """Test connection handling and challenge."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_session_manager = MockSessionManager()
        self.gp_server = GpServer(self.mock_session_manager)
        self.mock_transport = MockTransport()

    def test_connection_made_sends_challenge(self):
        """Test that connection_made sends initial challenge."""
        self.gp_server.connection_made(self.mock_transport)

        assert len(self.mock_transport.written) == 1
        written = self.mock_transport.written[0].decode()
        assert "\\lc\\1" in written
        assert "\\challenge\\" in written
        assert "\\final\\" in written

    def test_connection_made_generates_challenge(self):
        """Test that connection_made generates a challenge string."""
        self.gp_server.connection_made(self.mock_transport)

        assert hasattr(self.gp_server, "server_challenge")
        # Server challenge is 10 uppercase letters (matches real data: RKSUWPOCWX)
        assert len(self.gp_server.server_challenge) == 10
        assert self.gp_server.server_challenge.isupper()

    def test_generate_challenge_is_random(self):
        """Test that _generate_challenge produces different values."""
        challenge1 = self.gp_server._generate_challenge()
        challenge2 = self.gp_server._generate_challenge()

        assert challenge1 != challenge2
        # Server challenge is 10 uppercase letters
        assert len(challenge1) == 10
        assert len(challenge2) == 10
        assert challenge1.isupper()
        assert challenge2.isupper()


class TestGpServerIPConversion:
    """Test IP address conversion."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_session_manager = MockSessionManager()
        self.gp_server = GpServer(self.mock_session_manager)

    def test_ip_to_int_localhost(self):
        """Test IP to int conversion for localhost."""
        result = self.gp_server._ip_to_int("127.0.0.1")
        assert result == 2130706433  # 127*2^24 + 0*2^16 + 0*2^8 + 1

    def test_ip_to_int_example(self):
        """Test IP to int conversion for example IP."""
        # 95.87.147.176 -> 1600311728 (from example data)
        result = self.gp_server._ip_to_int("95.87.147.176")
        assert result == (95 << 24) + (87 << 16) + (147 << 8) + 176

    def test_ip_to_int_invalid(self):
        """Test IP to int conversion handles invalid IP."""
        result = self.gp_server._ip_to_int("invalid")
        assert result == 0


class TestBuddyMessageFormat:
    """Test buddy message (bm) format parsing."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_session_manager = MockSessionManager()
        self.gp_server = GpServer(self.mock_session_manager)

    def _parse_bm_message(self, bm_msg: str) -> dict:
        """Parse pipe-separated buddy message format."""
        # Format: |key|value|key|value|...
        # First character is |, so we skip it and filter empty parts
        parts = [p for p in bm_msg.split("|") if p]
        data = {}
        for i in range(0, len(parts) - 1, 2):
            data[parts[i]] = parts[i + 1]
        return data

    def test_parse_bm_status_message(self):
        """Test parsing buddy status message format."""
        # Example: \bm\100\f\1000535979\msg\|s|4|ss|Chatting|ls|2166|ip|1600311736|p|0|qm|0\final\
        # This is a server-to-client message, but we test the format understanding

        bm_msg = "|s|4|ss|Chatting|ls|2166|ip|1600311736|p|0|qm|0"
        data = self._parse_bm_message(bm_msg)

        assert data.get("s") == "4"  # Status code
        assert data.get("ss") == "Chatting"  # Status string
        assert data.get("ls") == "2166"  # Location string
        assert data.get("ip") == "1600311736"  # IP address (as int)
        assert data.get("p") == "0"  # Port
        assert data.get("qm") == "0"  # Queue mode

    def test_parse_bm_offline_message(self):
        """Test parsing buddy offline message."""
        # Example: \bm\100\f\1000535979\msg\|s|0|ss|Offline\final\

        bm_msg = "|s|0|ss|Offline"
        data = self._parse_bm_message(bm_msg)

        assert data.get("s") == "0"  # Offline status code
        assert data.get("ss") == "Offline"

    def test_parse_bm_online_message(self):
        """Test parsing buddy online message."""
        bm_msg = "|s|1|ss|Online|ls||ip|1600311736|p|0|qm|0"
        data = self._parse_bm_message(bm_msg)

        assert data.get("s") == "1"  # Online status code
        assert data.get("ss") == "Online"

    def test_parse_bm_staging_message(self):
        """Test parsing buddy staging message."""
        bm_msg = "|s|3|ss|Staging|ls|testplayer|ip|1600311736|p|0|qm|0"
        data = self._parse_bm_message(bm_msg)

        assert data.get("s") == "3"  # Staging status code
        assert data.get("ss") == "Staging"
        assert data.get("ls") == "testplayer"  # Location is host name
