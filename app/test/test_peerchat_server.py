"""
Tests for the IRC/Peerchat Server.

These tests cover:
1. IRC message parsing and serialization
2. IRC command handling (NICK, USER, JOIN, PART, etc.)
3. GameSpy extensions (GETCKEY, SETCKEY, CDKEY, UTM, USRIP)
4. Server response formats based on real protocol structure

Format examples validated (using placeholder data):
- USRIP response: :s 302  :=+@<ip>
- Welcome: :s 001 <nick> :Welcome to the Matrix <nick>
- JOIN broadcast: :<nick>!<encoded>|<profileid>@* JOIN #<channel>
- 702 BCAST: :s 702 #<channel> #<channel> <nick> BCAST \\key\\value
"""

import pytest

# Configure pytest-asyncio mode
pytest_plugins = ("pytest_asyncio",)

from app.models.irc_types import IRCChannel, IRCMessage, IRCNumeric, IRCUser
from app.models.peerchat_state import (
    irc_channels,
    irc_clients,
    irc_clients_lock,
    join_channel,
    part_channel,
)
from app.servers.peerchat_handlers import IRCFactory
from app.servers.peerchat_server import IRCClient

# =============================================================================
# Test Data Constants (placeholder/fake data)
# =============================================================================

TEST_IP = "192.168.1.100"
TEST_NICKNAME = "testplayer"
TEST_NICKNAME_2 = "otherplayer"
TEST_ENCODED_IP = "TestToken"
TEST_PROFILE_ID = 123456789
TEST_USERNAME = f"{TEST_ENCODED_IP}|{TEST_PROFILE_ID}"
TEST_CDKEY_HASH = "AAAA1111BBBB2222CCCC"
TEST_AUTH_TOKEN = "00000000000000000000000000000000"
TEST_GPG_CHANNEL = "#GPG!1234"
TEST_GSP_CHANNEL = "#GSP!testgame!TestSession"
TEST_REALNAME = "testrealname"


# =============================================================================
# IRC Message Parsing Tests
# =============================================================================


class TestIRCMessageParsing:
    """Test IRC message parsing from wire format."""

    def test_parse_simple_command(self):
        """Test parsing a simple command without prefix."""
        message = IRCMessage.parse(f"NICK {TEST_NICKNAME}")

        assert message.command == "NICK"
        assert message.params == [TEST_NICKNAME]
        assert message.prefix is None

    def test_parse_usrip_command(self):
        """Test parsing USRIP command (first command client sends)."""
        message = IRCMessage.parse("USRIP")

        assert message.command == "USRIP"
        assert message.params == []

    def test_parse_user_command_gamespy_format(self):
        """Test parsing USER command in GameSpy format."""
        # Format: USER <encoded_ip|profile_id> <local_ip> <server> :<auth_token>
        line = f"USER {TEST_USERNAME} 127.0.0.1 peerchat.gamespy.com :{TEST_AUTH_TOKEN}"
        message = IRCMessage.parse(line)

        assert message.command == "USER"
        assert message.params[0] == TEST_USERNAME
        assert message.params[1] == "127.0.0.1"
        assert message.params[2] == "peerchat.gamespy.com"
        assert message.params[3] == TEST_AUTH_TOKEN

    def test_parse_cdkey_command(self):
        """Test parsing CDKEY command."""
        message = IRCMessage.parse(f"CDKEY {TEST_CDKEY_HASH}")

        assert message.command == "CDKEY"
        assert message.params == [TEST_CDKEY_HASH]

    def test_parse_join_command_with_trailing_space(self):
        """Test parsing JOIN command with trailing space (as seen in real data)."""
        message = IRCMessage.parse(f"JOIN {TEST_GPG_CHANNEL} ")

        assert message.command == "JOIN"
        assert TEST_GPG_CHANNEL in message.params[0]

    def test_parse_join_gsp_channel(self):
        """Test parsing JOIN for GSP (game session) channel."""
        message = IRCMessage.parse(f"JOIN {TEST_GSP_CHANNEL}")

        assert message.command == "JOIN"
        assert message.params[0] == TEST_GSP_CHANNEL

    def test_parse_pong_command(self):
        """Test parsing PONG command with trailing."""
        message = IRCMessage.parse("PONG :s")

        assert message.command == "PONG"
        assert message.params == ["s"]

    def test_parse_mode_query_command(self):
        """Test parsing MODE query command."""
        message = IRCMessage.parse(f"MODE {TEST_GPG_CHANNEL}")

        assert message.command == "MODE"
        assert message.params == [TEST_GPG_CHANNEL]

    def test_parse_mode_set_command(self):
        """Test parsing MODE set command with parameters."""
        # Format: MODE #channel +l <limit>
        message = IRCMessage.parse(f"MODE {TEST_GSP_CHANNEL} +l 6")

        assert message.command == "MODE"
        assert message.params[0] == TEST_GSP_CHANNEL
        assert message.params[1] == "+l"
        assert message.params[2] == "6"

    def test_parse_mode_complex_flags(self):
        """Test parsing MODE with complex flag string."""
        # Format: MODE #channel -i-p-s-m-n-t+l+e <limit>
        message = IRCMessage.parse(f"MODE {TEST_GSP_CHANNEL} -i-p-s-m-n-t+l+e 6")

        assert message.command == "MODE"
        assert message.params[0] == TEST_GSP_CHANNEL
        assert message.params[1] == "-i-p-s-m-n-t+l+e"
        assert message.params[2] == "6"

    def test_parse_getckey_command_wildcard(self):
        """Test parsing GETCKEY command with wildcard target (GameSpy extension)."""
        # Format: GETCKEY #channel * <request_id> <flags> :\\key1\\key2
        line = f"GETCKEY {TEST_GPG_CHANNEL} * 000 0 :\\username\\b_flags"
        message = IRCMessage.parse(line)

        assert message.command == "GETCKEY"
        assert message.params[0] == TEST_GPG_CHANNEL
        assert message.params[1] == "*"  # wildcard for all users
        assert message.params[2] == "000"  # request ID
        assert message.params[3] == "0"  # flags
        assert "username" in message.params[4]

    def test_parse_getckey_multiple_keys(self):
        """Test parsing GETCKEY with multiple keys."""
        line = f"GETCKEY {TEST_GPG_CHANNEL} * 001 0 :\\b_wins\\b_losses\\b_rank"
        message = IRCMessage.parse(line)

        assert message.command == "GETCKEY"
        assert message.params[0] == TEST_GPG_CHANNEL
        assert message.params[1] == "*"
        assert message.params[2] == "001"
        assert "b_wins" in message.params[4]

    def test_parse_setckey_command(self):
        """Test parsing SETCKEY command (GameSpy extension)."""
        # Format: SETCKEY #channel <nick> :\\key\\value
        line = f"SETCKEY {TEST_GPG_CHANNEL} {TEST_NICKNAME} :\\b_flags\\s"
        message = IRCMessage.parse(line)

        assert message.command == "SETCKEY"
        assert message.params[0] == TEST_GPG_CHANNEL
        assert message.params[1] == TEST_NICKNAME
        assert "b_flags" in message.params[2]

    def test_parse_setckey_complex_data(self):
        """Test parsing SETCKEY with complex game stats."""
        line = f"SETCKEY {TEST_GPG_CHANNEL} {TEST_NICKNAME} :\\b_wins\\10\\b_losses\\5\\b_rank\\100"
        message = IRCMessage.parse(line)

        assert message.command == "SETCKEY"
        assert message.params[0] == TEST_GPG_CHANNEL
        assert message.params[1] == TEST_NICKNAME
        assert "b_wins" in message.params[2]

    def test_parse_topic_command(self):
        """Test parsing TOPIC command."""
        message = IRCMessage.parse(f"TOPIC {TEST_GSP_CHANNEL} :{TEST_NICKNAME} {TEST_NICKNAME}")

        assert message.command == "TOPIC"
        assert message.params[0] == TEST_GSP_CHANNEL
        assert message.params[1] == f"{TEST_NICKNAME} {TEST_NICKNAME}"

    def test_parse_utm_channel_command(self):
        """Test parsing UTM command to channel (GameSpy extension)."""
        message = IRCMessage.parse(f"UTM {TEST_GSP_CHANNEL} :PN/ 0={TEST_NICKNAME}")

        assert message.command == "UTM"
        assert message.params[0] == TEST_GSP_CHANNEL
        assert f"PN/ 0={TEST_NICKNAME}" in message.params[1]

    def test_parse_utm_user_command(self):
        """Test parsing UTM command to specific user."""
        message = IRCMessage.parse(f"UTM {TEST_NICKNAME} :MAP 1")

        assert message.command == "UTM"
        assert message.params[0] == TEST_NICKNAME
        assert message.params[1] == "MAP 1"

    def test_parse_utm_game_data(self):
        """Test parsing UTM with complex game data."""
        line = f"UTM {TEST_GSP_CHANNEL} :SL/ M=testmap;MC=ABC123"
        message = IRCMessage.parse(line)

        assert message.command == "UTM"
        assert message.params[0] == TEST_GSP_CHANNEL
        assert "SL/" in message.params[1]
        assert "testmap" in message.params[1]

    def test_parse_part_command(self):
        """Test parsing PART command."""
        message = IRCMessage.parse(f"PART {TEST_GSP_CHANNEL} :")

        assert message.command == "PART"
        assert message.params[0] == TEST_GSP_CHANNEL

    def test_parse_part_with_reason(self):
        """Test parsing PART command with reason."""
        message = IRCMessage.parse(f"PART {TEST_GPG_CHANNEL} :leaving")

        assert message.command == "PART"
        assert message.params[0] == TEST_GPG_CHANNEL
        assert message.params[1] == "leaving"

    def test_parse_who_command(self):
        """Test parsing WHO command."""
        message = IRCMessage.parse(f"WHO {TEST_NICKNAME}")

        assert message.command == "WHO"
        assert message.params == [TEST_NICKNAME]

    def test_parse_server_join_message(self):
        """Test parsing server JOIN message with prefix."""
        # Format: :<nick>!<username>@* JOIN #channel
        line = f":{TEST_NICKNAME}!{TEST_USERNAME}@* JOIN {TEST_GPG_CHANNEL}"
        message = IRCMessage.parse(line)

        assert message.prefix == f"{TEST_NICKNAME}!{TEST_USERNAME}@*"
        assert message.command == "JOIN"
        assert message.params == [TEST_GPG_CHANNEL]

    def test_parse_server_part_message(self):
        """Test parsing server PART message with prefix."""
        line = f":{TEST_NICKNAME}!{TEST_USERNAME}@* PART {TEST_GPG_CHANNEL} :leaving"
        message = IRCMessage.parse(line)

        assert message.prefix == f"{TEST_NICKNAME}!{TEST_USERNAME}@*"
        assert message.command == "PART"
        assert message.params[0] == TEST_GPG_CHANNEL
        assert message.params[1] == "leaving"


# =============================================================================
# IRC Message Serialization Tests
# =============================================================================


class TestIRCMessageSerialization:
    """Test IRC message serialization to wire format."""

    def test_serialize_simple_command(self):
        """Test serializing a simple command."""
        message = IRCMessage(command="NICK", params=[TEST_NICKNAME])

        assert message.serialize() == f"NICK {TEST_NICKNAME}"

    def test_serialize_with_server_prefix(self):
        """Test serializing with short server prefix (GameSpy style)."""
        # Format: :s 001 <nick> :Welcome message
        message = IRCMessage(
            command="001", params=[TEST_NICKNAME, f"Welcome to the Matrix {TEST_NICKNAME}"], prefix="s"
        )

        result = message.serialize()
        assert result.startswith(":s 001")
        assert TEST_NICKNAME in result

    def test_serialize_with_user_prefix(self):
        """Test serializing a message with user prefix (GameSpy format with * hostname)."""
        # Format: :<nick>!<username>@* JOIN #channel
        message = IRCMessage(command="JOIN", params=[TEST_GPG_CHANNEL], prefix=f"{TEST_NICKNAME}!{TEST_USERNAME}@*")

        result = message.serialize()
        assert result.startswith(f":{TEST_NICKNAME}!{TEST_USERNAME}@*")
        assert "JOIN" in result
        assert TEST_GPG_CHANNEL in result

    def test_serialize_with_trailing(self):
        """Test serializing a message with trailing parameter containing spaces."""
        message = IRCMessage(command="PRIVMSG", params=["#channel", "Hello World!"])

        result = message.serialize()
        assert ":Hello World!" in result

    def test_serialize_usrip_response(self):
        """Test serializing USRIP response (302)."""
        # Format: :s 302  :=+@<ip>
        message = IRCMessage(command="302", params=["", f"=+@{TEST_IP}"], prefix="s")

        result = message.serialize()
        assert ":s 302" in result
        assert "=+@" in result

    def test_serialize_702_bcast_response(self):
        """Test serializing 702 BCAST response."""
        # Format: :s 702 #channel #channel <nick> BCAST \\key\\value
        message = IRCMessage(
            command="702",
            params=[TEST_GPG_CHANNEL, TEST_GPG_CHANNEL, TEST_NICKNAME, "BCAST", "\\b_flags\\s"],
            prefix="s",
        )

        result = message.serialize()
        assert ":s 702" in result
        assert TEST_GPG_CHANNEL in result
        assert "BCAST" in result


# =============================================================================
# IRCUser Tests
# =============================================================================


class TestIRCUser:
    """Test IRCUser data class."""

    def test_get_prefix_gamespy_format(self):
        """Test user prefix generation uses * as hostname (GameSpy format)."""
        # Format: <nick>!<username>@*
        user = IRCUser(
            nickname=TEST_NICKNAME,
            username=TEST_USERNAME,
            hostname=TEST_IP,  # Real IP ignored, uses *
        )

        prefix = user.get_prefix()
        # GameSpy uses * as hostname in messages
        assert prefix == f"{TEST_NICKNAME}!{TEST_USERNAME}@*"

    def test_is_registered(self):
        """Test registration check requires both NICK and USER."""
        user = IRCUser()
        assert not user.is_registered()

        user.nickname = TEST_NICKNAME
        assert not user.is_registered()

        user.username = TEST_USERNAME
        assert user.is_registered()

    def test_profile_id_storage(self):
        """Test profile_id can be stored on user."""
        user = IRCUser()
        user.profile_id = TEST_PROFILE_ID

        assert user.profile_id == TEST_PROFILE_ID


# =============================================================================
# IRCChannel Tests
# =============================================================================


class TestIRCChannel:
    """Test IRCChannel data class."""

    def test_is_private_gsp_channel(self):
        """Test private channel detection for GSP channels (game lobbies)."""
        # GSP channels are private game sessions
        channel = IRCChannel(name=TEST_GSP_CHANNEL)
        assert channel.is_private()

    def test_is_not_private_gpg_channel(self):
        """Test public channel detection for GPG channels (chat lobbies)."""
        # GPG channels are public chat lobbies
        channel = IRCChannel(name=TEST_GPG_CHANNEL)
        assert not channel.is_private()

    def test_is_operator(self):
        """Test operator check."""
        channel = IRCChannel(name=TEST_GPG_CHANNEL)
        channel.operators.add(TEST_NICKNAME)

        assert channel.is_operator(TEST_NICKNAME)
        assert not channel.is_operator("other")

    def test_user_stats_storage(self):
        """Test user stats dictionary for GameSpy GETCKEY/SETCKEY."""
        channel = IRCChannel(name=TEST_GPG_CHANNEL)
        channel.user_stats[TEST_NICKNAME] = {"b_flags": "s", "b_wins": "10", "b_losses": "5"}

        assert channel.user_stats[TEST_NICKNAME]["b_wins"] == "10"


# =============================================================================
# Mock Classes for Testing
# =============================================================================


class MockStreamReader:
    """Mock asyncio StreamReader for testing."""

    def __init__(self, data: list[bytes]):
        self.data = data
        self.index = 0

    async def readline(self) -> bytes:
        if self.index < len(self.data):
            line = self.data[self.index]
            self.index += 1
            return line
        return b""


class MockStreamWriter:
    """Mock asyncio StreamWriter for testing."""

    def __init__(self):
        self.written = []
        self.closed = False

    def write(self, data: bytes):
        self.written.append(data)

    async def drain(self):
        pass

    def get_extra_info(self, name):
        if name == "peername":
            return (TEST_IP, 12345)
        return None

    def close(self):
        self.closed = True

    async def wait_closed(self):
        pass

    def get_all_written(self) -> bytes:
        """Get all written data concatenated."""
        return b"".join(self.written)


# =============================================================================
# IRCClient Tests
# =============================================================================


class TestIRCClient:
    """Test IRCClient class."""

    def setup_method(self):
        """Set up test fixtures."""
        self.reader = MockStreamReader([])
        self.writer = MockStreamWriter()
        self.client = IRCClient(self.reader, self.writer, (TEST_IP, 12345))

    @pytest.mark.asyncio
    async def test_send_message(self):
        """Test sending an IRC message."""
        message = IRCMessage(command="PONG", params=["s"])

        await self.client.send_message(message)

        assert len(self.writer.written) == 1
        assert b"PONG" in self.writer.written[0]
        assert b"s" in self.writer.written[0]

    @pytest.mark.asyncio
    async def test_send_numeric_with_short_prefix(self):
        """Test sending a numeric reply uses 's' as server prefix."""
        await self.client.send_numeric(IRCNumeric.RPL_WELCOME, "Welcome!")

        assert len(self.writer.written) == 1
        # Should use 's' as prefix like real GameSpy server
        assert b":s 001" in self.writer.written[0]
        assert b"Welcome!" in self.writer.written[0]


# =============================================================================
# USRIP Command Tests
# =============================================================================


class TestUSRIPCommand:
    """Test USRIP command handling."""

    def setup_method(self):
        """Set up test fixtures."""
        self.reader = MockStreamReader([])
        self.writer = MockStreamWriter()
        self.client = IRCClient(self.reader, self.writer, (TEST_IP, 12345))

    @pytest.mark.asyncio
    async def test_usrip_returns_ip_in_gamespy_format(self):
        """Test USRIP returns IP in GameSpy format: :s 302  :=+@<ip>"""
        message = IRCMessage.parse("USRIP")

        await IRCFactory.handle_usrip(self.client, message)

        written = self.writer.get_all_written()
        # Format: :s 302  :=+@<ip>
        assert b":s 302" in written
        assert b"=+@" in written
        assert TEST_IP.encode() in written


# =============================================================================
# NICK Command Tests
# =============================================================================


class TestNICKCommand:
    """Test NICK command handling."""

    def setup_method(self):
        """Set up test fixtures and clear global state."""
        self.reader = MockStreamReader([])
        self.writer = MockStreamWriter()
        self.client = IRCClient(self.reader, self.writer, (TEST_IP, 12345))

        # Clear global state
        with irc_clients_lock:
            irc_clients.clear()
        irc_channels.clear()

    @pytest.mark.asyncio
    async def test_nick_sets_nickname(self):
        """Test NICK command sets the client nickname."""
        message = IRCMessage.parse(f"NICK {TEST_NICKNAME}")

        await IRCFactory.handle_nick(self.client, message)

        assert self.client.user.nickname == TEST_NICKNAME

    @pytest.mark.asyncio
    async def test_nick_registers_in_global_dict(self):
        """Test NICK command registers client in global dict."""
        message = IRCMessage.parse(f"NICK {TEST_NICKNAME}")

        await IRCFactory.handle_nick(self.client, message)

        with irc_clients_lock:
            assert TEST_NICKNAME in irc_clients
            assert irc_clients[TEST_NICKNAME] == self.client

    @pytest.mark.asyncio
    async def test_nick_no_params_error(self):
        """Test NICK with no parameters returns error 431."""
        message = IRCMessage(command="NICK", params=[])

        await IRCFactory.handle_nick(self.client, message)

        assert b"431" in self.writer.written[0]  # ERR_NONICKNAMEGIVEN


# =============================================================================
# USER Command Tests
# =============================================================================


class TestUSERCommand:
    """Test USER command handling."""

    def setup_method(self):
        """Set up test fixtures."""
        self.reader = MockStreamReader([])
        self.writer = MockStreamWriter()
        self.client = IRCClient(self.reader, self.writer, (TEST_IP, 12345))

    @pytest.mark.asyncio
    async def test_user_sets_fields_from_gamespy_format(self):
        """Test USER command parses GameSpy format."""
        # Format: USER <encoded_ip|profile_id> <local_ip> <server> :<auth_token>
        message = IRCMessage.parse(f"USER {TEST_USERNAME} 127.0.0.1 peerchat.gamespy.com :{TEST_AUTH_TOKEN}")

        await IRCFactory.handle_user(self.client, message)

        assert self.client.user.username == TEST_USERNAME
        assert self.client.user.realname == TEST_AUTH_TOKEN

    @pytest.mark.asyncio
    async def test_user_parses_profile_id(self):
        """Test USER command extracts profile_id from username."""
        # Username format: <encoded_ip>|<profile_id>
        message = IRCMessage.parse(f"USER {TEST_USERNAME} 127.0.0.1 peerchat.gamespy.com :token")

        await IRCFactory.handle_user(self.client, message)

        assert self.client.user.profile_id == TEST_PROFILE_ID

    @pytest.mark.asyncio
    async def test_user_not_enough_params_error(self):
        """Test USER with insufficient parameters returns error 461."""
        message = IRCMessage(command="USER", params=["user", "host"])

        await IRCFactory.handle_user(self.client, message)

        assert b"461" in self.writer.written[0]  # ERR_NEEDMOREPARAMS


# =============================================================================
# Welcome/Registration Tests
# =============================================================================


class TestWelcomeSequence:
    """Test welcome message sequence after registration."""

    def setup_method(self):
        """Set up test fixtures."""
        self.reader = MockStreamReader([])
        self.writer = MockStreamWriter()
        self.client = IRCClient(self.reader, self.writer, (TEST_IP, 12345))

        with irc_clients_lock:
            irc_clients.clear()

    @pytest.mark.asyncio
    async def test_welcome_sequence_sent_after_registration(self):
        """Test full welcome sequence (001-004 + MOTD) sent after USER+NICK."""
        user_msg = IRCMessage.parse(f"USER {TEST_USERNAME} 127.0.0.1 peerchat.gamespy.com :token")
        await IRCFactory.handle_user(self.client, user_msg)

        nick_msg = IRCMessage.parse(f"NICK {TEST_NICKNAME}")
        await IRCFactory.handle_nick(self.client, nick_msg)

        written = self.writer.get_all_written()

        # Server sends: 001, 002, 003, 004, 375, 372, 376
        assert b"001" in written  # RPL_WELCOME
        assert b"002" in written  # RPL_YOURHOST
        assert b"003" in written  # RPL_CREATED
        assert b"004" in written  # RPL_MYINFO
        assert b"375" in written  # RPL_MOTDSTART
        assert b"372" in written  # RPL_MOTD
        assert b"376" in written  # RPL_ENDOFMOTD

    @pytest.mark.asyncio
    async def test_welcome_message_format(self):
        """Test welcome message matches GameSpy format."""
        user_msg = IRCMessage.parse(f"USER {TEST_USERNAME} 127.0.0.1 peerchat.gamespy.com :token")
        await IRCFactory.handle_user(self.client, user_msg)

        nick_msg = IRCMessage.parse(f"NICK {TEST_NICKNAME}")
        await IRCFactory.handle_nick(self.client, nick_msg)

        written = self.writer.get_all_written()

        # Format: :s 001 <nick> :Welcome to the Matrix <nick>
        assert b":s 001" in written
        assert TEST_NICKNAME.encode() in written
        assert b"Welcome to the Matrix" in written


# =============================================================================
# CDKEY Command Tests
# =============================================================================


class TestCDKEYCommand:
    """Test GameSpy CDKEY command handling."""

    def setup_method(self):
        """Set up test fixtures."""
        self.reader = MockStreamReader([])
        self.writer = MockStreamWriter()
        self.client = IRCClient(self.reader, self.writer, (TEST_IP, 12345))
        self.client.user.nickname = TEST_NICKNAME

    @pytest.mark.asyncio
    async def test_cdkey_authenticates_and_sends_ping(self):
        """Test CDKEY returns 706 and sends PING like real server."""
        message = IRCMessage.parse(f"CDKEY {TEST_CDKEY_HASH}")

        await IRCFactory.handle_cdkey(self.client, message)

        # Server sends: :s 706 <nick> 1 :Authenticated followed by PING :s
        assert len(self.writer.written) == 2
        assert b"706" in self.writer.written[0]
        assert b"PING" in self.writer.written[1]

    @pytest.mark.asyncio
    async def test_cdkey_stores_hash(self):
        """Test CDKEY stores the hash on the user."""
        message = IRCMessage.parse(f"CDKEY {TEST_CDKEY_HASH}")

        await IRCFactory.handle_cdkey(self.client, message)

        assert self.client.user.cdkey_hash == TEST_CDKEY_HASH


# =============================================================================
# JOIN Command Tests
# =============================================================================


class TestJOINCommand:
    """Test JOIN command handling."""

    def setup_method(self):
        """Set up test fixtures and clear global state."""
        self.reader = MockStreamReader([])
        self.writer = MockStreamWriter()
        self.client = IRCClient(self.reader, self.writer, (TEST_IP, 12345))
        self.client.user.nickname = TEST_NICKNAME
        self.client.user.username = TEST_USERNAME

        # Clear global state
        with irc_clients_lock:
            irc_clients.clear()
            irc_clients[TEST_NICKNAME] = self.client
        irc_channels.clear()

    @pytest.mark.asyncio
    async def test_join_creates_channel(self):
        """Test JOIN creates new channel."""
        message = IRCMessage.parse(f"JOIN {TEST_GPG_CHANNEL}")

        await IRCFactory.handle_join(self.client, message)

        assert TEST_GPG_CHANNEL in irc_channels

    @pytest.mark.asyncio
    async def test_join_adds_user_to_channel(self):
        """Test JOIN adds user to channel."""
        message = IRCMessage.parse(f"JOIN {TEST_GPG_CHANNEL}")

        await IRCFactory.handle_join(self.client, message)

        channel = irc_channels[TEST_GPG_CHANNEL]
        assert TEST_NICKNAME in channel.users

    @pytest.mark.asyncio
    async def test_join_first_user_becomes_operator(self):
        """Test first user to join becomes channel operator."""
        message = IRCMessage.parse(f"JOIN {TEST_GSP_CHANNEL}")

        await IRCFactory.handle_join(self.client, message)

        channel = irc_channels[TEST_GSP_CHANNEL]
        assert TEST_NICKNAME in channel.operators

    @pytest.mark.asyncio
    async def test_join_sends_names_reply(self):
        """Test JOIN sends 353 NAMREPLY and 366 ENDOFNAMES."""
        message = IRCMessage.parse(f"JOIN {TEST_GPG_CHANNEL}")

        await IRCFactory.handle_join(self.client, message)

        written = self.writer.get_all_written()
        # Format: :s 353 <nick> = #channel :@<nick>
        assert b"353" in written  # RPL_NAMREPLY
        assert b"366" in written  # RPL_ENDOFNAMES

    @pytest.mark.asyncio
    async def test_join_sends_join_notification(self):
        """Test JOIN broadcasts join notification with user prefix."""
        message = IRCMessage.parse(f"JOIN {TEST_GPG_CHANNEL}")

        await IRCFactory.handle_join(self.client, message)

        written = self.writer.get_all_written()
        # Format: :<nick>!<username>@* JOIN #channel
        assert f"{TEST_NICKNAME}!{TEST_USERNAME}@*".encode() in written
        assert b"JOIN" in written

    @pytest.mark.asyncio
    async def test_join_bad_channel_mask_error(self):
        """Test JOIN with invalid channel name returns error 476."""
        message = IRCMessage.parse("JOIN invalid_channel")

        await IRCFactory.handle_join(self.client, message)

        assert b"476" in self.writer.written[0]  # ERR_BADCHANMASK


# =============================================================================
# PART Command Tests
# =============================================================================


class TestPARTCommand:
    """Test PART command handling."""

    def setup_method(self):
        """Set up test fixtures and clear global state."""
        self.reader = MockStreamReader([])
        self.writer = MockStreamWriter()
        self.client = IRCClient(self.reader, self.writer, (TEST_IP, 12345))
        self.client.user.nickname = TEST_NICKNAME
        self.client.user.username = TEST_USERNAME
        self.client.user.channels.add(TEST_GPG_CHANNEL)

        # Clear global state
        with irc_clients_lock:
            irc_clients.clear()
            irc_clients[TEST_NICKNAME] = self.client
        irc_channels.clear()

        # Create channel with user
        channel = IRCChannel(name=TEST_GPG_CHANNEL)
        channel.users.add(TEST_NICKNAME)
        irc_channels[TEST_GPG_CHANNEL] = channel

    @pytest.mark.asyncio
    async def test_part_removes_user_from_channel(self):
        """Test PART removes user from channel."""
        message = IRCMessage.parse(f"PART {TEST_GPG_CHANNEL} :")

        await IRCFactory.handle_part(self.client, message)

        channel = irc_channels.get(TEST_GPG_CHANNEL)
        if channel:
            assert TEST_NICKNAME not in channel.users

    @pytest.mark.asyncio
    async def test_part_broadcasts_with_reason(self):
        """Test PART broadcasts part message with reason."""
        message = IRCMessage.parse(f"PART {TEST_GPG_CHANNEL} :leaving")

        await IRCFactory.handle_part(self.client, message)

        written = self.writer.get_all_written()
        # Format: :<nick>!<username>@* PART #channel :reason
        assert b"PART" in written
        assert f"{TEST_NICKNAME}!".encode() in written

    @pytest.mark.asyncio
    async def test_part_not_on_channel_error(self):
        """Test PART when not on channel returns error 442."""
        self.client.user.channels.discard(TEST_GPG_CHANNEL)
        message = IRCMessage.parse(f"PART {TEST_GPG_CHANNEL} :")

        await IRCFactory.handle_part(self.client, message)

        assert b"442" in self.writer.written[0]  # ERR_NOTONCHANNEL


# =============================================================================
# MODE Command Tests
# =============================================================================


class TestMODECommand:
    """Test MODE command handling."""

    def setup_method(self):
        """Set up test fixtures."""
        self.reader = MockStreamReader([])
        self.writer = MockStreamWriter()
        self.client = IRCClient(self.reader, self.writer, (TEST_IP, 12345))
        self.client.user.nickname = TEST_NICKNAME

        irc_channels.clear()
        channel = IRCChannel(name=TEST_GPG_CHANNEL)
        channel.users.add(TEST_NICKNAME)
        channel.operators.add(TEST_NICKNAME)
        irc_channels[TEST_GPG_CHANNEL] = channel

    @pytest.mark.asyncio
    async def test_mode_query_returns_channel_mode(self):
        """Test MODE query returns 324 with channel mode."""
        message = IRCMessage.parse(f"MODE {TEST_GPG_CHANNEL}")

        await IRCFactory.handle_mode(self.client, message)

        written = self.writer.get_all_written()
        # Format: :s 324 <nick> #channel +
        assert b"324" in written  # RPL_CHANNELMODEIS

    @pytest.mark.asyncio
    async def test_mode_set_with_params(self):
        """Test MODE set with parameters."""
        # Format: MODE #channel +l <limit>
        gsp_channel = IRCChannel(name="#GSP!testgame!test1")
        gsp_channel.users.add(TEST_NICKNAME)
        gsp_channel.operators.add(TEST_NICKNAME)
        irc_channels["#GSP!testgame!test1"] = gsp_channel

        message = IRCMessage.parse("MODE #GSP!testgame!test1 +l 6")

        await IRCFactory.handle_mode(self.client, message)

        channel = irc_channels["#GSP!testgame!test1"]
        assert "l" in channel.modes or "+l" in channel.modes

    @pytest.mark.asyncio
    async def test_mode_complex_flags(self):
        """Test MODE with complex flag string."""
        gsp_channel = IRCChannel(name="#GSP!testgame!test2")
        gsp_channel.users.add(TEST_NICKNAME)
        irc_channels["#GSP!testgame!test2"] = gsp_channel

        message = IRCMessage.parse("MODE #GSP!testgame!test2 -i-p-s-m-n-t+l+e 6")

        await IRCFactory.handle_mode(self.client, message)

        # Should not raise and should store mode
        channel = irc_channels["#GSP!testgame!test2"]
        assert channel.modes is not None


# =============================================================================
# TOPIC Command Tests
# =============================================================================


class TestTOPICCommand:
    """Test TOPIC command handling."""

    def setup_method(self):
        """Set up test fixtures."""
        self.reader = MockStreamReader([])
        self.writer = MockStreamWriter()
        self.client = IRCClient(self.reader, self.writer, (TEST_IP, 12345))
        self.client.user.nickname = TEST_NICKNAME

        with irc_clients_lock:
            irc_clients.clear()
            irc_clients[TEST_NICKNAME] = self.client

        irc_channels.clear()
        channel = IRCChannel(name=TEST_GSP_CHANNEL)
        channel.users.add(TEST_NICKNAME)
        channel.operators.add(TEST_NICKNAME)
        irc_channels[TEST_GSP_CHANNEL] = channel

    @pytest.mark.asyncio
    async def test_topic_set_by_operator(self):
        """Test TOPIC sets channel topic when user is operator."""
        message = IRCMessage.parse(f"TOPIC {TEST_GSP_CHANNEL} :{TEST_NICKNAME} {TEST_NICKNAME}")

        await IRCFactory.handle_topic(self.client, message)

        channel = irc_channels[TEST_GSP_CHANNEL]
        assert channel.topic == f"{TEST_NICKNAME} {TEST_NICKNAME}"

    @pytest.mark.asyncio
    async def test_topic_broadcasts_change(self):
        """Test TOPIC broadcasts topic change."""
        message = IRCMessage.parse(f"TOPIC {TEST_GSP_CHANNEL} :test topic")

        await IRCFactory.handle_topic(self.client, message)

        written = self.writer.get_all_written()
        # Format: :<nick> TOPIC #channel :topic
        assert b"TOPIC" in written

    @pytest.mark.asyncio
    async def test_topic_get_no_topic(self):
        """Test TOPIC query returns 331 when no topic set."""
        message = IRCMessage.parse(f"TOPIC {TEST_GSP_CHANNEL}")

        await IRCFactory.handle_topic(self.client, message)

        assert b"331" in self.writer.written[0]  # RPL_NOTOPIC


# =============================================================================
# PING/PONG Command Tests
# =============================================================================


class TestPINGPONGCommands:
    """Test PING/PONG handling."""

    def setup_method(self):
        """Set up test fixtures."""
        self.reader = MockStreamReader([])
        self.writer = MockStreamWriter()
        self.client = IRCClient(self.reader, self.writer, (TEST_IP, 12345))

    @pytest.mark.asyncio
    async def test_ping_responds_with_pong(self):
        """Test PING command receives PONG response."""
        message = IRCMessage.parse("PING :s")

        await IRCFactory.handle_ping(self.client, message)

        assert len(self.writer.written) == 1
        assert b"PONG" in self.writer.written[0]
        assert b":s" in self.writer.written[0]

    @pytest.mark.asyncio
    async def test_pong_updates_timestamp(self):
        """Test PONG updates last_pong_time."""

        old_time = self.client.last_pong_time

        message = IRCMessage.parse("PONG :s")
        await IRCFactory.handle_pong(self.client, message)

        assert self.client.last_pong_time >= old_time


# =============================================================================
# GETCKEY Command Tests
# =============================================================================


class TestGETCKEYCommand:
    """Test GameSpy GETCKEY command handling."""

    def setup_method(self):
        """Set up test fixtures."""
        self.reader = MockStreamReader([])
        self.writer = MockStreamWriter()
        self.client = IRCClient(self.reader, self.writer, (TEST_IP, 12345))
        self.client.user.nickname = TEST_NICKNAME
        self.client.user.username = TEST_USERNAME

        with irc_clients_lock:
            irc_clients.clear()
            irc_clients[TEST_NICKNAME] = self.client

        irc_channels.clear()
        channel = IRCChannel(name=TEST_GPG_CHANNEL)
        channel.users.add(TEST_NICKNAME)
        channel.user_stats[TEST_NICKNAME] = {"b_flags": "s", "b_wins": "10", "b_losses": "5"}
        irc_channels[TEST_GPG_CHANNEL] = channel

    @pytest.mark.asyncio
    async def test_getckey_wildcard_returns_all_users(self):
        """Test GETCKEY with * returns stats for all users."""
        # Format: GETCKEY #channel * <request_id> <flags> :\\keys
        message = IRCMessage.parse(f"GETCKEY {TEST_GPG_CHANNEL} * 000 0 :\\username\\b_flags")

        await IRCFactory.handle_getckey(self.client, message)

        written = self.writer.get_all_written()
        # Should have 702 response and 703 end marker
        assert b"702" in written
        assert b"703" in written

    @pytest.mark.asyncio
    async def test_getckey_returns_username(self):
        """Test GETCKEY returns username field from user object."""
        message = IRCMessage.parse(f"GETCKEY {TEST_GPG_CHANNEL} * 000 0 :\\username")

        await IRCFactory.handle_getckey(self.client, message)

        written = self.writer.get_all_written()
        # Should include the encoded username
        assert TEST_USERNAME.encode() in written

    @pytest.mark.asyncio
    async def test_getckey_ends_with_703(self):
        """Test GETCKEY always ends with 703 marker."""
        # Format: :s 703 <nick> #channel <request_id> :End of GETCKEY
        message = IRCMessage.parse(f"GETCKEY {TEST_GPG_CHANNEL} * 000 0 :\\username")

        await IRCFactory.handle_getckey(self.client, message)

        written = self.writer.get_all_written()
        assert b"703" in written
        assert b"End of GETCKEY" in written

    @pytest.mark.asyncio
    async def test_getckey_no_such_channel_error(self):
        """Test GETCKEY with invalid channel returns error 403."""
        message = IRCMessage.parse("GETCKEY #invalid * 000 0 :\\username")

        await IRCFactory.handle_getckey(self.client, message)

        assert b"403" in self.writer.written[0]  # ERR_NOSUCHCHANNEL


# =============================================================================
# SETCKEY Command Tests
# =============================================================================


class TestSETCKEYCommand:
    """Test GameSpy SETCKEY command handling."""

    def setup_method(self):
        """Set up test fixtures."""
        self.reader = MockStreamReader([])
        self.writer = MockStreamWriter()
        self.client = IRCClient(self.reader, self.writer, (TEST_IP, 12345))
        self.client.user.nickname = TEST_NICKNAME
        self.client.user.channels.add(TEST_GPG_CHANNEL)

        with irc_clients_lock:
            irc_clients.clear()
            irc_clients[TEST_NICKNAME] = self.client

        irc_channels.clear()
        channel = IRCChannel(name=TEST_GPG_CHANNEL)
        channel.users.add(TEST_NICKNAME)
        irc_channels[TEST_GPG_CHANNEL] = channel

    @pytest.mark.asyncio
    async def test_setckey_updates_user_stats(self):
        """Test SETCKEY updates user stats in channel."""
        # Format: SETCKEY #channel <nick> :\\key\\value
        message = IRCMessage.parse(f"SETCKEY {TEST_GPG_CHANNEL} {TEST_NICKNAME} :\\b_flags\\s")

        await IRCFactory.handle_setckey(self.client, message)

        channel = irc_channels[TEST_GPG_CHANNEL]
        assert TEST_NICKNAME in channel.user_stats
        assert channel.user_stats[TEST_NICKNAME].get("b_flags") == "s"

    @pytest.mark.asyncio
    async def test_setckey_broadcasts_702_bcast(self):
        """Test SETCKEY broadcasts 702 BCAST to channel."""
        # Format: :s 702 #channel #channel <nick> BCAST \\key\\value
        message = IRCMessage.parse(f"SETCKEY {TEST_GPG_CHANNEL} {TEST_NICKNAME} :\\b_flags\\s")

        await IRCFactory.handle_setckey(self.client, message)

        written = self.writer.get_all_written()
        assert b"702" in written
        assert b"BCAST" in written
        assert TEST_GPG_CHANNEL.encode() in written

    @pytest.mark.asyncio
    async def test_setckey_complex_stats(self):
        """Test SETCKEY with complex game stats."""
        message = IRCMessage.parse(
            f"SETCKEY {TEST_GPG_CHANNEL} {TEST_NICKNAME} :\\b_wins\\10\\b_losses\\5\\b_rank\\100"
        )

        await IRCFactory.handle_setckey(self.client, message)

        channel = irc_channels[TEST_GPG_CHANNEL]
        stats = channel.user_stats[TEST_NICKNAME]
        assert stats.get("b_wins") == "10"
        assert stats.get("b_losses") == "5"


# =============================================================================
# UTM Command Tests
# =============================================================================


class TestUTMCommand:
    """Test GameSpy UTM command handling."""

    def setup_method(self):
        """Set up test fixtures."""
        self.reader = MockStreamReader([])
        self.writer = MockStreamWriter()
        self.client = IRCClient(self.reader, self.writer, (TEST_IP, 12345))
        self.client.user.nickname = TEST_NICKNAME
        self.client.user.username = TEST_USERNAME
        self.client.user.channels.add(TEST_GSP_CHANNEL)

        # Create another client to receive messages
        self.other_writer = MockStreamWriter()
        self.other_client = IRCClient(MockStreamReader([]), self.other_writer, ("10.0.0.1", 12346))
        self.other_client.user.nickname = TEST_NICKNAME_2
        self.other_client.user.username = "OtherToken|987654321"

        with irc_clients_lock:
            irc_clients.clear()
            irc_clients[TEST_NICKNAME] = self.client
            irc_clients[TEST_NICKNAME_2] = self.other_client

        irc_channels.clear()
        channel = IRCChannel(name=TEST_GSP_CHANNEL)
        channel.users.add(TEST_NICKNAME)
        channel.users.add(TEST_NICKNAME_2)
        irc_channels[TEST_GSP_CHANNEL] = channel

    @pytest.mark.asyncio
    async def test_utm_to_channel_broadcasts(self):
        """Test UTM to channel broadcasts to other members."""
        message = IRCMessage.parse(f"UTM {TEST_GSP_CHANNEL} :PN/ 0={TEST_NICKNAME}")

        await IRCFactory.handle_utm(self.client, message)

        # Other client should receive the UTM
        other_written = self.other_writer.get_all_written()
        assert b"UTM" in other_written
        assert f"PN/ 0={TEST_NICKNAME}".encode() in other_written

    @pytest.mark.asyncio
    async def test_utm_to_user_direct(self):
        """Test UTM to specific user sends directly."""
        message = IRCMessage.parse(f"UTM {TEST_NICKNAME_2} :MAP 1")

        await IRCFactory.handle_utm(self.client, message)

        # Other client should receive the UTM
        other_written = self.other_writer.get_all_written()
        assert b"UTM" in other_written
        assert b"MAP 1" in other_written

    @pytest.mark.asyncio
    async def test_utm_includes_sender_prefix(self):
        """Test UTM includes sender prefix in broadcast."""
        # Format: :<nick>!<username>@* UTM #channel :message
        message = IRCMessage.parse(f"UTM {TEST_GSP_CHANNEL} :test")

        await IRCFactory.handle_utm(self.client, message)

        other_written = self.other_writer.get_all_written()
        assert f"{TEST_NICKNAME}!".encode() in other_written

    @pytest.mark.asyncio
    async def test_utm_game_data(self):
        """Test UTM with complex game data."""
        message = IRCMessage.parse(f"UTM {TEST_GSP_CHANNEL} :SL/ M=testmap;MC=ABC123")

        await IRCFactory.handle_utm(self.client, message)

        # Should not raise
        other_written = self.other_writer.get_all_written()
        assert b"SL/" in other_written


# =============================================================================
# WHO Command Tests
# =============================================================================


class TestWHOCommand:
    """Test WHO command handling."""

    def setup_method(self):
        """Set up test fixtures."""
        self.reader = MockStreamReader([])
        self.writer = MockStreamWriter()
        self.client = IRCClient(self.reader, self.writer, (TEST_IP, 12345))
        self.client.user.nickname = TEST_NICKNAME
        self.client.user.username = TEST_USERNAME

        # Target user
        self.target_writer = MockStreamWriter()
        self.target_client = IRCClient(MockStreamReader([]), self.target_writer, ("10.0.0.1", 12346))
        self.target_client.user.nickname = TEST_NICKNAME_2
        self.target_client.user.username = "OtherToken|987654321"
        self.target_client.user.realname = TEST_REALNAME

        with irc_clients_lock:
            irc_clients.clear()
            irc_clients[TEST_NICKNAME] = self.client
            irc_clients[TEST_NICKNAME_2] = self.target_client

    @pytest.mark.asyncio
    async def test_who_user_returns_352_and_315(self):
        """Test WHO for user returns 352 WHOREPLY and 315 ENDOFWHO."""
        message = IRCMessage.parse(f"WHO {TEST_NICKNAME_2}")

        await IRCFactory.handle_who(self.client, message)

        written = self.writer.get_all_written()
        # Format: :s 352 <requester> * <username> * s <nick> H :0 <realname>
        assert b"352" in written  # RPL_WHOREPLY
        assert b"315" in written  # RPL_ENDOFWHO
        assert TEST_NICKNAME_2.encode() in written


# =============================================================================
# Channel Operations Tests
# =============================================================================


class TestChannelOperations:
    """Test channel join/part operations."""

    def setup_method(self):
        """Clear global state before each test."""
        with irc_clients_lock:
            irc_clients.clear()
        irc_channels.clear()

    @pytest.mark.asyncio
    async def test_join_channel_creates_new(self):
        """Test join_channel creates new channel if doesn't exist."""
        reader = MockStreamReader([])
        writer = MockStreamWriter()
        client = IRCClient(reader, writer, (TEST_IP, 12345))
        client.user.nickname = TEST_NICKNAME

        await join_channel(client, "#newchannel")

        assert "#newchannel" in irc_channels
        assert TEST_NICKNAME in irc_channels["#newchannel"].users

    @pytest.mark.asyncio
    async def test_part_channel_removes_user(self):
        """Test part_channel removes user from channel."""
        reader = MockStreamReader([])
        writer = MockStreamWriter()
        client = IRCClient(reader, writer, (TEST_IP, 12345))
        client.user.nickname = TEST_NICKNAME
        client.user.channels.add("#testchannel")

        channel = IRCChannel(name="#testchannel")
        channel.users.add(TEST_NICKNAME)
        irc_channels["#testchannel"] = channel

        await part_channel(client, "#testchannel")

        assert TEST_NICKNAME not in irc_channels["#testchannel"].users

    @pytest.mark.asyncio
    async def test_private_gsp_channel_deleted_when_empty(self):
        """Test private GSP channel is deleted when last user leaves."""
        reader = MockStreamReader([])
        writer = MockStreamWriter()
        client = IRCClient(reader, writer, (TEST_IP, 12345))
        client.user.nickname = TEST_NICKNAME
        client.user.channels.add("#GSP!testgame!testsession")

        channel = IRCChannel(name="#GSP!testgame!testsession")
        channel.users.add(TEST_NICKNAME)
        irc_channels["#GSP!testgame!testsession"] = channel

        await part_channel(client, "#GSP!testgame!testsession")

        # GSP channels are deleted when empty
        assert "#GSP!testgame!testsession" not in irc_channels


# =============================================================================
# Full Flow Integration Tests
# =============================================================================


class TestFullProtocolFlow:
    """Test complete protocol flows using placeholder data."""

    def setup_method(self):
        """Set up test fixtures and clear global state."""
        self.reader = MockStreamReader([])
        self.writer = MockStreamWriter()
        self.client = IRCClient(self.reader, self.writer, (TEST_IP, 12345))

        with irc_clients_lock:
            irc_clients.clear()
        irc_channels.clear()

    @pytest.mark.asyncio
    async def test_full_registration_flow(self):
        """Test complete registration: USRIP -> USER -> NICK -> CDKEY."""
        # Step 1: USRIP
        await IRCFactory.handle_usrip(self.client, IRCMessage.parse("USRIP"))

        # Step 2: USER + NICK (registration)
        await IRCFactory.handle_user(
            self.client, IRCMessage.parse(f"USER {TEST_USERNAME} 127.0.0.1 peerchat.gamespy.com :{TEST_AUTH_TOKEN}")
        )
        await IRCFactory.handle_nick(self.client, IRCMessage.parse(f"NICK {TEST_NICKNAME}"))

        # Step 3: CDKEY
        await IRCFactory.handle_cdkey(self.client, IRCMessage.parse(f"CDKEY {TEST_CDKEY_HASH}"))

        written = self.writer.get_all_written()

        # Verify all expected responses
        assert b"302" in written  # USRIP response
        assert b"001" in written  # Welcome
        assert b"375" in written  # MOTD start
        assert b"706" in written  # CDKEY OK
        assert b"PING" in written  # Post-auth PING

    @pytest.mark.asyncio
    async def test_join_channel_flow(self):
        """Test JOIN channel flow."""
        self.client.user.nickname = TEST_NICKNAME
        self.client.user.username = TEST_USERNAME

        with irc_clients_lock:
            irc_clients[TEST_NICKNAME] = self.client

        await IRCFactory.handle_join(self.client, IRCMessage.parse(f"JOIN {TEST_GPG_CHANNEL}"))

        # Should be in channel
        assert TEST_GPG_CHANNEL in self.client.user.channels

        written = self.writer.get_all_written()
        assert b"353" in written  # NAMREPLY
        assert b"366" in written  # ENDOFNAMES

    @pytest.mark.asyncio
    async def test_game_lobby_flow(self):
        """Test game lobby (GSP channel) flow."""
        self.client.user.nickname = TEST_NICKNAME
        self.client.user.username = TEST_USERNAME

        with irc_clients_lock:
            irc_clients[TEST_NICKNAME] = self.client

        # Join game lobby
        await IRCFactory.handle_join(self.client, IRCMessage.parse(f"JOIN {TEST_GSP_CHANNEL}"))

        # Set topic (as lobby host)
        await IRCFactory.handle_topic(
            self.client, IRCMessage.parse(f"TOPIC {TEST_GSP_CHANNEL} :{TEST_NICKNAME} {TEST_NICKNAME}")
        )

        # Set mode
        await IRCFactory.handle_mode(self.client, IRCMessage.parse(f"MODE {TEST_GSP_CHANNEL} +l 6"))

        # Verify
        channel = irc_channels[TEST_GSP_CHANNEL]
        assert channel.topic == f"{TEST_NICKNAME} {TEST_NICKNAME}"
        assert TEST_NICKNAME in channel.operators
        assert channel.is_private()

    @pytest.mark.asyncio
    async def test_setckey_getckey_flow(self):
        """Test SETCKEY then GETCKEY flow."""
        self.client.user.nickname = TEST_NICKNAME
        self.client.user.username = TEST_USERNAME
        self.client.user.channels.add(TEST_GPG_CHANNEL)

        with irc_clients_lock:
            irc_clients[TEST_NICKNAME] = self.client

        channel = IRCChannel(name=TEST_GPG_CHANNEL)
        channel.users.add(TEST_NICKNAME)
        irc_channels[TEST_GPG_CHANNEL] = channel

        # Set stats
        await IRCFactory.handle_setckey(
            self.client, IRCMessage.parse(f"SETCKEY {TEST_GPG_CHANNEL} {TEST_NICKNAME} :\\b_wins\\10\\b_losses\\5")
        )

        # Clear writer to check GETCKEY response
        self.writer.written.clear()

        # Get stats
        await IRCFactory.handle_getckey(
            self.client, IRCMessage.parse(f"GETCKEY {TEST_GPG_CHANNEL} * 000 0 :\\username\\b_wins\\b_losses")
        )

        written = self.writer.get_all_written()
        assert b"702" in written
        assert b"703" in written
