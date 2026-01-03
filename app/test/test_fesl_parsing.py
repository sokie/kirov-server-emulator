"""
Tests for FESL protocol parsing and serialization.

Tests cover:
- FeslHeader parsing from bytes
- FESL packet parsing (header + payload)
- Model serialization to key-value strings
- Round-trip packet creation and parsing
- All authentication-related TXN types
"""

import base64
import struct

from app.models.fesl_types import (
    EntitledGameFeatureWrapper,
    FeslHeader,
    FeslType,
    GameSpyPreAuthClient,
    GameSpyPreAuthServer,
    HelloClient,
    MemcheckClient,
    MemcheckServer,
    NuGetPersonasClient,
    NuGetPersonasServer,
    NuLoginClient,
    NuLoginPersonaClient,
    NuLoginPersonaServer,
    NuLoginServer,
)
from app.servers.fesl_server import create_packet, parse_game_data


class TestFeslHeader:
    """Tests for FESL header parsing."""

    def test_parse_valid_header(self):
        """Test parsing a valid FESL header."""
        # fsys command, TAG_SINGLE_CLIENT (0xC0), packet number 1, size 176 (0xB0)
        header_bytes = struct.pack(">4sII", b"fsys", 0xC0000001, 0x000000B0)

        header, data_size = FeslHeader.from_bytes(header_bytes)

        assert header is not None
        assert header.fesl_command == "fsys"
        assert header.fesl_type == FeslType.TAG_SINGLE_CLIENT
        assert header.packet_number == 1
        assert header.packet_size == 176
        assert data_size == 176 - 12  # packet_size - header_size

    def test_parse_acct_header(self):
        """Test parsing an 'acct' command header."""
        # acct command, TAG_SINGLE_CLIENT (0xC0), packet number 2, size 109 (0x6D)
        header_bytes = struct.pack(">4sII", b"acct", 0xC0000002, 0x0000006D)

        header, data_size = FeslHeader.from_bytes(header_bytes)

        assert header is not None
        assert header.fesl_command == "acct"
        assert header.fesl_type == FeslType.TAG_SINGLE_CLIENT
        assert header.packet_number == 2
        assert data_size == 109 - 12

    def test_parse_server_response_header(self):
        """Test parsing a server response header (TAG_SINGLE_SERVER)."""
        # acct command, TAG_SINGLE_SERVER (0x80), packet number 2
        header_bytes = struct.pack(">4sII", b"acct", 0x80000002, 0x00000100)

        header, data_size = FeslHeader.from_bytes(header_bytes)

        assert header is not None
        assert header.fesl_type == FeslType.TAG_SINGLE_SERVER

    def test_parse_short_data_fails(self):
        """Test that parsing fails with insufficient data."""
        short_data = b"fsys"  # Only 4 bytes, need 12

        header, data_size = FeslHeader.from_bytes(short_data)

        assert header is None
        assert data_size == -1

    def test_header_repr(self):
        """Test header string representation."""
        header_bytes = struct.pack(">4sII", b"acct", 0xC0000001, 0x00000064)
        header, _ = FeslHeader.from_bytes(header_bytes)

        repr_str = repr(header)

        assert "acct" in repr_str
        assert "TAG_SINGLE_CLIENT" in repr_str


class TestHelloClientParsing:
    """Tests for Hello client request parsing."""

    def test_parse_hello_client(self):
        """Test parsing a Hello client request packet."""
        # Real Hello packet structure (simplified)
        payload = (
            b"TXN=Hello\n"
            b"clientString=cncra3-pc\n"
            b"sku=15299\n"
            b"locale=en_US\n"
            b"clientPlatform=PC\n"
            b"clientVersion=1.0\n"
            b"SDKVersion=4.3.4.0.0\n"
            b"protocolVersion=2.0\n"
            b"fragmentSize=8096\n"
            b"clientType=\n\x00"
        )

        packet_size = 12 + len(payload)
        header_bytes = struct.pack(">4sII", b"fsys", 0xC0000001, packet_size)
        packet = bytearray(header_bytes + payload)

        header, model = parse_game_data(packet)

        assert header is not None
        assert header.fesl_command == "fsys"
        assert isinstance(model, HelloClient)
        assert model.txn == "Hello"
        assert model.clientString == "cncra3-pc"
        assert model.sku == "15299"
        assert model.locale == "en_US"
        assert model.clientPlatform == "PC"

    def test_hello_client_to_string(self):
        """Test serializing HelloClient to key-value string."""
        hello = HelloClient(
            txn="Hello",
            clientString="cncra3-pc",
            sku=15299,
            locale="en_US",
            clientPlatform="PC",
            clientVersion="1.0",
            SDKVersion="4.3.4.0.0",
            protocolVersion="2.0",
            fragmentSize=8096,
            clientType="",
        )

        result = hello.to_key_value_string()

        assert "TXN=Hello" in result
        assert "clientString=cncra3-pc" in result
        assert "sku=15299" in result


class TestNuLoginParsing:
    """Tests for NuLogin request/response parsing."""

    def test_parse_nulogin_client(self):
        """Test parsing a NuLogin client request."""
        payload = (
            b"TXN=NuLogin\n"
            b"returnEncryptedInfo=1\n"
            b"nuid=test@example.com\n"
            b"password=testpass123\n"
            b"macAddr=$aabbccddeeff\n\x00"
        )

        packet_size = 12 + len(payload)
        header_bytes = struct.pack(">4sII", b"acct", 0xC0000002, packet_size)
        packet = bytearray(header_bytes + payload)

        header, model = parse_game_data(packet)

        assert header is not None
        assert header.fesl_command == "acct"
        assert isinstance(model, NuLoginClient)
        assert model.txn == "NuLogin"
        assert model.nuid == "test@example.com"
        assert model.password == "testpass123"
        assert model.macAddr == "$aabbccddeeff"

    def test_nulogin_server_response_serialization(self):
        """Test serializing NuLoginServer response to key-value string."""
        feature = EntitledGameFeatureWrapper(
            gameFeatureId=6014, entitlementExpirationDays=-1, entitlementExpirationDate="", message="", status=0
        )

        response = NuLoginServer(
            txn="NuLogin",
            displayName="testplayer",
            lkey="TestLkeyToken123456789.",
            userId=1000001,
            profileId=1000001,
            nuid=1000001,
            entitledGameFeatureWrappers=[feature],
        )

        result = response.to_key_value_string()

        assert "TXN=NuLogin" in result
        assert "displayName=testplayer" in result
        assert "lkey=TestLkeyToken123456789." in result
        assert "userId=1000001" in result
        assert "profileId=1000001" in result
        assert "entitledGameFeatureWrappers.[]=1" in result
        assert "entitledGameFeatureWrappers.0.gameFeatureId=6014" in result
        assert "entitledGameFeatureWrappers.0.entitlementExpirationDays=-1" in result
        assert "entitledGameFeatureWrappers.0.status=0" in result

    def test_nulogin_packet_creation(self):
        """Test creating a complete NuLogin response packet."""
        feature = EntitledGameFeatureWrapper(
            gameFeatureId=6014, entitlementExpirationDays=-1, entitlementExpirationDate="", message="", status=0
        )

        response = NuLoginServer(
            txn="NuLogin",
            displayName="testplayer",
            lkey="TestLkeyToken123456789.",
            userId=1000001,
            profileId=1000001,
            nuid=1000001,
            entitledGameFeatureWrappers=[feature],
        )

        packet = create_packet("acct", FeslType.TAG_SINGLE_SERVER, 2, response)

        assert packet is not None
        assert len(packet) > 12
        # Verify header
        assert packet[0:4] == b"acct"


class TestNuGetPersonasParsing:
    """Tests for NuGetPersonas request/response parsing."""

    def test_nugetpersonas_client_serialization(self):
        """Test NuGetPersonas client request serialization."""
        request = NuGetPersonasClient(txn="NuGetPersonas", namespace="")

        result = request.to_key_value_string()

        assert "TXN=NuGetPersonas" in result
        assert "namespace=" in result

    def test_nugetpersonas_server_response(self):
        """Test NuGetPersonas server response with personas."""
        response = NuGetPersonasServer(txn="NuGetPersonas", personas=["testplayer", "altchar"])

        result = response.to_key_value_string()

        assert "TXN=NuGetPersonas" in result
        assert "personas.[]=2" in result
        assert "personas.0=testplayer" in result
        assert "personas.1=altchar" in result

    def test_nugetpersonas_single_persona(self):
        """Test NuGetPersonas response with single persona."""
        response = NuGetPersonasServer(txn="NuGetPersonas", personas=["testplayer"])

        result = response.to_key_value_string()

        assert "personas.[]=1" in result
        assert "personas.0=testplayer" in result

    def test_nugetpersonas_empty_personas(self):
        """Test NuGetPersonas response with no personas."""
        response = NuGetPersonasServer(txn="NuGetPersonas", personas=[])

        result = response.to_key_value_string()

        assert "personas.[]=0" in result


class TestNuLoginPersonaParsing:
    """Tests for NuLoginPersona request/response parsing."""

    def test_nuloginpersona_client_serialization(self):
        """Test NuLoginPersona client request serialization."""
        request = NuLoginPersonaClient(txn="NuLoginPersona", name="testplayer")

        result = request.to_key_value_string()

        assert "TXN=NuLoginPersona" in result
        assert "name=testplayer" in result

    def test_nuloginpersona_server_response(self):
        """Test NuLoginPersona server response serialization."""
        response = NuLoginPersonaServer(
            txn="NuLoginPersona",
            userId=1000001,
            lkey="NewLkeyAfterPersonaLogin.",
            profileId=2000001,  # Different from userId - this is the persona ID
        )

        result = response.to_key_value_string()

        assert "TXN=NuLoginPersona" in result
        assert "userId=1000001" in result
        assert "lkey=NewLkeyAfterPersonaLogin." in result
        assert "profileId=2000001" in result

    def test_nuloginpersona_profileid_differs_from_userid(self):
        """Test that profileId (persona) can differ from userId."""
        response = NuLoginPersonaServer(txn="NuLoginPersona", userId=1000001, lkey="TestKey123.", profileId=2000001)

        result = response.to_key_value_string()

        # Verify both IDs are present and different
        assert "userId=1000001" in result
        assert "profileId=2000001" in result


class TestGameSpyPreAuthParsing:
    """Tests for GameSpyPreAuth request/response parsing."""

    def test_gamespypreauth_client_serialization(self):
        """Test GameSpyPreAuth client request serialization."""
        request = GameSpyPreAuthClient(txn="GameSpyPreAuth")

        result = request.to_key_value_string()

        assert "TXN=GameSpyPreAuth" in result

    def test_gamespypreauth_server_response(self):
        """Test GameSpyPreAuth server response serialization."""
        # Ticket format: base64(userId|personaId|secretToken)
        ticket_payload = "1000001|2000001|xYz123AbC456DeFgHiJk"
        ticket = base64.b64encode(ticket_payload.encode()).decode()

        response = GameSpyPreAuthServer(txn="GameSpyPreAuth", challenge="abcd1234", ticket=ticket)

        result = response.to_key_value_string()

        assert "TXN=GameSpyPreAuth" in result
        assert "challenge=abcd1234" in result
        assert f"ticket={ticket}" in result

    def test_gamespypreauth_ticket_format(self):
        """Test that the ticket follows the correct format."""
        # Real ticket format: base64(userId|personaId|secretToken)
        user_id = 1000001
        persona_id = 2000001
        secret_token = "RandomSecretToken123"

        ticket_payload = f"{user_id}|{persona_id}|{secret_token}"
        ticket = base64.b64encode(ticket_payload.encode()).decode()

        # Verify we can decode it back
        decoded = base64.b64decode(ticket).decode()
        parts = decoded.split("|")

        assert len(parts) == 3
        assert int(parts[0]) == user_id
        assert int(parts[1]) == persona_id
        assert parts[2] == secret_token


class TestMemcheckParsing:
    """Tests for MemCheck request/response parsing."""

    def test_memcheck_server_serialization(self):
        """Test MemCheck server response serialization."""
        response = MemcheckServer(txn="MemCheck", type=0, salt=12345)

        result = response.to_key_value_string()

        assert "TXN=MemCheck" in result
        assert "type=0" in result
        assert "salt=12345" in result

    def test_memcheck_client_serialization(self):
        """Test MemCheck client response serialization."""
        response = MemcheckClient(txn="MemCheck", result="")

        result = response.to_key_value_string()

        assert "TXN=MemCheck" in result
        assert "result=" in result


class TestPacketRoundTrip:
    """Tests for packet creation and parsing round-trips."""

    def test_hello_client_round_trip(self):
        """Test creating and parsing a HelloClient packet."""
        original = HelloClient(
            txn="Hello",
            clientString="cncra3-pc",
            sku=15299,
            locale="en_US",
            clientPlatform="PC",
            clientVersion="1.0",
            SDKVersion="4.3.4.0.0",
            protocolVersion="2.0",
            fragmentSize=8096,
            clientType="",
        )

        packet = create_packet("fsys", FeslType.TAG_SINGLE_CLIENT, 1, original)
        header, parsed = parse_game_data(packet)

        assert header is not None
        assert header.fesl_command == "fsys"
        assert header.packet_number == 1
        assert isinstance(parsed, HelloClient)
        assert parsed.txn == "Hello"
        assert parsed.clientString == "cncra3-pc"

    def test_nulogin_server_round_trip(self):
        """Test creating and parsing a NuLoginServer packet."""
        feature = EntitledGameFeatureWrapper(
            gameFeatureId=6014, entitlementExpirationDays=-1, entitlementExpirationDate="", message="", status=0
        )

        original = NuLoginServer(
            txn="NuLogin",
            displayName="testplayer",
            lkey="TestKey123.",
            userId=1000001,
            profileId=1000001,
            nuid=1000001,
            entitledGameFeatureWrappers=[feature],
        )

        packet = create_packet("acct", FeslType.TAG_SINGLE_SERVER, 2, original)
        header, parsed = parse_game_data(packet)

        assert header is not None
        assert header.fesl_command == "acct"
        assert header.fesl_type == FeslType.TAG_SINGLE_SERVER


class TestEntitledGameFeatureWrapper:
    """Tests for EntitledGameFeatureWrapper."""

    def test_feature_wrapper_defaults(self):
        """Test default values for EntitledGameFeatureWrapper."""
        wrapper = EntitledGameFeatureWrapper(gameFeatureId=6014)

        assert wrapper.gameFeatureId == 6014
        assert wrapper.entitlementExpirationDays == -1
        assert wrapper.entitlementExpirationDate == ""
        assert wrapper.message == ""
        assert wrapper.status == 0

    def test_multiple_feature_wrappers(self):
        """Test NuLoginServer with multiple entitlements."""
        features = [
            EntitledGameFeatureWrapper(gameFeatureId=6014, status=0),
            EntitledGameFeatureWrapper(gameFeatureId=6015, status=0),
            EntitledGameFeatureWrapper(gameFeatureId=6016, status=1),
        ]

        response = NuLoginServer(
            txn="NuLogin",
            displayName="testplayer",
            lkey="TestKey123.",
            userId=1000001,
            profileId=1000001,
            nuid=1000001,
            entitledGameFeatureWrappers=features,
        )

        result = response.to_key_value_string()

        assert "entitledGameFeatureWrappers.[]=3" in result
        assert "entitledGameFeatureWrappers.0.gameFeatureId=6014" in result
        assert "entitledGameFeatureWrappers.1.gameFeatureId=6015" in result
        assert "entitledGameFeatureWrappers.2.gameFeatureId=6016" in result
        assert "entitledGameFeatureWrappers.2.status=1" in result


class TestFeslTypeEnum:
    """Tests for FeslType enumeration."""

    def test_fesl_type_values(self):
        """Test FeslType enum values match protocol spec."""
        assert FeslType.TAG_SINGLE_CLIENT.value == 0xC0
        assert FeslType.TAG_SINGLE_SERVER.value == 0x80
        assert FeslType.TAG_MULTI_CLIENT.value == 0xF0
        assert FeslType.TAG_MULTI_SERVER.value == 0xB0

    def test_fesl_type_from_value(self):
        """Test creating FeslType from value."""
        assert FeslType(0xC0) == FeslType.TAG_SINGLE_CLIENT
        assert FeslType(0x80) == FeslType.TAG_SINGLE_SERVER


class TestAuthChainValidation:
    """Tests that validate the complete authentication chain format."""

    def test_nulogin_response_format(self):
        """Validate NuLogin response matches expected protocol format."""
        feature = EntitledGameFeatureWrapper(
            gameFeatureId=6014, entitlementExpirationDays=-1, entitlementExpirationDate="", message="", status=0
        )

        response = NuLoginServer(
            txn="NuLogin",
            displayName="testplayer",
            lkey="T4QdgDQCFm83wYUMCn4qpAAAKDw.",
            userId=1000001,
            profileId=1000001,
            nuid=1000001,
            entitledGameFeatureWrappers=[feature],
        )

        result = response.to_key_value_string()
        lines = result.split("\n")

        # Verify all required fields are present
        required_fields = [
            "TXN=NuLogin",
            "displayName=",
            "lkey=",
            "userId=",
            "profileId=",
            "nuid=",
            "entitledGameFeatureWrappers.[]=",
            "entitledGameFeatureWrappers.0.gameFeatureId=",
            "entitledGameFeatureWrappers.0.entitlementExpirationDays=",
            "entitledGameFeatureWrappers.0.status=",
        ]

        for field in required_fields:
            assert any(field in line for line in lines), f"Missing field: {field}"

    def test_nuloginpersona_response_format(self):
        """Validate NuLoginPersona response matches expected protocol format."""
        response = NuLoginPersonaServer(
            txn="NuLoginPersona", userId=1000001, lkey="T4QdfjQBRQh0wRHDCn4qoAAAKDw.", profileId=2000001
        )

        result = response.to_key_value_string()
        lines = result.split("\n")

        # Verify format matches: TXN, userId, lkey, profileId
        assert lines[0] == "TXN=NuLoginPersona"
        assert any("userId=1000001" in line for line in lines)
        assert any("profileId=2000001" in line for line in lines)
        assert any("lkey=" in line for line in lines)

    def test_gamespypreauth_response_format(self):
        """Validate GameSpyPreAuth response matches expected protocol format."""
        ticket = base64.b64encode(b"1000001|2000001|WEyCcbQQZ7oHzkSZr9fr").decode()

        response = GameSpyPreAuthServer(txn="GameSpyPreAuth", challenge="hiztauza", ticket=ticket)

        result = response.to_key_value_string()
        lines = result.split("\n")

        assert lines[0] == "TXN=GameSpyPreAuth"
        assert any("challenge=hiztauza" in line for line in lines)
        assert any("ticket=" in line for line in lines)
