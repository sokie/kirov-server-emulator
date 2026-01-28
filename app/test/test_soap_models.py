"""
Tests for SOAP service models and response generation.

Tests the XML serialization and response patterns for:
- Sake Storage Service (GetMyRecords, GetSpecificRecords, SearchForRecords)
- Competition Service (CreateSession, SetReportIntention, SubmitReport)
- Auth Service (LoginRemoteAuth)
"""

import base64

import pytest
from sqlmodel import SQLModel

from app.db.database import engine
from app.soap.envelope import extract_soap_body, get_element_text, wrap_soap_envelope
from app.soap.models.auth import LoginRemoteAuthResponse, LoginResponseCode
from app.soap.models.common import RecordValue
from app.soap.models.competition import (
    CreateSessionResponse,
    SetReportIntentionResponse,
    SubmitReportResponse,
)
from app.soap.models.sake import (
    GetMyRecordsResponse,
    SAKEResultCode,
)
from app.soap.sake_service import (
    LEVEL_THRESHOLDS,
    SCORING_MULTIPLIERS,
    get_requested_fields,
    handle_get_my_records,
    handle_get_specific_records,
    handle_search_for_records,
    parse_login_ticket,
)

# Valid test login ticket: base64("12345|67890|testtoken")
VALID_LOGIN_TICKET = base64.b64encode(b"12345|67890|testtoken").decode("utf-8")


class TestSakeService:
    """Tests for Sake Storage Service response generation."""

    def test_get_my_records_response_with_score_and_rank(self):
        """Test GetMyRecordsResponse serializes correctly with score and rank values."""
        records = [
            RecordValue.from_int(1500),  # score
            RecordValue.from_int(25),  # rank
        ]
        response = GetMyRecordsResponse.success(records)
        xml = wrap_soap_envelope(response)

        assert "GetMyRecordsResponse" in xml
        assert "<GetMyRecordsResult>Success</GetMyRecordsResult>" in xml
        assert "<intValue><value>1500</value></intValue>" in xml
        assert "<intValue><value>25</value></intValue>" in xml
        assert "soap:Envelope" in xml
        assert "soap:Body" in xml

    def test_get_specific_records_scoring_multipliers(self):
        """Test GetSpecificRecords returns ScoringMultipliers as short values."""
        response = handle_get_specific_records("ScoringMultipliers", VALID_LOGIN_TICKET)
        xml = wrap_soap_envelope(response)

        assert "GetSpecificRecordsResponse" in xml
        assert "<GetSpecificRecordsResult>Success</GetSpecificRecordsResult>" in xml
        # Verify all 4 multipliers are present as shortValue
        for mult in SCORING_MULTIPLIERS:
            assert f"<shortValue><value>{mult}</value></shortValue>" in xml

    def test_get_specific_records_unknown_table_returns_empty(self):
        """Test GetSpecificRecords returns empty values for unknown tables."""
        response = handle_get_specific_records("UnknownTable", VALID_LOGIN_TICKET)
        xml = wrap_soap_envelope(response)

        assert "GetSpecificRecordsResponse" in xml
        assert "<GetSpecificRecordsResult>Success</GetSpecificRecordsResult>" in xml
        # Should have empty values container (self-closing when empty)
        assert "<values/>" in xml or "<values></values>" in xml

    def test_get_specific_records_invalid_login_ticket(self):
        """Test GetSpecificRecords returns LoginTicketInvalid for invalid ticket."""
        response = handle_get_specific_records("ScoringMultipliers", "invalid_ticket")
        xml = wrap_soap_envelope(response)

        assert "GetSpecificRecordsResponse" in xml
        assert f"<GetSpecificRecordsResult>{SAKEResultCode.LOGIN_TICKET_INVALID}</GetSpecificRecordsResult>" in xml

    def test_get_specific_records_unranked_losses(self):
        """Test GetSpecificRecords returns defaults for UnrankedLosses table."""
        response = handle_get_specific_records("UnrankedLosses", VALID_LOGIN_TICKET)
        xml = wrap_soap_envelope(response)

        assert "GetSpecificRecordsResponse" in xml
        assert "<GetSpecificRecordsResult>Success</GetSpecificRecordsResult>" in xml
        # All default to 0
        assert xml.count("<shortValue><value>0</value></shortValue>") == 4

    def test_search_for_records_levels_filter(self):
        """Test SearchForRecords returns XP thresholds for Levels table."""
        response = handle_search_for_records("Levels", "", VALID_LOGIN_TICKET)
        xml = wrap_soap_envelope(response)

        assert "SearchForRecordsResponse" in xml
        assert "<SearchForRecordsResult>Success</SearchForRecordsResult>" in xml
        # Verify first few level thresholds are present
        assert "<intValue><value>0</value></intValue>" in xml  # Level 1
        assert "<intValue><value>5</value></intValue>" in xml  # Level 2
        assert "<intValue><value>13</value></intValue>" in xml  # Level 3
        # Should have 87 ArrayOfRecordValue elements (one per level)
        assert xml.count("<ArrayOfRecordValue>") == len(LEVEL_THRESHOLDS)

    def test_search_for_records_news_ticker_returns_empty(self):
        """Test SearchForRecords returns empty for NewsTicker table."""
        response = handle_search_for_records("NewsTicker", "", VALID_LOGIN_TICKET)
        xml = wrap_soap_envelope(response)

        assert "SearchForRecordsResponse" in xml
        assert "<SearchForRecordsResult>Success</SearchForRecordsResult>" in xml

    def test_search_for_records_invalid_login_ticket(self):
        """Test SearchForRecords returns LoginTicketInvalid for invalid ticket."""
        response = handle_search_for_records("Levels", "", "invalid_ticket")
        xml = wrap_soap_envelope(response)

        assert "SearchForRecordsResponse" in xml
        assert f"<SearchForRecordsResult>{SAKEResultCode.LOGIN_TICKET_INVALID}</SearchForRecordsResult>" in xml

    def test_get_my_records_invalid_login_ticket(self):
        """Test GetMyRecords returns LoginTicketInvalid for invalid ticket."""
        response = handle_get_my_records("invalid_ticket", 0, ["score", "rank"])
        xml = wrap_soap_envelope(response)

        assert "GetMyRecordsResponse" in xml
        assert f"<GetMyRecordsResult>{SAKEResultCode.LOGIN_TICKET_INVALID}</GetMyRecordsResult>" in xml

    def test_parse_login_ticket_valid(self):
        """Test parsing a valid base64 login ticket."""
        import base64

        ticket = base64.b64encode(b"12345|67890|sometoken").decode("utf-8")
        user_id, persona_id = parse_login_ticket(ticket)

        assert user_id == 12345
        assert persona_id == 67890

    def test_parse_login_ticket_invalid(self):
        """Test parsing an invalid login ticket returns zeros."""
        user_id, persona_id = parse_login_ticket("invalid_ticket")

        assert user_id == 0
        assert persona_id == 0


class TestCompetitionModels:
    """Tests for Competition Service response models."""

    def test_create_session_response_success(self):
        """Test CreateSessionResponse success serialization with csid and ccid."""
        response = CreateSessionResponse.success(csid="session123", ccid="channel456")
        xml = wrap_soap_envelope(response)

        assert "CreateSessionResponse" in xml
        assert "<CreateSessionResult>" in xml
        assert "<result>0</result>" in xml  # 0 = SUCCESS
        assert "<message/>" in xml or "<message></message>" in xml
        assert "<csid>session123</csid>" in xml
        assert "<ccid>channel456</ccid>" in xml
        assert "soap:Envelope" in xml

    def test_create_session_response_error(self):
        """Test CreateSessionResponse error serialization."""
        response = CreateSessionResponse.error(code=1)
        xml = wrap_soap_envelope(response)

        assert "CreateSessionResponse" in xml
        assert "<CreateSessionResult>" in xml
        assert "<result>1</result>" in xml  # 1 = ERROR

    def test_set_report_intention_response_success(self):
        """Test SetReportIntentionResponse success serialization with csid and ccid."""
        response = SetReportIntentionResponse.success(csid="session123", ccid="channel789")
        xml = wrap_soap_envelope(response)

        assert "SetReportIntentionResponse" in xml
        assert "<SetReportIntentionResult>" in xml
        assert "<result>0</result>" in xml  # 0 = SUCCESS
        assert "<message/>" in xml or "<message></message>" in xml
        assert "<csid>session123</csid>" in xml
        assert "<ccid>channel789</ccid>" in xml

    def test_submit_report_response_success(self):
        """Test SubmitReportResponse success serialization."""
        response = SubmitReportResponse.success()
        xml = wrap_soap_envelope(response)

        assert "SubmitReportResponse" in xml
        assert "<SubmitReportResult>" in xml
        assert "<result>0</result>" in xml  # 0 = SUCCESS


class TestAuthModels:
    """Tests for Auth Service response models."""

    def test_login_remote_auth_response_success(self):
        """Test LoginRemoteAuthResponse success with certificate and crypto fields."""
        response = LoginRemoteAuthResponse.success(
            user_id=12345,
            profile_id=67890,
            nickname="TestPlayer",
            email="test@example.com",
            peerkeymodulus="ABC123DEF456",
            serverdata="SERVERDATA789",
            signature="SIGNATURE000",
            peerkeyprivate="PRIVATEKEY111",
            timestamp="1234567890",
        )
        xml = wrap_soap_envelope(response)

        # Check SOAP envelope structure
        assert "soap:Envelope" in xml
        assert "soap:Body" in xml
        assert "LoginRemoteAuthResponse" in xml

        # Check result structure
        assert "<responseCode>0</responseCode>" in xml

        # Check certificate fields
        assert "<userid>12345</userid>" in xml
        assert "<profileid>67890</profileid>" in xml
        assert "<profilenick>TestPlayer</profilenick>" in xml
        assert "<uniquenick>TestPlayer</uniquenick>" in xml
        assert "<email>test@example.com</email>" in xml

        # Check crypto fields
        assert "<peerkeymodulus>ABC123DEF456</peerkeymodulus>" in xml
        assert "<serverdata>SERVERDATA789</serverdata>" in xml
        assert "<signature>SIGNATURE000</signature>" in xml
        assert "<peerkeyprivate>PRIVATEKEY111</peerkeyprivate>" in xml
        assert "<timestamp>1234567890</timestamp>" in xml

        # Check default values
        assert "<peerkeyexponent>010001</peerkeyexponent>" in xml
        assert "<partnercode>60</partnercode>" in xml
        assert "<namespaceid>69</namespaceid>" in xml

    def test_login_remote_auth_response_error_user_not_found(self):
        """Test LoginRemoteAuthResponse error with USER_NOT_FOUND code."""
        response = LoginRemoteAuthResponse.error(LoginResponseCode.USER_NOT_FOUND)
        xml = wrap_soap_envelope(response)

        # Check SOAP envelope structure
        assert "soap:Envelope" in xml
        assert "soap:Body" in xml
        assert "LoginRemoteAuthResponse" in xml

        # Check error response code (2 = USER_NOT_FOUND)
        assert "<responseCode>2</responseCode>" in xml

        # Error response should NOT have actual certificate data (userid, profileid, etc.)
        assert "<userid>" not in xml
        assert "<profileid>" not in xml
        assert "<profilenick>" not in xml

    def test_login_remote_auth_response_error_invalid_profile(self):
        """Test LoginRemoteAuthResponse error with INVALID_PROFILE code."""
        response = LoginRemoteAuthResponse.error(LoginResponseCode.INVALID_PROFILE)
        xml = wrap_soap_envelope(response)

        # Check error response code (4 = INVALID_PROFILE)
        assert "<responseCode>4</responseCode>" in xml


class TestRecordValueSerialization:
    """Tests for RecordValue model serialization."""

    def test_record_value_from_int(self):
        """Test RecordValue.from_int serializes correctly."""
        record = RecordValue.from_int(42)
        xml = record.to_xml(encoding="unicode")

        assert "<RecordValue>" in xml
        assert "<intValue><value>42</value></intValue>" in xml

    def test_record_value_from_float(self):
        """Test RecordValue.from_float serializes correctly."""
        record = RecordValue.from_float(3.14)
        xml = record.to_xml(encoding="unicode")

        assert "<RecordValue>" in xml
        assert "<floatValue><value>3.14</value></floatValue>" in xml

    def test_record_value_from_short(self):
        """Test RecordValue.from_short serializes correctly."""
        record = RecordValue.from_short(100)
        xml = record.to_xml(encoding="unicode")

        assert "<RecordValue>" in xml
        assert "<shortValue><value>100</value></shortValue>" in xml


class TestSakeServiceIntegration:
    """Integration tests using real game request formats."""

    @pytest.fixture(autouse=True)
    def setup_database(self):
        """Set up a fresh database for each test."""
        SQLModel.metadata.create_all(engine)
        yield
        SQLModel.metadata.drop_all(engine)

    def test_search_for_records_player_stats_with_owner_filter(self):
        """
        Test SearchForRecords for PlayerStats_v5 with ownerid filter.

        """
        # Test login ticket: base64("12345|67890|testtoken")
        login_ticket = base64.b64encode(b"12345|67890|testtoken").decode("utf-8")

        # Real game request format with test data
        request_body = f"""<?xml version="1.0" encoding="UTF-8"?>
<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/"
                   xmlns:SOAP-ENC="http://schemas.xmlsoap.org/soap/encoding/"
                   xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
                   xmlns:xsd="http://www.w3.org/2001/XMLSchema"
                   xmlns:ns1="http://gamespy.net/sake">
    <SOAP-ENV:Body>
        <ns1:SearchForRecords>
            <ns1:gameid>2128</ns1:gameid>
            <ns1:secretKey>testkey</ns1:secretKey>
            <ns1:loginTicket>{login_ticket}</ns1:loginTicket>
            <ns1:tableid>PlayerStats_v5</ns1:tableid>
            <ns1:filter>ownerid=12345</ns1:filter>
            <ns1:sort>recordid</ns1:sort>
            <ns1:offset>0</ns1:offset>
            <ns1:max>1</ns1:max>
            <ns1:surrounding>0</ns1:surrounding>
            <ns1:ownerids></ns1:ownerids>
            <ns1:cacheFlag>0</ns1:cacheFlag>
            <ns1:fields>
                <ns1:string>Rank</ns1:string>
                <ns1:string>ownerid</ns1:string>
            </ns1:fields>
        </ns1:SearchForRecords>
    </SOAP-ENV:Body>
</SOAP-ENV:Envelope>"""

        # Parse the SOAP request like the handler does
        operation = extract_soap_body(request_body)
        table_id = get_element_text(operation, "tableid")
        filter_str = get_element_text(operation, "filter")

        assert table_id == "PlayerStats_v5"
        assert filter_str == "ownerid=12345"

        # Call the handler with parsed values
        login_ticket = get_element_text(operation, "loginTicket")
        response = handle_search_for_records(table_id, filter_str, login_ticket)
        xml = wrap_soap_envelope(response)

        # Verify response structure
        assert "SearchForRecordsResponse" in xml
        assert "<SearchForRecordsResult>Success</SearchForRecordsResult>" in xml
        assert "soap:Envelope" in xml
        assert "soap:Body" in xml

        assert xml.count("<ArrayOfRecordValue>") == 1
        assert xml.count("<RecordValue>") == 2
        assert "<intValue><value>57</value></intValue>" in xml
        # Owner ID echoed back
        assert "<intValue><value>12345</value></intValue>" in xml

    def test_get_my_records_player_stats_with_many_fields(self):
        """
        Test GetMyRecords for PlayerStats_v5 with many stat fields.

        Based on real game request format - tests field extraction and response
        returns correct number of values for each requested field.
        """
        # Test login ticket: base64("12345|67890|testtoken")
        login_ticket = base64.b64encode(b"12345|67890|testtoken").decode("utf-8")

        # Real game request format with test data (190 stat fields)
        request_body = f"""<?xml version="1.0" encoding="UTF-8"?>
<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/"
                   xmlns:SOAP-ENC="http://schemas.xmlsoap.org/soap/encoding/"
                   xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
                   xmlns:xsd="http://www.w3.org/2001/XMLSchema"
                   xmlns:ns1="http://gamespy.net/sake">
    <SOAP-ENV:Body>
        <ns1:GetMyRecords>
            <ns1:gameid>2128</ns1:gameid>
            <ns1:secretKey>testkey</ns1:secretKey>
            <ns1:loginTicket>{login_ticket}</ns1:loginTicket>
            <ns1:tableid>PlayerStats_v5</ns1:tableid>
            <ns1:fields>
                <ns1:string>CurrentWinStreak_UNRANKED</ns1:string>
                <ns1:string>CurrentWinStreak_RANKED1V1</ns1:string>
                <ns1:string>CurrentWinStreak_RANKED2V2</ns1:string>
                <ns1:string>CurrentWinStreak_CLAN1V1</ns1:string>
                <ns1:string>CurrentWinStreak_CLAN2V2</ns1:string>
                <ns1:string>CurrentLossStreak_UNRANKED</ns1:string>
                <ns1:string>CurrentLossStreak_RANKED1V1</ns1:string>
                <ns1:string>CurrentLossStreak_RANKED2V2</ns1:string>
                <ns1:string>CurrentLossStreak_CLAN1V1</ns1:string>
                <ns1:string>CurrentLossStreak_CLAN2V2</ns1:string>
                <ns1:string>LongestWinStreak_UNRANKED</ns1:string>
                <ns1:string>LongestWinStreak_RANKED1V1</ns1:string>
                <ns1:string>LongestWinStreak_RANKED2V2</ns1:string>
                <ns1:string>LongestWinStreak_CLAN1V1</ns1:string>
                <ns1:string>LongestWinStreak_CLAN2V2</ns1:string>
                <ns1:string>CareerWins_UNRANKED</ns1:string>
                <ns1:string>CareerWins_RANKED1V1</ns1:string>
                <ns1:string>CareerLosses_UNRANKED</ns1:string>
                <ns1:string>CareerLosses_RANKED1V1</ns1:string>
                <ns1:string>TotalMatches_UNRANKED</ns1:string>
            </ns1:fields>
        </ns1:GetMyRecords>
    </SOAP-ENV:Body>
</SOAP-ENV:Envelope>"""

        # Parse the SOAP request like the handler does
        operation = extract_soap_body(request_body)
        table_id = get_element_text(operation, "tableid")
        login_ticket_parsed = get_element_text(operation, "loginTicket")
        requested_fields = get_requested_fields(operation)

        assert table_id == "PlayerStats_v5"
        assert login_ticket_parsed == login_ticket
        assert len(requested_fields) == 20
        assert "CurrentWinStreak_UNRANKED" in requested_fields
        assert "CareerWins_RANKED1V1" in requested_fields
        assert "TotalMatches_UNRANKED" in requested_fields

        # Call the handler with parsed values
        response = handle_get_my_records(login_ticket_parsed, profile_id=67890, requested_fields=requested_fields)
        xml = wrap_soap_envelope(response)

        # Verify response structure
        assert "GetMyRecordsResponse" in xml
        assert "<GetMyRecordsResult>Success</GetMyRecordsResult>" in xml
        assert "soap:Envelope" in xml
        assert "soap:Body" in xml
        # Should have values container with RecordValue elements
        assert "<values>" in xml or "<values/>" in xml
        # Should return one RecordValue per requested field (20 fields = 20 values)
        assert xml.count("<RecordValue>") == 20

    def test_search_for_records_levels_table_with_filter(self):
        """
        Test SearchForRecords for Levels table with Level>0 filter.

        Based on real game request format - returns XP thresholds for 87 ranks.
        """
        # Test login ticket: base64("12345|67890|testtoken")
        login_ticket = base64.b64encode(b"12345|67890|testtoken").decode("utf-8")

        # Real game request format with test data
        # Note: &gt; is XML entity for > character
        request_body = f"""<?xml version="1.0" encoding="UTF-8"?>
<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/"
                   xmlns:SOAP-ENC="http://schemas.xmlsoap.org/soap/encoding/"
                   xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
                   xmlns:xsd="http://www.w3.org/2001/XMLSchema"
                   xmlns:ns1="http://gamespy.net/sake">
    <SOAP-ENV:Body>
        <ns1:SearchForRecords>
            <ns1:gameid>2128</ns1:gameid>
            <ns1:secretKey>testkey</ns1:secretKey>
            <ns1:loginTicket>{login_ticket}</ns1:loginTicket>
            <ns1:tableid>Levels</ns1:tableid>
            <ns1:filter>Level&gt;0</ns1:filter>
            <ns1:sort>Level</ns1:sort>
            <ns1:offset>0</ns1:offset>
            <ns1:max>1000</ns1:max>
            <ns1:surrounding>0</ns1:surrounding>
            <ns1:ownerids></ns1:ownerids>
            <ns1:cacheFlag>1</ns1:cacheFlag>
            <ns1:fields>
                <ns1:string>Score</ns1:string>
            </ns1:fields>
        </ns1:SearchForRecords>
    </SOAP-ENV:Body>
</SOAP-ENV:Envelope>"""

        # Parse the SOAP request like the handler does
        operation = extract_soap_body(request_body)
        table_id = get_element_text(operation, "tableid")
        filter_str = get_element_text(operation, "filter")

        assert table_id == "Levels"
        # XML parser automatically decodes &gt; to >
        assert filter_str == "Level>0"

        # Call the handler with parsed values
        login_ticket = get_element_text(operation, "loginTicket")
        response = handle_search_for_records(table_id, filter_str, login_ticket)
        xml = wrap_soap_envelope(response)

        # Verify response structure
        assert "SearchForRecordsResponse" in xml
        assert "<SearchForRecordsResult>Success</SearchForRecordsResult>" in xml
        assert "soap:Envelope" in xml
        assert "soap:Body" in xml
        # Should have 87 ArrayOfRecordValue elements (one per level)
        assert xml.count("<ArrayOfRecordValue>") == len(LEVEL_THRESHOLDS)
        # Each level contains one RecordValue with XP threshold
        assert xml.count("<RecordValue>") == len(LEVEL_THRESHOLDS)
        # Verify first XP threshold (level 1 = 0 XP)
        assert "<intValue><value>0</value></intValue>" in xml
