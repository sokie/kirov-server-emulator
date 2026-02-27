"""
Integration tests for the complete authentication flow between FESL and GPServer.

This tests the cross-service handshake:
1. User registers via REST API
2. User authenticates via FESL (NuLogin)
3. User gets personas (NuGetPersonas)
4. User selects persona (NuLoginPersona)
5. User gets GameSpy pre-auth ticket (GameSpyPreAuth)
6. User authenticates with GPServer using the ticket
"""

import base64

import pytest
from sqlmodel import Session, SQLModel

from app.db.crud import (
    create_fesl_session,
    create_gamespy_session,
    create_new_user,
    create_preauth_ticket,
    get_personas_for_user,
    get_user_by_username_and_password,
    get_user_entitlements,
    parse_ticket,
    update_fesl_session_persona,
    validate_and_consume_preauth_ticket,
)
from app.db.database import engine
from app.models.models import UserCreate


class TestAuthenticationFlow:
    """Integration tests for the complete authentication flow."""

    @pytest.fixture(autouse=True)
    def setup_database(self):
        """Set up a fresh database for each test."""
        # Create tables
        SQLModel.metadata.create_all(engine)
        yield
        # Clean up
        SQLModel.metadata.drop_all(engine)

    def get_session(self):
        """Get a database session."""
        return Session(engine)

    def test_user_registration_creates_persona_and_entitlement(self):
        """Test that user registration creates a default persona and entitlement."""
        with self.get_session() as session:
            user_data = UserCreate(username="testuser", password="testpass123", email="test@example.com")

            user = create_new_user(session, user_data)

            assert user.id is not None
            assert user.username == "testuser"
            assert user.email == "test@example.com"

            # Check persona was created
            personas = get_personas_for_user(session, user.id)
            assert len(personas) == 1
            assert personas[0].name == "testuser"

            # Check entitlements were created (one per supported game)
            entitlements = get_user_entitlements(session, user.id)
            assert len(entitlements) == 2
            feature_ids = {e.game_feature_id for e in entitlements}
            assert 2588 in feature_ids  # CNC3
            assert 6014 in feature_ids  # RA3

    def test_user_authentication(self):
        """Test user authentication by email and password."""
        with self.get_session() as session:
            # Create user
            user_data = UserCreate(username="authtest", password="authpass123", email="auth@example.com")
            create_new_user(session, user_data)

            # Authenticate by username
            user = get_user_by_username_and_password(session, "authtest", "authpass123")
            assert user is not None
            assert user.username == "authtest"

            # Authenticate by email (nuid)
            user = get_user_by_username_and_password(session, "auth@example.com", "authpass123")
            assert user is not None
            assert user.email == "auth@example.com"

            # Wrong password should fail
            user = get_user_by_username_and_password(session, "authtest", "wrongpass")
            assert user is None

    def test_fesl_session_creation(self):
        """Test FESL session creation and lkey generation."""
        with self.get_session() as session:
            # Create user
            user_data = UserCreate(username="sessiontest", password="sessionpass", email="session@example.com")
            user = create_new_user(session, user_data)

            # Create FESL session
            fesl_session = create_fesl_session(
                session=session, user_id=user.id, client_ip="192.168.1.1", mac_addr="$aabbccddeeff"
            )

            assert fesl_session.id is not None
            assert fesl_session.lkey is not None
            assert len(fesl_session.lkey) > 0
            assert fesl_session.user_id == user.id
            assert fesl_session.is_active is True

    def test_fesl_session_persona_update(self):
        """Test updating FESL session with persona selection."""
        with self.get_session() as session:
            # Create user
            user_data = UserCreate(username="personatest", password="personapass", email="persona@example.com")
            user = create_new_user(session, user_data)
            personas = get_personas_for_user(session, user.id)
            persona = personas[0]

            # Create FESL session
            fesl_session = create_fesl_session(session, user.id)
            original_lkey = fesl_session.lkey

            # Update with persona
            updated_session = update_fesl_session_persona(session, original_lkey, persona.id)

            assert updated_session is not None
            assert updated_session.persona_id == persona.id
            # New lkey should be generated
            assert updated_session.lkey != original_lkey

    def test_preauth_ticket_creation(self):
        """Test GameSpy pre-auth ticket creation."""
        with self.get_session() as session:
            # Create user
            user_data = UserCreate(username="tickettest", password="ticketpass", email="ticket@example.com")
            user = create_new_user(session, user_data)
            personas = get_personas_for_user(session, user.id)
            persona = personas[0]

            # Create pre-auth ticket
            ticket = create_preauth_ticket(session, user.id, persona.id)

            assert ticket.id is not None
            assert ticket.ticket is not None
            assert ticket.challenge is not None
            assert len(ticket.challenge) == 8  # 8 character challenge
            assert ticket.is_used is False

            # Verify ticket format (base64 of userId|profileId|token)
            decoded = base64.b64decode(ticket.ticket).decode("utf-8")
            parts = decoded.split("|")
            assert len(parts) == 3
            assert parts[0] == str(user.id)
            assert parts[1] == str(persona.id)

    def test_preauth_ticket_validation(self):
        """Test validating and consuming a pre-auth ticket."""
        with self.get_session() as session:
            # Create user
            user_data = UserCreate(username="validatetest", password="validatepass", email="validate@example.com")
            user = create_new_user(session, user_data)
            personas = get_personas_for_user(session, user.id)
            persona = personas[0]

            # Create pre-auth ticket
            ticket = create_preauth_ticket(session, user.id, persona.id)
            ticket_str = ticket.ticket

            # Validate and consume
            result = validate_and_consume_preauth_ticket(session, ticket_str)

            assert result is not None
            user_id, persona_id, consumed_ticket = result
            assert user_id == user.id
            assert persona_id == persona.id
            assert consumed_ticket.is_used is True

            # Second validation should fail (already used)
            result = validate_and_consume_preauth_ticket(session, ticket_str)
            assert result is None

    def test_gamespy_session_creation(self):
        """Test GameSpy session creation after ticket validation."""
        with self.get_session() as session:
            # Create user
            user_data = UserCreate(username="gptest", password="gppass", email="gp@example.com")
            user = create_new_user(session, user_data)
            personas = get_personas_for_user(session, user.id)
            persona = personas[0]

            # Create and validate pre-auth ticket
            ticket = create_preauth_ticket(session, user.id, persona.id)
            result = validate_and_consume_preauth_ticket(session, ticket.ticket)
            user_id, persona_id, consumed_ticket = result

            # Create GameSpy session
            gp_session = create_gamespy_session(
                session=session,
                user_id=user_id,
                persona_id=persona_id,
                preauth_ticket_id=consumed_ticket.id,
                client_ip="192.168.1.100",
                port=29900,
                product_id=11419,
                gamename="redalert3pc",
            )

            assert gp_session.id is not None
            assert gp_session.sesskey is not None
            assert len(gp_session.sesskey) == 9  # 9 digit sesskey
            assert gp_session.user_id == user.id
            assert gp_session.persona_id == persona.id
            assert gp_session.is_active is True

    def test_complete_auth_flow(self):
        """Test the complete authentication flow from registration to GPServer login."""
        with self.get_session() as session:
            # Step 1: User Registration
            user_data = UserCreate(username="testplayer", password="testpass123", email="testplayer@example.com")
            user = create_new_user(session, user_data)
            assert user.id is not None
            print(f"[1] User created: id={user.id}, username={user.username}")

            # Step 2: FESL NuLogin
            auth_user = get_user_by_username_and_password(session, "testplayer@example.com", "testpass123")
            assert auth_user is not None
            fesl_session = create_fesl_session(session, auth_user.id, mac_addr="$aabbccddeeff")
            print(f"[2] NuLogin successful: userId={auth_user.id}, lkey={fesl_session.lkey}")

            # Step 3: FESL NuGetPersonas
            personas = get_personas_for_user(session, auth_user.id)
            assert len(personas) > 0
            print(f"[3] NuGetPersonas: {[p.name for p in personas]}")

            # Step 4: FESL NuLoginPersona
            selected_persona = personas[0]
            updated_session = update_fesl_session_persona(session, fesl_session.lkey, selected_persona.id)
            assert updated_session is not None
            print(f"[4] NuLoginPersona: profileId={selected_persona.id}, lkey={updated_session.lkey}")

            # Step 5: FESL GameSpyPreAuth
            preauth = create_preauth_ticket(session, auth_user.id, selected_persona.id)
            print(f"[5] GameSpyPreAuth: challenge={preauth.challenge}, ticket={preauth.ticket}")

            # Step 6: GPServer login (validate ticket)
            result = validate_and_consume_preauth_ticket(session, preauth.ticket)
            assert result is not None
            validated_user_id, validated_persona_id, consumed_ticket = result
            print(f"[6] Ticket validated: userId={validated_user_id}, personaId={validated_persona_id}")

            # Step 7: Create GPServer session
            gp_session = create_gamespy_session(
                session=session,
                user_id=validated_user_id,
                persona_id=validated_persona_id,
                preauth_ticket_id=consumed_ticket.id,
                product_id=11419,
                gamename="redalert3pc",
            )
            print(f"[7] GPServer session created: sesskey={gp_session.sesskey}")

            # Verify final state
            assert gp_session.user_id == auth_user.id
            assert gp_session.persona_id == selected_persona.id
            assert gp_session.is_active is True
            print("[SUCCESS] Complete authentication flow verified!")


class TestTicketParsing:
    """Tests for ticket parsing utilities."""

    def test_parse_valid_ticket(self):
        """Test parsing a valid ticket."""
        # Create a ticket with dummy data (base64 encoded: userId|personaId|secretToken)
        ticket_payload = "1000001|2000001|xYz123AbC456DeFgHiJk"
        ticket = base64.b64encode(ticket_payload.encode()).decode()

        result = parse_ticket(ticket)

        assert result is not None
        user_id, persona_id, secret_token = result
        assert user_id == 1000001
        assert persona_id == 2000001
        assert secret_token == "xYz123AbC456DeFgHiJk"

    def test_parse_base64_ticket(self):
        """Test parsing a base64-encoded ticket."""
        # Pre-encoded ticket: base64("1000001|2000001|xYz123AbC456DeFgHiJk")
        ticket = "MTAwMDAwMXwyMDAwMDAxfHhZejEyM0FiQzQ1NkRlRmdIaUpr"

        result = parse_ticket(ticket)

        assert result is not None
        user_id, persona_id, secret_token = result
        assert user_id == 1000001
        assert persona_id == 2000001

    def test_parse_invalid_ticket(self):
        """Test parsing an invalid ticket."""
        # Invalid base64
        result = parse_ticket("not-valid-base64!!!")
        assert result is None

        # Valid base64 but wrong format
        invalid_ticket = base64.b64encode(b"invalid|format").decode()
        result = parse_ticket(invalid_ticket)
        assert result is None

        # Valid format but non-numeric IDs
        invalid_ids = base64.b64encode(b"abc|def|token").decode()
        result = parse_ticket(invalid_ids)
        assert result is None


class TestFeslHandlersIntegration:
    """Integration tests for FESL FeslHandlers handlers with real database operations."""

    @pytest.fixture(autouse=True)
    def setup_database(self):
        """Set up a fresh database for each test."""
        SQLModel.metadata.create_all(engine)
        yield
        SQLModel.metadata.drop_all(engine)

    def get_session(self):
        """Get a database session."""
        return Session(engine)

    def test_nulogin_handler_flow(self):
        """Test that NuLogin handler authenticates and creates session correctly."""
        from app.models.fesl_types import NuLoginClient, client_data_var
        from app.servers.fesl_handlers import FeslHandlers

        with self.get_session() as session:
            # Create user first
            user_data = UserCreate(username="handlertest", password="handlerpass", email="handler@example.com")
            user = create_new_user(session, user_data)

        # Reset context
        client_data_var.set({})

        # Create login request
        login_request = NuLoginClient(
            txn="NuLogin", nuid="handler@example.com", password="handlerpass", macAddr="$aabbccddeeff"
        )

        # Call handler
        response = FeslHandlers.handle_login(login_request)

        assert response is not None
        assert response.txn == "NuLogin"
        assert response.displayName == "handlertest"
        assert response.lkey is not None
        assert len(response.lkey) > 0
        assert len(response.entitledGameFeatureWrappers) >= 1
        feature_ids = {w.gameFeatureId for w in response.entitledGameFeatureWrappers}
        assert 6014 in feature_ids  # RA3 entitlement present

    def test_nulogin_wrong_password(self):
        """Test that NuLogin handler rejects wrong password with AUTH_FAILURE error."""
        from app.models.fesl_types import FeslError, FeslErrorResponse, NuLoginClient, client_data_var
        from app.servers.fesl_handlers import FeslHandlers

        with self.get_session() as session:
            user_data = UserCreate(username="wrongpass", password="correctpass", email="wrongpass@example.com")
            create_new_user(session, user_data)

        client_data_var.set({})

        login_request = NuLoginClient(
            txn="NuLogin", nuid="wrongpass@example.com", password="incorrectpass", macAddr="$aabbccddeeff"
        )

        response = FeslHandlers.handle_login(login_request)

        assert isinstance(response, FeslErrorResponse)
        assert response.txn == "NuLogin"
        assert response.errorCode == FeslError.AUTH_FAILURE

    def test_nugetpersonas_handler_flow(self):
        """Test NuGetPersonas handler returns correct personas."""
        from app.models.fesl_types import NuGetPersonasClient, NuLoginClient, client_data_var
        from app.servers.fesl_handlers import FeslHandlers

        with self.get_session() as session:
            user_data = UserCreate(
                username="personahandler", password="personapass", email="personahandler@example.com"
            )
            create_new_user(session, user_data)

        client_data_var.set({})

        # First login
        login_request = NuLoginClient(
            txn="NuLogin", nuid="personahandler@example.com", password="personapass", macAddr="$aabbccddeeff"
        )
        FeslHandlers.handle_login(login_request)

        # Then get personas
        personas_request = NuGetPersonasClient(txn="NuGetPersonas", namespace="")
        response = FeslHandlers.handle_get_personas(personas_request)

        assert response is not None
        assert response.txn == "NuGetPersonas"
        assert len(response.personas) == 1
        assert response.personas[0] == "personahandler"

    def test_nuloginpersona_handler_flow(self):
        """Test NuLoginPersona handler selects persona correctly."""
        from app.models.fesl_types import NuLoginClient, NuLoginPersonaClient, client_data_var
        from app.servers.fesl_handlers import FeslHandlers

        with self.get_session() as session:
            user_data = UserCreate(username="selectpersona", password="selectpass", email="selectpersona@example.com")
            user = create_new_user(session, user_data)
            personas = get_personas_for_user(session, user.id)
            persona_id = personas[0].id

        client_data_var.set({})

        # Login first
        login_request = NuLoginClient(
            txn="NuLogin", nuid="selectpersona@example.com", password="selectpass", macAddr="$aabbccddeeff"
        )
        login_response = FeslHandlers.handle_login(login_request)
        original_lkey = login_response.lkey

        # Select persona
        persona_request = NuLoginPersonaClient(txn="NuLoginPersona", name="selectpersona")
        response = FeslHandlers.handle_login_persona(persona_request)

        assert response is not None
        assert response.txn == "NuLoginPersona"
        assert response.profileId == persona_id
        # New lkey should be generated
        assert response.lkey != original_lkey

    def test_gamespypreauth_handler_flow(self):
        """Test GameSpyPreAuth handler generates valid ticket."""
        from app.models.fesl_types import GameSpyPreAuthClient, NuLoginClient, NuLoginPersonaClient, client_data_var
        from app.servers.fesl_handlers import FeslHandlers

        with self.get_session() as session:
            user_data = UserCreate(username="preauthtest", password="preauthpass", email="preauthtest@example.com")
            user = create_new_user(session, user_data)
            personas = get_personas_for_user(session, user.id)
            persona = personas[0]

        client_data_var.set({})

        # Login
        login_request = NuLoginClient(
            txn="NuLogin", nuid="preauthtest@example.com", password="preauthpass", macAddr="$aabbccddeeff"
        )
        FeslHandlers.handle_login(login_request)

        # Select persona
        persona_request = NuLoginPersonaClient(txn="NuLoginPersona", name="preauthtest")
        FeslHandlers.handle_login_persona(persona_request)

        # Get pre-auth ticket
        preauth_request = GameSpyPreAuthClient(txn="GameSpyPreAuth")
        response = FeslHandlers.handle_gamespy_pre_auth(preauth_request)

        assert response is not None
        assert response.txn == "GameSpyPreAuth"
        assert response.challenge is not None
        assert len(response.challenge) == 8
        assert response.ticket is not None

        # Verify ticket format
        decoded = base64.b64decode(response.ticket).decode("utf-8")
        parts = decoded.split("|")
        assert len(parts) == 3
        assert int(parts[0]) == user.id
        assert int(parts[1]) == persona.id

    def test_userid_profileid_differ_after_persona_selection(self):
        """
        Test that userId and profileId are correctly differentiated.

        Protocol behavior:
        - After NuLogin: userId == profileId (both are user.id)
        - After NuLoginPersona: userId == user.id, profileId == persona.id (different!)

        """
        from app.models.fesl_types import NuLoginClient, NuLoginPersonaClient, client_data_var
        from app.servers.fesl_handlers import FeslHandlers

        with self.get_session() as session:
            user_data = UserCreate(username="idtest", password="idtestpass", email="idtest@example.com")
            user = create_new_user(session, user_data)
            personas = get_personas_for_user(session, user.id)
            persona = personas[0]

            # Verify user and persona have different IDs (they should in real scenarios)
            # Note: In test DB they might be sequential (1, 2) but still different
            user_id = user.id
            persona_id = persona.id

        client_data_var.set({})

        # Step 1: NuLogin - userId and profileId should BOTH be user.id
        login_request = NuLoginClient(
            txn="NuLogin", nuid="idtest@example.com", password="idtestpass", macAddr="$aabbccddeeff"
        )
        login_response = FeslHandlers.handle_login(login_request)

        assert login_response is not None
        assert login_response.userId == user_id
        assert login_response.profileId == user_id  # Before persona selection, profileId == userId
        assert login_response.userId == login_response.profileId

        # Step 2: NuLoginPersona - userId stays same, profileId becomes persona.id
        persona_request = NuLoginPersonaClient(txn="NuLoginPersona", name="idtest")
        persona_response = FeslHandlers.handle_login_persona(persona_request)

        assert persona_response is not None
        assert persona_response.userId == user_id  # userId stays as user.id
        assert persona_response.profileId == persona_id  # profileId is now persona.id
        # In most cases these will be different (unless user.id happens to equal persona.id)
        # The key point is that profileId changed to persona.id after selection

    def test_complete_fesl_to_gpserver_handoff(self):
        """Test complete FESL authentication followed by GPServer ticket validation."""
        from app.models.fesl_types import GameSpyPreAuthClient, NuLoginClient, NuLoginPersonaClient, client_data_var
        from app.servers.fesl_handlers import FeslHandlers

        with self.get_session() as session:
            user_data = UserCreate(username="fullflow", password="fullflowpass", email="fullflow@example.com")
            user = create_new_user(session, user_data)
            personas = get_personas_for_user(session, user.id)
            persona = personas[0]

        client_data_var.set({})

        # Step 1: NuLogin
        login_request = NuLoginClient(
            txn="NuLogin", nuid="fullflow@example.com", password="fullflowpass", macAddr="$aabbccddeeff"
        )
        login_response = FeslHandlers.handle_login(login_request)
        assert login_response is not None
        assert login_response.userId == user.id
        # After NuLogin, profileId == userId
        assert login_response.profileId == user.id

        # Step 2: NuLoginPersona
        persona_request = NuLoginPersonaClient(txn="NuLoginPersona", name="fullflow")
        persona_response = FeslHandlers.handle_login_persona(persona_request)
        assert persona_response is not None
        # After NuLoginPersona: userId stays same, profileId becomes persona.id
        assert persona_response.userId == user.id
        assert persona_response.profileId == persona.id

        # Step 3: GameSpyPreAuth
        preauth_request = GameSpyPreAuthClient(txn="GameSpyPreAuth")
        preauth_response = FeslHandlers.handle_gamespy_pre_auth(preauth_request)
        assert preauth_response is not None

        # Step 4: GPServer validates ticket (simulating GPServer login handler)
        with self.get_session() as session:
            result = validate_and_consume_preauth_ticket(session, preauth_response.ticket)
            assert result is not None

            validated_user_id, validated_persona_id, consumed_ticket = result
            assert validated_user_id == user.id
            assert validated_persona_id == persona.id
            assert consumed_ticket.is_used is True

            # Step 5: Create GPServer session
            gp_session = create_gamespy_session(
                session=session,
                user_id=validated_user_id,
                persona_id=validated_persona_id,
                preauth_ticket_id=consumed_ticket.id,
                product_id=11419,
                gamename="redalert3pc",
            )
            assert gp_session is not None
            assert gp_session.is_active is True


class TestEdgeCases:
    """Edge case tests for authentication flow."""

    @pytest.fixture(autouse=True)
    def setup_database(self):
        """Set up a fresh database for each test."""
        SQLModel.metadata.create_all(engine)
        yield
        SQLModel.metadata.drop_all(engine)

    def get_session(self):
        """Get a database session."""
        return Session(engine)

    def test_expired_ticket_rejected(self):
        """Test that expired pre-auth tickets are rejected."""
        from datetime import datetime, timedelta

        with self.get_session() as session:
            user_data = UserCreate(username="expiredticket", password="expiredpass", email="expired@example.com")
            user = create_new_user(session, user_data)
            personas = get_personas_for_user(session, user.id)
            persona = personas[0]

            # Create ticket and manually expire it
            ticket = create_preauth_ticket(session, user.id, persona.id)
            ticket.expires_at = datetime.utcnow() - timedelta(minutes=10)
            session.commit()

            # Try to validate expired ticket
            result = validate_and_consume_preauth_ticket(session, ticket.ticket)
            assert result is None

    def test_already_used_ticket_rejected(self):
        """Test that already-used pre-auth tickets are rejected."""
        with self.get_session() as session:
            user_data = UserCreate(username="usedticket", password="usedpass", email="used@example.com")
            user = create_new_user(session, user_data)
            personas = get_personas_for_user(session, user.id)
            persona = personas[0]

            # Create and use ticket
            ticket = create_preauth_ticket(session, user.id, persona.id)
            ticket_str = ticket.ticket

            # First validation should succeed
            result1 = validate_and_consume_preauth_ticket(session, ticket_str)
            assert result1 is not None

            # Second validation should fail
            result2 = validate_and_consume_preauth_ticket(session, ticket_str)
            assert result2 is None

    def test_multiple_personas_selection(self):
        """Test selecting different personas in sequence."""
        from app.db.crud import create_persona_for_user

        with self.get_session() as session:
            user_data = UserCreate(username="multipersona", password="multipass", email="multi@example.com")
            user = create_new_user(session, user_data)

            # Create additional persona
            create_persona_for_user(session, user, "altcharacter")

            personas = get_personas_for_user(session, user.id)
            assert len(personas) == 2

            # Create session and select first persona
            fesl_session = create_fesl_session(session, user.id)
            updated = update_fesl_session_persona(session, fesl_session.lkey, personas[0].id)
            assert updated.persona_id == personas[0].id

    def test_session_isolation(self):
        """Test that different users have isolated sessions."""
        with self.get_session() as session:
            # Create two users
            user1_data = UserCreate(username="user1", password="password1", email="user1@example.com")
            user2_data = UserCreate(username="user2", password="password2", email="user2@example.com")
            user1 = create_new_user(session, user1_data)
            user2 = create_new_user(session, user2_data)

            # Create sessions for both
            session1 = create_fesl_session(session, user1.id)
            session2 = create_fesl_session(session, user2.id)

            # Verify sessions are different
            assert session1.lkey != session2.lkey
            assert session1.user_id != session2.user_id
