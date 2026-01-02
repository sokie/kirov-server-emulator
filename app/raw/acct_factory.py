"""
FESL Account Factory - Handles all 'acct' (account) protocol commands.

This module processes authentication-related FESL commands:
- NuLogin: Initial user authentication
- NuGetPersonas: Get list of personas for a user
- NuLoginPersona: Select a persona to play as
- GameSpyPreAuth: Generate ticket for GPServer handshake
"""

from typing import TypeVar, Optional

from app.db.crud import (
    get_user_by_username_and_password,
    get_persona_by_name,
    get_personas_for_user,
    get_user_entitlements,
    create_fesl_session,
    update_fesl_session_persona,
    create_preauth_ticket,
    update_user_mac_addr,
    create_persona_for_user,
)
from app.db.database import get_session
from app.models.fesl_types import (
    FeslBaseModel,
    NuLoginClient,
    NuLoginServer,
    EntitledGameFeatureWrapper,
    NuGetPersonasClient,
    NuLoginPersonaClient,
    GameSpyPreAuthClient,
    NuGetPersonasServer,
    NuLoginPersonaServer,
    GameSpyPreAuthServer,
    NuAddPersonaClient,
    NuAddPersonaServer,
    FeslHeader,
    client_data_var,
)
from app.util.logging_helper import get_logger

logger = get_logger(__name__)


class AcctFactory:
    """
    Factory class for handling FESL account commands.

    Each handler method processes a specific TXN (transaction) type
    and returns the appropriate response model.
    """

    @staticmethod
    def handle_login(model_data: NuLoginClient) -> Optional[NuLoginServer]:
        """
        Handle NuLogin - Initial user authentication.

        Flow:
        1. Validate credentials (nuid = email, password)
        2. Create FESL session with lkey
        3. Store user in context for subsequent requests
        4. Return user info with entitlements

        Request fields:
        - nuid: User's email address
        - password: User's password
        - macAddr: Client's MAC address
        - returnEncryptedInfo: Whether to return encrypted info

        Response fields:
        - userId: User's database ID
        - profileId: Same as userId (persona ID set later)
        - displayName: User's display name
        - lkey: Login key token for session
        - entitledGameFeatureWrappers: List of game entitlements
        """
        logger.debug("NuLogin for nuid: %s", model_data.nuid)

        db_session = next(get_session())

        # Authenticate user by email (nuid) and password
        user = get_user_by_username_and_password(
            session=db_session,
            username=model_data.nuid,
            password=model_data.password
        )

        if not user:
            logger.debug("Authentication failed for nuid: %s", model_data.nuid)
            # TODO: Return proper error response
            return None

        # Update MAC address if provided
        if model_data.macAddr:
            update_user_mac_addr(db_session, user.id, model_data.macAddr)

        # Create FESL session
        fesl_session = create_fesl_session(
            session=db_session,
            user_id=user.id,
            mac_addr=model_data.macAddr
        )

        # Store in context for subsequent requests in this connection
        client_data = client_data_var.get()
        client_data['user'] = user
        client_data['fesl_session'] = fesl_session
        client_data['lkey'] = fesl_session.lkey

        # Get user entitlements
        entitlements = get_user_entitlements(db_session, user.id)

        # Convert to FESL format
        feature_wrappers = []
        for ent in entitlements:
            feature_wrappers.append(EntitledGameFeatureWrapper(
                gameFeatureId=ent.game_feature_id,
                entitlementExpirationDays=ent.expiration_days,
                entitlementExpirationDate=ent.expiration_date or "",
                message=ent.message or "",
                status=ent.status
            ))

        # If no entitlements, add default RA3 entitlement
        if not feature_wrappers:
            feature_wrappers.append(EntitledGameFeatureWrapper(
                gameFeatureId=6014,
                entitlementExpirationDays=-1,
                entitlementExpirationDate="",
                message=""
            ))

        response = NuLoginServer(
            txn='NuLogin',
            nuid=user.id,
            profileId=user.id,  # Will be updated to persona ID after NuLoginPersona
            userId=user.id,
            displayName=user.username,
            lkey=fesl_session.lkey,
            entitledGameFeatureWrappers=feature_wrappers
        )

        logger.debug("NuLogin successful for user: %s (id=%s)", user.username, user.id)
        return response

    @staticmethod
    def handle_get_personas(model_data: NuGetPersonasClient) -> Optional[NuGetPersonasServer]:
        """
        Handle NuGetPersonas - Get list of personas for the logged-in user.

        Request fields:
        - namespace: Persona namespace filter (usually empty)

        Response fields:
        - personas: List of persona names
        """
        logger.debug("NuGetPersonas")

        client_data = client_data_var.get()
        user = client_data.get('user')

        if not user:
            logger.debug("NuGetPersonas: No user in context")
            return None

        db_session = next(get_session())
        personas = get_personas_for_user(db_session, user.id)

        persona_names = [p.name for p in personas]

        response = NuGetPersonasServer(
            txn='NuGetPersonas',
            personas=persona_names
        )

        logger.debug("NuGetPersonas returning %d personas", len(persona_names))
        return response

    @staticmethod
    def handle_add_persona(model_data: NuAddPersonaClient) -> Optional[NuAddPersonaServer]:
        """
        Handle NuAddPersona - Add a new persona for the logged-in user.

        Request fields:
        - name: Name of the new persona to create

        Response fields:
        - (just TXN on success)
        """
        logger.debug("NuAddPersona: %s", model_data.name)

        client_data = client_data_var.get()
        user = client_data.get('user')

        if not user:
            logger.debug("NuAddPersona: No user in context")
            return None

        db_session = next(get_session())

        # Check if persona name already exists
        existing_persona = get_persona_by_name(db_session, model_data.name)
        if existing_persona:
            logger.debug("NuAddPersona: Persona name already taken: %s", model_data.name)
            # TODO: Return proper error response for duplicate name
            return None

        # Create the new persona
        persona = create_persona_for_user(db_session, user, model_data.name)

        response = NuAddPersonaServer(
            txn='NuAddPersona'
        )

        logger.debug("NuAddPersona successful: created persona %s (id=%s) for user %s",
                    persona.name, persona.id, user.id)
        return response

    @staticmethod
    def handle_login_persona(model_data: NuLoginPersonaClient) -> Optional[NuLoginPersonaServer]:
        """
        Handle NuLoginPersona - Select a persona to play as.

        This updates the session with the selected persona and generates
        a new lkey that will be used for subsequent requests.

        Request fields:
        - name: Persona name to login as

        Response fields:
        - userId: User's database ID
        - profileId: Selected persona's database ID
        - lkey: New login key for this persona session
        """
        logger.debug("NuLoginPersona for: %s", model_data.name)

        client_data = client_data_var.get()
        user = client_data.get('user')
        current_lkey = client_data.get('lkey')

        if not user:
            logger.debug("NuLoginPersona: No user in context")
            return None

        db_session = next(get_session())

        # Get the persona by name
        persona = get_persona_by_name(db_session, model_data.name)

        if not persona:
            logger.debug("Persona not found: %s", model_data.name)
            return None

        # Verify persona belongs to this user
        if persona.user_id != user.id:
            logger.debug("Persona %s does not belong to user %s", model_data.name, user.id)
            return None

        # Update FESL session with persona (generates new lkey)
        fesl_session = update_fesl_session_persona(db_session, current_lkey, persona.id)

        if not fesl_session:
            logger.debug("Failed to update FESL session")
            return None

        # Update context
        client_data['persona'] = persona
        client_data['lkey'] = fesl_session.lkey
        client_data['fesl_session'] = fesl_session

        response = NuLoginPersonaServer(
            txn='NuLoginPersona',
            userId=user.id,
            profileId=persona.id,
            lkey=fesl_session.lkey
        )

        logger.debug("NuLoginPersona successful: persona=%s (id=%s)", persona.name, persona.id)
        return response

    @staticmethod
    def handle_gamespy_pre_auth(model_data: GameSpyPreAuthClient) -> Optional[GameSpyPreAuthServer]:
        """
        Handle GameSpyPreAuth - Generate ticket for GPServer handshake.

        This is the bridge between FESL and GPServer authentication.
        FESL generates a ticket containing:
        - challenge: Random string for handshake
        - ticket: base64(userId|profileId|secretToken)

        The client then sends this ticket to GPServer's \\login\\ command,
        and GPServer validates it against our database.

        Response fields:
        - challenge: Random challenge string
        - ticket: Base64-encoded authentication ticket
        """
        logger.debug("GameSpyPreAuth")

        client_data = client_data_var.get()
        user = client_data.get('user')
        persona = client_data.get('persona')

        if not user:
            logger.debug("GameSpyPreAuth: No user in context")
            return None

        if not persona:
            logger.debug("GameSpyPreAuth: No persona in context (must call NuLoginPersona first)")
            return None

        db_session = next(get_session())

        # Create pre-auth ticket with a random secret embedded in the ticket
        # The client extracts this secret from the ticket for proof calculation
        preauth = create_preauth_ticket(
            session=db_session,
            user_id=user.id,
            persona_id=persona.id
        )
        logger.debug("GameSpyPreAuth created ticket with challenge: %s", preauth.challenge)

        # Store in context for reference
        client_data['preauth_ticket'] = preauth

        response = GameSpyPreAuthServer(
            txn='GameSpyPreAuth',
            challenge=preauth.challenge,
            ticket=preauth.ticket
        )

        logger.debug("GameSpyPreAuth successful: ticket created for user=%s, persona=%s", user.id, persona.id)
        return response

    T = TypeVar('T', bound=FeslBaseModel)

    @staticmethod
    def parse(header: FeslHeader, model_data: T) -> T | None:
        """
        Route incoming FESL account commands to appropriate handlers.

        Args:
            header: FESL packet header
            model_data: Parsed request model

        Returns:
            Response model or None
        """
        logger.debug("Parsing TXN: %s", model_data.txn)

        match model_data.txn:
            case 'NuLogin':
                return AcctFactory.handle_login(model_data)
            case 'NuGetPersonas':
                return AcctFactory.handle_get_personas(model_data)
            case 'NuAddPersona':
                return AcctFactory.handle_add_persona(model_data)
            case 'NuLoginPersona':
                return AcctFactory.handle_login_persona(model_data)
            case 'GameSpyPreAuth':
                return AcctFactory.handle_gamespy_pre_auth(model_data)
            case 'GetTelemetryToken':
                # No response expected for telemetry
                pass
            case _:
                logger.debug("Unknown TXN: %s", model_data.txn)

        return None
