"""
FESL Command Handlers - Handles all FESL protocol commands.

This module processes both 'fsys' (system) and 'acct' (account) commands:
- fsys: Hello, MemCheck (connection initialization)
- acct: NuLogin, NuGetPersonas, NuLoginPersona, GameSpyPreAuth (authentication)
"""

import random
import time
from typing import TypeVar

from app.db.crud import (
    create_fesl_session,
    create_persona_for_user,
    create_preauth_ticket,
    get_persona_by_name,
    get_personas_for_user,
    get_user_by_username_and_password,
    get_user_entitlements,
    update_fesl_session_persona,
    update_user_mac_addr,
)
from app.db.database import get_session
from app.models.fesl_types import (
    DomainPartition,
    EntitledGameFeatureWrapper,
    FeslBaseModel,
    FeslHeader,
    GameSpyPreAuthClient,
    GameSpyPreAuthServer,
    HelloClient,
    HelloServer,
    MemcheckServer,
    NuAddPersonaClient,
    NuAddPersonaServer,
    NuGetPersonasClient,
    NuGetPersonasServer,
    NuLoginClient,
    NuLoginPersonaClient,
    NuLoginPersonaServer,
    NuLoginServer,
    client_data_var,
)
from app.util.logging_helper import get_logger

logger = get_logger(__name__)


T = TypeVar("T", bound=FeslBaseModel)


class FeslHandlers:
    """
    Unified FESL command handlers for fsys and acct commands.

    This class replaces FsysFactory and AcctFactory with a single handler
    that routes commands based on the FESL command type and TXN.
    """

    # ==========================================================================
    # fsys handlers
    # ==========================================================================

    @staticmethod
    def handle_hello(model_data: HelloClient) -> list[FeslBaseModel]:
        """
        Handle Hello request - returns both MemCheck and Hello response.
        The game expects both packets together.
        """
        assert isinstance(model_data, HelloClient)

        # MemCheck must be sent with Hello
        memcheck_response = MemcheckServer(txn="MemCheck", type=0, salt=random.getrandbits(32))

        domain_partition = DomainPartition(domain="eagames", subDomain="CNCRA3")
        time_buff = time.strftime('"%b-%d-%Y %H:%M:%S UTC"', time.gmtime())
        hello_response = HelloServer(
            txn="Hello",
            theaterIp="0.0.0.0",
            theaterPort=0,
            messengerIp="0.0.0.0",
            messengerPort=0,
            activityTimeoutSecs=0,
            curTime=time_buff,
            domainPartition=domain_partition,
        )

        # Order matters: Hello first (uses client's packet number), then MemCheck (server-initiated, packet 0)
        return [hello_response, memcheck_response]

    # ==========================================================================
    # acct handlers
    # ==========================================================================

    @staticmethod
    def handle_login(model_data: NuLoginClient) -> NuLoginServer | None:
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
            session=db_session, username=model_data.nuid, password=model_data.password
        )

        if not user:
            logger.debug("Authentication failed for nuid: %s", model_data.nuid)
            return None

        # Update MAC address if provided
        if model_data.macAddr:
            update_user_mac_addr(db_session, user.id, model_data.macAddr)

        # Create FESL session
        fesl_session = create_fesl_session(session=db_session, user_id=user.id, mac_addr=model_data.macAddr)

        # Store in context for subsequent requests in this connection
        client_data = client_data_var.get()
        client_data["user"] = user
        client_data["fesl_session"] = fesl_session
        client_data["lkey"] = fesl_session.lkey

        # Get user entitlements
        entitlements = get_user_entitlements(db_session, user.id)

        # Convert to FESL format
        feature_wrappers = []
        for ent in entitlements:
            feature_wrappers.append(
                EntitledGameFeatureWrapper(
                    gameFeatureId=ent.game_feature_id,
                    entitlementExpirationDays=ent.expiration_days,
                    entitlementExpirationDate=ent.expiration_date or "",
                    message=ent.message or "",
                    status=ent.status,
                )
            )

        # If no entitlements, add default RA3 entitlement
        if not feature_wrappers:
            feature_wrappers.append(
                EntitledGameFeatureWrapper(
                    gameFeatureId=6014, entitlementExpirationDays=-1, entitlementExpirationDate="", message=""
                )
            )

        response = NuLoginServer(
            txn="NuLogin",
            nuid=user.id,
            profileId=user.id,  # Will be updated to persona ID after NuLoginPersona
            userId=user.id,
            displayName=user.username,
            lkey=fesl_session.lkey,
            entitledGameFeatureWrappers=feature_wrappers,
        )

        logger.debug("NuLogin successful for user: %s (id=%s)", user.username, user.id)
        return response

    @staticmethod
    def handle_get_personas(model_data: NuGetPersonasClient) -> NuGetPersonasServer | None:
        """
        Handle NuGetPersonas - Get list of personas for the logged-in user.

        Request fields:
        - namespace: Persona namespace filter (usually empty)

        Response fields:
        - personas: List of persona names
        """
        logger.debug("NuGetPersonas")

        client_data = client_data_var.get()
        user = client_data.get("user")

        if not user:
            logger.debug("NuGetPersonas: No user in context")
            return None

        db_session = next(get_session())
        personas = get_personas_for_user(db_session, user.id)

        persona_names = [p.name for p in personas]

        response = NuGetPersonasServer(txn="NuGetPersonas", personas=persona_names)

        logger.debug("NuGetPersonas returning %d personas", len(persona_names))
        return response

    @staticmethod
    def handle_add_persona(model_data: NuAddPersonaClient) -> NuAddPersonaServer | None:
        """
        Handle NuAddPersona - Add a new persona for the logged-in user.

        Request fields:
        - name: Name of the new persona to create

        Response fields:
        - (just TXN on success)
        """
        logger.debug("NuAddPersona: %s", model_data.name)

        client_data = client_data_var.get()
        user = client_data.get("user")

        if not user:
            logger.debug("NuAddPersona: No user in context")
            return None

        db_session = next(get_session())

        # Check if persona name already exists
        existing_persona = get_persona_by_name(db_session, model_data.name)
        if existing_persona:
            logger.debug("NuAddPersona: Persona name already taken: %s", model_data.name)
            return None

        # Create the new persona
        persona = create_persona_for_user(db_session, user, model_data.name)

        response = NuAddPersonaServer(txn="NuAddPersona")

        logger.debug(
            "NuAddPersona successful: created persona %s (id=%s) for user %s", persona.name, persona.id, user.id
        )
        return response

    @staticmethod
    def handle_login_persona(model_data: NuLoginPersonaClient) -> NuLoginPersonaServer | None:
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
        user = client_data.get("user")
        current_lkey = client_data.get("lkey")

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
        client_data["persona"] = persona
        client_data["lkey"] = fesl_session.lkey
        client_data["fesl_session"] = fesl_session

        response = NuLoginPersonaServer(
            txn="NuLoginPersona", userId=user.id, profileId=persona.id, lkey=fesl_session.lkey
        )

        logger.debug("NuLoginPersona successful: persona=%s (id=%s)", persona.name, persona.id)
        return response

    @staticmethod
    def handle_gamespy_pre_auth(model_data: GameSpyPreAuthClient) -> GameSpyPreAuthServer | None:
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
        user = client_data.get("user")
        persona = client_data.get("persona")

        if not user:
            logger.debug("GameSpyPreAuth: No user in context")
            return None

        if not persona:
            logger.debug("GameSpyPreAuth: No persona in context (must call NuLoginPersona first)")
            return None

        db_session = next(get_session())

        # Create pre-auth ticket with a random secret embedded in the ticket
        preauth = create_preauth_ticket(session=db_session, user_id=user.id, persona_id=persona.id)
        logger.debug("GameSpyPreAuth created ticket with challenge: %s", preauth.challenge)

        # Store in context for reference
        client_data["preauth_ticket"] = preauth

        response = GameSpyPreAuthServer(txn="GameSpyPreAuth", challenge=preauth.challenge, ticket=preauth.ticket)

        logger.debug("GameSpyPreAuth successful: ticket created for user=%s, persona=%s", user.id, persona.id)
        return response

    # ==========================================================================
    # Command routing
    # ==========================================================================

    @staticmethod
    def parse(header: FeslHeader, model_data: FeslBaseModel) -> FeslBaseModel | list[FeslBaseModel] | None:
        """
        Route incoming FESL commands to appropriate handlers.

        Args:
            header: FESL packet header
            model_data: Parsed request model

        Returns:
            Response model, list of response models, or None
        """
        logger.debug("Parsing command=%s, TXN=%s", header.fesl_command, model_data.txn)

        if header.fesl_command == "fsys":
            return FeslHandlers._parse_fsys(header, model_data)
        elif header.fesl_command == "acct":
            return FeslHandlers._parse_acct(header, model_data)

        logger.debug("Unknown command: %s", header.fesl_command)
        return None

    @staticmethod
    def _parse_fsys(header: FeslHeader, model_data: FeslBaseModel) -> FeslBaseModel | list[FeslBaseModel] | None:
        """Route fsys commands."""
        match model_data.txn:
            case "Hello":
                if isinstance(model_data, HelloClient):
                    return FeslHandlers.handle_hello(model_data)
            case "MemCheck":
                # Client MemCheck response - no action needed
                pass

        return None

    @staticmethod
    def _parse_acct(header: FeslHeader, model_data: FeslBaseModel) -> FeslBaseModel | None:
        """Route acct commands."""
        match model_data.txn:
            case "NuLogin":
                return FeslHandlers.handle_login(model_data)
            case "NuGetPersonas":
                return FeslHandlers.handle_get_personas(model_data)
            case "NuAddPersona":
                return FeslHandlers.handle_add_persona(model_data)
            case "NuLoginPersona":
                return FeslHandlers.handle_login_persona(model_data)
            case "GameSpyPreAuth":
                return FeslHandlers.handle_gamespy_pre_auth(model_data)
            case "GetTelemetryToken":
                # No response expected for telemetry
                pass
            case _:
                logger.debug("Unknown TXN: %s", model_data.txn)

        return None
