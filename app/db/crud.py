import base64
import random
import secrets
import string
from datetime import datetime, timedelta
from typing import Optional, List, Tuple

from sqlmodel import Session, select
from app.models.models import (
    User, UserCreate, Persona, Friend,
    FeslSession, GameSpyPreAuthTicket, GameSpySession, GameEntitlement,
    BuddyRequest, GameInvite
)
from app.security import hash_password, verify_password


# =============================================================================
# User CRUD Operations
# =============================================================================

def create_new_user(session: Session, user_create: UserCreate) -> User:
    """
    Create a new user in the database with a default persona and entitlement.
    """
    hashed_pass = hash_password(user_create.password)
    user_db = User(
        username=user_create.username,
        hashed_password=hashed_pass,
        email=user_create.email
    )

    session.add(user_db)
    session.commit()
    session.refresh(user_db)

    # Create default persona with the same name as username
    persona = Persona(name=user_create.username, user=user_db)
    session.add(persona)
    session.commit()
    session.refresh(persona)

    # Create default game entitlement for RA3
    entitlement = GameEntitlement(
        user_id=user_db.id,
        game_feature_id=6014,  # RA3 game feature ID
        expiration_days=-1,    # Never expires
        status=0
    )
    session.add(entitlement)
    session.commit()

    return user_db


def get_user_by_id(session: Session, user_id: int) -> Optional[User]:
    """Retrieves a user by their ID."""
    return session.get(User, user_id)


def get_user_by_username(session: Session, username: str) -> Optional[User]:
    """Retrieves a user by their username."""
    statement = select(User).where(User.username == username)
    user = session.exec(statement).first()
    return user


def get_user_by_email(session: Session, email: str) -> Optional[User]:
    """Retrieves a user by their email (nuid)."""
    statement = select(User).where(User.email == email)
    user = session.exec(statement).first()
    return user


def get_user_by_username_and_password(session: Session, username: str, password: str) -> Optional[User]:
    """
    Retrieves a user by username/email and verifies their password.
    Supports login by either username or email (nuid).
    """
    # Try by username first
    user = get_user_by_username(session, username)
    if not user:
        # Try by email (nuid)
        user = get_user_by_email(session, username)
    if not user:
        return None
    if not verify_password(password, user.hashed_password):
        return None
    return user


def update_user_mac_addr(session: Session, user_id: int, mac_addr: str) -> Optional[User]:
    """Updates the user's MAC address."""
    user = session.get(User, user_id)
    if user:
        user.mac_addr = mac_addr
        user.updated_at = datetime.utcnow()
        session.add(user)
        session.commit()
        session.refresh(user)
    return user


# =============================================================================
# Persona CRUD Operations
# =============================================================================

def create_persona_for_user(session: Session, user: User, persona_name: str, namespace: str = "") -> Persona:
    """Creates a persona and associates it with a user."""
    user_in_session = session.get(User, user.id)
    if not user_in_session:
        raise ValueError(f"User with id {user.id} not found in this session")

    persona = Persona(name=persona_name, namespace=namespace, user=user_in_session)
    session.add(persona)
    session.commit()
    session.refresh(persona)
    print(f"Created Persona: {persona.name} for User: {user_in_session.username}")
    return persona


def get_persona_by_id(session: Session, persona_id: int) -> Optional[Persona]:
    """Retrieves a persona by ID."""
    return session.get(Persona, persona_id)


def get_persona_by_name(session: Session, name: str) -> Optional[Persona]:
    """Retrieves a persona by their name."""
    statement = select(Persona).where(Persona.name == name)
    persona = session.exec(statement).first()
    return persona


def get_personas_for_user(session: Session, user_id: int) -> List[Persona]:
    """Retrieves all personas for a user."""
    statement = select(Persona).where(Persona.user_id == user_id)
    personas = session.exec(statement).all()
    return list(personas)


def get_user_from_persona(session: Session, persona_id: int) -> Optional[User]:
    """Gets the user associated with a persona."""
    stmt = select(Persona).where(Persona.id == persona_id)
    persona = session.exec(stmt).first()
    return persona.user if persona else None


# =============================================================================
# Friend Operations
# =============================================================================

def add_friend(session: Session, persona1: Persona, persona2: Persona):
    """Makes two personas friends with each other."""
    p1 = session.get(Persona, persona1.id)
    p2 = session.get(Persona, persona2.id)

    if not p1 or not p2:
        raise ValueError("One or both personas not found in this session.")

    p1.friends.append(p2)
    session.add(p1)
    session.commit()
    print(f"Made {p1.name} and {p2.name} friends.")


def get_persona_friends(session: Session, persona_id: int) -> List[Persona]:
    """Gets all friends for a persona."""
    stmt = select(Persona).where(Persona.id == persona_id)
    persona = session.exec(stmt).first()
    return persona.friends if persona else []


# =============================================================================
# FESL Session Operations
# =============================================================================

def generate_lkey() -> str:
    """Generates a new lkey token."""
    # Generate a random token and base64 encode it
    token = secrets.token_bytes(20)
    lkey = base64.b64encode(token).decode('utf-8')
    # Format similar to real FESL lkeys (e.g., T4QdgDQCFm83wYUMCn4qpAAAKDw.)
    return lkey.rstrip('=') + '.'


def create_fesl_session(
    session: Session,
    user_id: int,
    client_ip: Optional[str] = None,
    mac_addr: Optional[str] = None
) -> FeslSession:
    """Creates a new FESL session for a user after NuLogin."""
    lkey = generate_lkey()

    fesl_session = FeslSession(
        lkey=lkey,
        user_id=user_id,
        client_ip=client_ip,
        mac_addr=mac_addr,
        is_active=True
    )

    session.add(fesl_session)
    session.commit()
    session.refresh(fesl_session)
    return fesl_session


def update_fesl_session_persona(
    session: Session,
    lkey: str,
    persona_id: int
) -> Optional[FeslSession]:
    """Updates a FESL session with the selected persona after NuLoginPersona."""
    stmt = select(FeslSession).where(FeslSession.lkey == lkey, FeslSession.is_active == True)
    fesl_session = session.exec(stmt).first()

    if fesl_session:
        # Generate new lkey for persona login
        fesl_session.lkey = generate_lkey()
        fesl_session.persona_id = persona_id
        session.add(fesl_session)
        session.commit()
        session.refresh(fesl_session)

    return fesl_session


def get_fesl_session_by_lkey(session: Session, lkey: str) -> Optional[FeslSession]:
    """Retrieves an active FESL session by lkey."""
    stmt = select(FeslSession).where(
        FeslSession.lkey == lkey,
        FeslSession.is_active == True,
        FeslSession.expires_at > datetime.utcnow()
    )
    return session.exec(stmt).first()


def invalidate_fesl_session(session: Session, lkey: str) -> bool:
    """Invalidates a FESL session."""
    fesl_session = get_fesl_session_by_lkey(session, lkey)
    if fesl_session:
        fesl_session.is_active = False
        session.add(fesl_session)
        session.commit()
        return True
    return False


# =============================================================================
# GameSpy Pre-Auth Ticket Operations
# =============================================================================

def generate_challenge() -> str:
    """Generates a random challenge string."""
    return ''.join(random.choice(string.ascii_lowercase) for _ in range(8))


def generate_secret_token() -> str:
    """Generates a random secret token for the ticket."""
    return secrets.token_urlsafe(16)


def create_preauth_ticket(
    session: Session,
    user_id: int,
    persona_id: int
) -> GameSpyPreAuthTicket:
    """
    Creates a GameSpy pre-auth ticket for cross-service handshake.

    The ticket format is: base64(userId|profileId|secretToken)
    """
    challenge = generate_challenge()
    secret_token = generate_secret_token()

    # Create ticket payload: userId|profileId|secretToken
    ticket_payload = f"{user_id}|{persona_id}|{secret_token}"
    ticket = base64.b64encode(ticket_payload.encode('utf-8')).decode('utf-8')

    preauth = GameSpyPreAuthTicket(
        ticket=ticket,
        challenge=challenge,
        secret_token=secret_token,
        user_id=user_id,
        persona_id=persona_id,
        is_used=False
    )

    session.add(preauth)
    session.commit()
    session.refresh(preauth)
    return preauth


def validate_and_consume_preauth_ticket(
    session: Session,
    ticket: str
) -> Optional[Tuple[int, int, GameSpyPreAuthTicket]]:
    """
    Validates a pre-auth ticket and marks it as used.

    Returns (user_id, persona_id, ticket) if valid, None otherwise.
    """
    stmt = select(GameSpyPreAuthTicket).where(
        GameSpyPreAuthTicket.ticket == ticket,
        GameSpyPreAuthTicket.is_used == False,
        GameSpyPreAuthTicket.expires_at > datetime.utcnow()
    )
    preauth = session.exec(stmt).first()

    if not preauth:
        return None

    # Mark as used
    preauth.is_used = True
    preauth.used_at = datetime.utcnow()
    session.add(preauth)
    session.commit()
    session.refresh(preauth)

    return preauth.user_id, preauth.persona_id, preauth


def parse_ticket(ticket: str) -> Optional[Tuple[int, int, str]]:
    """
    Parses a ticket to extract user_id, persona_id, and secret_token.

    Returns (user_id, persona_id, secret_token) or None if invalid.
    """
    try:
        decoded = base64.b64decode(ticket).decode('utf-8')
        parts = decoded.split('|')
        if len(parts) != 3:
            return None
        user_id = int(parts[0])
        persona_id = int(parts[1])
        secret_token = parts[2]
        return user_id, persona_id, secret_token
    except Exception:
        return None


# =============================================================================
# GameSpy Session Operations
# =============================================================================

def generate_sesskey() -> str:
    """Generates a random session key for GameSpy."""
    return str(random.randint(100000000, 999999999))


def create_gamespy_session(
    session: Session,
    user_id: int,
    persona_id: int,
    preauth_ticket_id: Optional[int] = None,
    client_ip: Optional[str] = None,
    port: Optional[int] = None,
    product_id: Optional[int] = None,
    gamename: Optional[str] = None
) -> GameSpySession:
    """Creates a new GameSpy session after successful login."""
    sesskey = generate_sesskey()

    gp_session = GameSpySession(
        sesskey=sesskey,
        user_id=user_id,
        persona_id=persona_id,
        preauth_ticket_id=preauth_ticket_id,
        client_ip=client_ip,
        port=port,
        product_id=product_id,
        gamename=gamename,
        is_active=True
    )

    session.add(gp_session)
    session.commit()
    session.refresh(gp_session)
    return gp_session


def get_gamespy_session_by_sesskey(session: Session, sesskey: str) -> Optional[GameSpySession]:
    """Retrieves an active GameSpy session by sesskey."""
    stmt = select(GameSpySession).where(
        GameSpySession.sesskey == sesskey,
        GameSpySession.is_active == True,
        GameSpySession.expires_at > datetime.utcnow()
    )
    return session.exec(stmt).first()


def update_gamespy_session_status(
    session: Session,
    sesskey: str,
    status: str,
    stat_string: str = "",
    loc_string: str = ""
) -> Optional[GameSpySession]:
    """Updates the status of a GameSpy session."""
    gp_session = get_gamespy_session_by_sesskey(session, sesskey)
    if gp_session:
        gp_session.status = status
        gp_session.stat_string = stat_string or status
        gp_session.loc_string = loc_string
        session.add(gp_session)
        session.commit()
        session.refresh(gp_session)
    return gp_session


def invalidate_gamespy_session(session: Session, sesskey: str) -> bool:
    """Invalidates a GameSpy session."""
    gp_session = get_gamespy_session_by_sesskey(session, sesskey)
    if gp_session:
        gp_session.is_active = False
        session.add(gp_session)
        session.commit()
        return True
    return False


# =============================================================================
# Game Entitlement Operations
# =============================================================================

def get_user_entitlements(session: Session, user_id: int) -> List[GameEntitlement]:
    """Gets all game entitlements for a user."""
    stmt = select(GameEntitlement).where(GameEntitlement.user_id == user_id)
    return list(session.exec(stmt).all())


def create_entitlement(
    session: Session,
    user_id: int,
    game_feature_id: int,
    expiration_days: int = -1,
    message: str = ""
) -> GameEntitlement:
    """Creates a new game entitlement for a user."""
    entitlement = GameEntitlement(
        user_id=user_id,
        game_feature_id=game_feature_id,
        expiration_days=expiration_days,
        message=message,
        status=0
    )
    session.add(entitlement)
    session.commit()
    session.refresh(entitlement)
    return entitlement


# =============================================================================
# Buddy Request Operations
# =============================================================================

def create_buddy_request(
    session: Session,
    from_persona_id: int,
    to_persona_id: int,
    reason: str = ""
) -> BuddyRequest:
    """Creates a new buddy request."""
    # Check if request already exists
    existing = get_pending_buddy_request(session, from_persona_id, to_persona_id)
    if existing:
        return existing

    buddy_request = BuddyRequest(
        from_persona_id=from_persona_id,
        to_persona_id=to_persona_id,
        reason=reason,
        status="pending"
    )
    session.add(buddy_request)
    session.commit()
    session.refresh(buddy_request)
    return buddy_request


def get_pending_buddy_request(
    session: Session,
    from_persona_id: int,
    to_persona_id: int
) -> Optional[BuddyRequest]:
    """Gets a pending buddy request between two personas."""
    stmt = select(BuddyRequest).where(
        BuddyRequest.from_persona_id == from_persona_id,
        BuddyRequest.to_persona_id == to_persona_id,
        BuddyRequest.status == "pending"
    )
    return session.exec(stmt).first()


def get_buddy_requests_for_persona(
    session: Session,
    persona_id: int
) -> List[BuddyRequest]:
    """Gets all pending buddy requests for a persona."""
    stmt = select(BuddyRequest).where(
        BuddyRequest.to_persona_id == persona_id,
        BuddyRequest.status == "pending"
    )
    return list(session.exec(stmt).all())


def accept_buddy_request(
    session: Session,
    from_persona_id: int,
    to_persona_id: int
) -> bool:
    """
    Accepts a buddy request and creates the friend relationship.

    Returns True if successful, False if request not found.
    """
    buddy_request = get_pending_buddy_request(session, from_persona_id, to_persona_id)
    if not buddy_request:
        return False

    # Update request status
    buddy_request.status = "accepted"
    buddy_request.updated_at = datetime.utcnow()
    session.add(buddy_request)

    # Create friend relationship (bidirectional)
    from_persona = session.get(Persona, from_persona_id)
    to_persona = session.get(Persona, to_persona_id)

    if from_persona and to_persona:
        # Add bidirectional friendship
        friend1 = Friend(persona_id=from_persona_id, friend_id=to_persona_id)
        friend2 = Friend(persona_id=to_persona_id, friend_id=from_persona_id)

        # Check if friendship already exists
        existing1 = session.exec(
            select(Friend).where(
                Friend.persona_id == from_persona_id,
                Friend.friend_id == to_persona_id
            )
        ).first()
        existing2 = session.exec(
            select(Friend).where(
                Friend.persona_id == to_persona_id,
                Friend.friend_id == from_persona_id
            )
        ).first()

        if not existing1:
            session.add(friend1)
        if not existing2:
            session.add(friend2)

    session.commit()
    return True


def reject_buddy_request(
    session: Session,
    from_persona_id: int,
    to_persona_id: int
) -> bool:
    """Rejects a buddy request."""
    buddy_request = get_pending_buddy_request(session, from_persona_id, to_persona_id)
    if not buddy_request:
        return False

    buddy_request.status = "rejected"
    buddy_request.updated_at = datetime.utcnow()
    session.add(buddy_request)
    session.commit()
    return True


def are_buddies(session: Session, persona_id_1: int, persona_id_2: int) -> bool:
    """Checks if two personas are buddies."""
    stmt = select(Friend).where(
        Friend.persona_id == persona_id_1,
        Friend.friend_id == persona_id_2
    )
    return session.exec(stmt).first() is not None


def remove_buddy(session: Session, persona_id_1: int, persona_id_2: int) -> bool:
    """Removes buddy relationship between two personas."""
    # Remove both directions
    stmt1 = select(Friend).where(
        Friend.persona_id == persona_id_1,
        Friend.friend_id == persona_id_2
    )
    stmt2 = select(Friend).where(
        Friend.persona_id == persona_id_2,
        Friend.friend_id == persona_id_1
    )

    friend1 = session.exec(stmt1).first()
    friend2 = session.exec(stmt2).first()

    if friend1:
        session.delete(friend1)
    if friend2:
        session.delete(friend2)

    session.commit()
    return friend1 is not None or friend2 is not None


def delete_buddy_one_way(session: Session, persona_id: int, buddy_id: int) -> bool:
    """
    Removes buddy from persona's friend list (one-way deletion).

    This only removes the buddy from the requesting persona's list.
    If the buddy has the persona in their list, it stays there.
    """
    stmt = select(Friend).where(
        Friend.persona_id == persona_id,
        Friend.friend_id == buddy_id
    )
    friend = session.exec(stmt).first()

    if friend:
        session.delete(friend)
        session.commit()
        return True
    return False


# =============================================================================
# Game Invite Operations
# =============================================================================

def create_game_invite(
    session: Session,
    from_persona_id: int,
    to_persona_id: int,
    product_id: int,
    location: str
) -> GameInvite:
    """Creates a new game invite."""
    invite = GameInvite(
        from_persona_id=from_persona_id,
        to_persona_id=to_persona_id,
        product_id=product_id,
        location=location,
        status="pending"
    )
    session.add(invite)
    session.commit()
    session.refresh(invite)
    return invite


def get_pending_invites_for_persona(
    session: Session,
    persona_id: int
) -> List[GameInvite]:
    """Gets all pending game invites for a persona."""
    stmt = select(GameInvite).where(
        GameInvite.to_persona_id == persona_id,
        GameInvite.status == "pending",
        GameInvite.expires_at > datetime.utcnow()
    )
    return list(session.exec(stmt).all())
