import base64
import random
import secrets
import string
from datetime import datetime

from sqlmodel import Session, select

from app.models.models import (
    AuthCertificate,
    BuddyRequest,
    Clan,
    ClanMembership,
    CompetitionSession,
    FeslSession,
    Friend,
    GameEntitlement,
    GameInvite,
    GameSpyPreAuthTicket,
    GameSpySession,
    MatchReport,
    Persona,
    PlayerLevel,
    PlayerReportIntent,
    PlayerStats,
    User,
    UserCreate,
    WebSession,
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
    user_db = User(username=user_create.username, hashed_password=hashed_pass, email=user_create.email)

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
        expiration_days=-1,  # Never expires
        status=0,
    )
    session.add(entitlement)
    session.commit()

    return user_db


def get_user_by_id(session: Session, user_id: int) -> User | None:
    """Retrieves a user by their ID."""
    return session.get(User, user_id)


def get_user_by_username(session: Session, username: str) -> User | None:
    """Retrieves a user by their username."""
    statement = select(User).where(User.username == username)
    user = session.exec(statement).first()
    return user


def get_user_by_email(session: Session, email: str) -> User | None:
    """Retrieves a user by their email (nuid)."""
    statement = select(User).where(User.email == email)
    user = session.exec(statement).first()
    return user


def get_user_by_username_and_password(session: Session, username: str, password: str) -> User | None:
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


def update_user_mac_addr(session: Session, user_id: int, mac_addr: str) -> User | None:
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


def get_persona_by_id(session: Session, persona_id: int) -> Persona | None:
    """Retrieves a persona by ID."""
    return session.get(Persona, persona_id)


def get_persona_by_name(session: Session, name: str) -> Persona | None:
    """Retrieves a persona by their name."""
    statement = select(Persona).where(Persona.name == name)
    persona = session.exec(statement).first()
    return persona


def get_personas_for_user(session: Session, user_id: int) -> list[Persona]:
    """Retrieves all personas for a user."""
    statement = select(Persona).where(Persona.user_id == user_id)
    personas = session.exec(statement).all()
    return list(personas)


def get_user_from_persona(session: Session, persona_id: int) -> User | None:
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


def get_persona_friends(session: Session, persona_id: int) -> list[Persona]:
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
    lkey = base64.b64encode(token).decode("utf-8")
    # Format similar to real FESL lkeys (e.g., T4QdgDQCFm83wYUMCn4qpAAAKDw.)
    return lkey.rstrip("=") + "."


def create_fesl_session(
    session: Session, user_id: int, client_ip: str | None = None, mac_addr: str | None = None
) -> FeslSession:
    """Creates a new FESL session for a user after NuLogin."""
    lkey = generate_lkey()

    fesl_session = FeslSession(lkey=lkey, user_id=user_id, client_ip=client_ip, mac_addr=mac_addr, is_active=True)

    session.add(fesl_session)
    session.commit()
    session.refresh(fesl_session)
    return fesl_session


def update_fesl_session_persona(session: Session, lkey: str, persona_id: int) -> FeslSession | None:
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


def get_fesl_session_by_lkey(session: Session, lkey: str) -> FeslSession | None:
    """Retrieves an active FESL session by lkey."""
    stmt = select(FeslSession).where(
        FeslSession.lkey == lkey, FeslSession.is_active == True, FeslSession.expires_at > datetime.utcnow()
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
    return "".join(random.choice(string.ascii_lowercase) for _ in range(8))


def generate_secret_token() -> str:
    """Generates a random secret token for the ticket."""
    return secrets.token_urlsafe(16)


def create_preauth_ticket(session: Session, user_id: int, persona_id: int) -> GameSpyPreAuthTicket:
    """
    Creates a GameSpy pre-auth ticket for cross-service handshake.

    The ticket format is: base64(userId|profileId|secretToken)
    """
    challenge = generate_challenge()
    secret_token = generate_secret_token()

    # Create ticket payload: userId|profileId|secretToken
    ticket_payload = f"{user_id}|{persona_id}|{secret_token}"
    ticket = base64.b64encode(ticket_payload.encode("utf-8")).decode("utf-8")

    preauth = GameSpyPreAuthTicket(
        ticket=ticket,
        challenge=challenge,
        secret_token=secret_token,
        user_id=user_id,
        persona_id=persona_id,
        is_used=False,
    )

    session.add(preauth)
    session.commit()
    session.refresh(preauth)
    return preauth


def validate_and_consume_preauth_ticket(session: Session, ticket: str) -> tuple[int, int, GameSpyPreAuthTicket] | None:
    """
    Validates a pre-auth ticket and marks it as used.

    Returns (user_id, persona_id, ticket) if valid, None otherwise.
    """
    stmt = select(GameSpyPreAuthTicket).where(
        GameSpyPreAuthTicket.ticket == ticket,
        GameSpyPreAuthTicket.is_used == False,
        GameSpyPreAuthTicket.expires_at > datetime.utcnow(),
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


def parse_ticket(ticket: str) -> tuple[int, int, str] | None:
    """
    Parses a ticket to extract user_id, persona_id, and secret_token.

    Returns (user_id, persona_id, secret_token) or None if invalid.
    """
    try:
        decoded = base64.b64decode(ticket).decode("utf-8")
        parts = decoded.split("|")
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
    preauth_ticket_id: int | None = None,
    client_ip: str | None = None,
    port: int | None = None,
    product_id: int | None = None,
    gamename: str | None = None,
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
        is_active=True,
    )

    session.add(gp_session)
    session.commit()
    session.refresh(gp_session)
    return gp_session


def get_gamespy_session_by_sesskey(session: Session, sesskey: str) -> GameSpySession | None:
    """Retrieves an active GameSpy session by sesskey."""
    stmt = select(GameSpySession).where(
        GameSpySession.sesskey == sesskey,
        GameSpySession.is_active == True,
        GameSpySession.expires_at > datetime.utcnow(),
    )
    return session.exec(stmt).first()


def update_gamespy_session_status(
    session: Session, sesskey: str, status: str, stat_string: str = "", loc_string: str = ""
) -> GameSpySession | None:
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


def get_user_entitlements(session: Session, user_id: int) -> list[GameEntitlement]:
    """Gets all game entitlements for a user."""
    stmt = select(GameEntitlement).where(GameEntitlement.user_id == user_id)
    return list(session.exec(stmt).all())


def create_entitlement(
    session: Session, user_id: int, game_feature_id: int, expiration_days: int = -1, message: str = ""
) -> GameEntitlement:
    """Creates a new game entitlement for a user."""
    entitlement = GameEntitlement(
        user_id=user_id, game_feature_id=game_feature_id, expiration_days=expiration_days, message=message, status=0
    )
    session.add(entitlement)
    session.commit()
    session.refresh(entitlement)
    return entitlement


# =============================================================================
# Buddy Request Operations
# =============================================================================


def create_buddy_request(session: Session, from_persona_id: int, to_persona_id: int, reason: str = "") -> BuddyRequest:
    """Creates a new buddy request."""
    # Check if request already exists
    existing = get_pending_buddy_request(session, from_persona_id, to_persona_id)
    if existing:
        return existing

    buddy_request = BuddyRequest(
        from_persona_id=from_persona_id, to_persona_id=to_persona_id, reason=reason, status="pending"
    )
    session.add(buddy_request)
    session.commit()
    session.refresh(buddy_request)
    return buddy_request


def get_pending_buddy_request(session: Session, from_persona_id: int, to_persona_id: int) -> BuddyRequest | None:
    """Gets a pending buddy request between two personas."""
    stmt = select(BuddyRequest).where(
        BuddyRequest.from_persona_id == from_persona_id,
        BuddyRequest.to_persona_id == to_persona_id,
        BuddyRequest.status == "pending",
    )
    return session.exec(stmt).first()


def get_buddy_requests_for_persona(session: Session, persona_id: int) -> list[BuddyRequest]:
    """Gets all pending buddy requests for a persona."""
    stmt = select(BuddyRequest).where(BuddyRequest.to_persona_id == persona_id, BuddyRequest.status == "pending")
    return list(session.exec(stmt).all())


def accept_buddy_request(session: Session, from_persona_id: int, to_persona_id: int) -> bool:
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
            select(Friend).where(Friend.persona_id == from_persona_id, Friend.friend_id == to_persona_id)
        ).first()
        existing2 = session.exec(
            select(Friend).where(Friend.persona_id == to_persona_id, Friend.friend_id == from_persona_id)
        ).first()

        if not existing1:
            session.add(friend1)
        if not existing2:
            session.add(friend2)

    session.commit()
    return True


def reject_buddy_request(session: Session, from_persona_id: int, to_persona_id: int) -> bool:
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
    stmt = select(Friend).where(Friend.persona_id == persona_id_1, Friend.friend_id == persona_id_2)
    return session.exec(stmt).first() is not None


def remove_buddy(session: Session, persona_id_1: int, persona_id_2: int) -> bool:
    """Removes buddy relationship between two personas."""
    # Remove both directions
    stmt1 = select(Friend).where(Friend.persona_id == persona_id_1, Friend.friend_id == persona_id_2)
    stmt2 = select(Friend).where(Friend.persona_id == persona_id_2, Friend.friend_id == persona_id_1)

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
    stmt = select(Friend).where(Friend.persona_id == persona_id, Friend.friend_id == buddy_id)
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
    session: Session, from_persona_id: int, to_persona_id: int, product_id: int, location: str
) -> GameInvite:
    """Creates a new game invite."""
    invite = GameInvite(
        from_persona_id=from_persona_id,
        to_persona_id=to_persona_id,
        product_id=product_id,
        location=location,
        status="pending",
    )
    session.add(invite)
    session.commit()
    session.refresh(invite)
    return invite


def get_pending_invites_for_persona(session: Session, persona_id: int) -> list[GameInvite]:
    """Gets all pending game invites for a persona."""
    stmt = select(GameInvite).where(
        GameInvite.to_persona_id == persona_id,
        GameInvite.status == "pending",
        GameInvite.expires_at > datetime.utcnow(),
    )
    return list(session.exec(stmt).all())


# =============================================================================
# Player Stats Operations
# =============================================================================


def get_player_stats(session: Session, persona_id: int) -> PlayerStats | None:
    """Gets player stats for a persona."""
    stmt = select(PlayerStats).where(PlayerStats.persona_id == persona_id)
    return session.exec(stmt).first()


def create_or_update_player_stats(session: Session, persona_id: int, stats_data: dict) -> PlayerStats:
    """
    Creates or updates player stats for a persona.

    Args:
        session: Database session
        persona_id: Persona ID
        stats_data: Dictionary of stats fields to update

    Returns:
        Updated or created PlayerStats
    """
    stats = get_player_stats(session, persona_id)

    if stats is None:
        stats = PlayerStats(persona_id=persona_id)
        session.add(stats)

    # Update fields from stats_data
    for field, value in stats_data.items():
        if hasattr(stats, field):
            setattr(stats, field, value)

    stats.updated_at = datetime.utcnow()
    session.commit()
    session.refresh(stats)
    return stats


def get_player_level(session: Session, persona_id: int) -> PlayerLevel | None:
    """Gets player level for a persona."""
    stmt = select(PlayerLevel).where(PlayerLevel.persona_id == persona_id)
    return session.exec(stmt).first()


def create_or_update_player_level(session: Session, persona_id: int, rank: int = 1, score: int = 0) -> PlayerLevel:
    """
    Creates or updates player level for a persona.

    Args:
        session: Database session
        persona_id: Persona ID
        rank: Player rank (1-87)
        score: XP score

    Returns:
        Updated or created PlayerLevel
    """
    level = get_player_level(session, persona_id)

    if level is None:
        level = PlayerLevel(persona_id=persona_id, rank=rank, score=score)
        session.add(level)
    else:
        level.rank = rank
        level.score = score

    session.commit()
    session.refresh(level)
    return level


# =============================================================================
# ELO Rating Operations
# =============================================================================


def calculate_expected_score(player_rating: int, opponent_rating: int) -> float:
    """
    Calculate the expected score for a player against an opponent.

    Formula: Expected = 1 / (1 + 10^((OpponentRating - PlayerRating) / 400))

    Args:
        player_rating: The player's current ELO rating.
        opponent_rating: The opponent's current ELO rating.

    Returns:
        Expected score between 0.0 and 1.0.
    """
    return 1.0 / (1.0 + pow(10, (opponent_rating - player_rating) / 400.0))


def get_k_factor(games_played: int, current_rating: int) -> int:
    """
    Determine the K-factor for ELO calculation.

    K-factors:
    - K=40 for new players (<30 games)
    - K=20 for established players
    - K=10 for elite players (2400+ rating)

    Args:
        games_played: Number of games played in this game type.
        current_rating: Current ELO rating.

    Returns:
        K-factor value (10, 20, or 40).
    """
    if current_rating >= 2400:
        return 10
    if games_played < 30:
        return 40
    return 20


def calculate_new_elo(player_rating: int, opponent_rating: int, actual_score: float, k_factor: int) -> int:
    """
    Calculate new ELO rating after a match.

    Formula: New = Old + K * (Actual - Expected)

    Args:
        player_rating: Current player rating.
        opponent_rating: Opponent's rating.
        actual_score: 1.0 for win, 0.5 for draw, 0.0 for loss.
        k_factor: K-factor for calculation.

    Returns:
        New ELO rating (minimum 100).
    """
    expected = calculate_expected_score(player_rating, opponent_rating)
    new_rating = player_rating + k_factor * (actual_score - expected)
    return max(100, int(round(new_rating)))


def update_player_elo(
    session: Session,
    persona_id: int,
    game_type: str,
    opponent_rating: int,
    won: bool,
    disconnected: bool = False,
) -> PlayerStats:
    """
    Update a player's ELO rating after a match.

    Args:
        session: Database session.
        persona_id: Player's persona ID.
        game_type: Game type (ranked_1v1, ranked_2v2, clan_1v1, clan_2v2).
        opponent_rating: Opponent's ELO rating.
        won: True if player won, False if lost.
        disconnected: True if player disconnected (1.5x K-factor penalty on loss).

    Returns:
        Updated PlayerStats.
    """
    stats = get_player_stats(session, persona_id)
    if stats is None:
        stats = PlayerStats(persona_id=persona_id)
        session.add(stats)
        session.commit()
        session.refresh(stats)

    # Map game type to field names
    elo_field = f"elo_{game_type}"
    games_field = f"games_{game_type}"

    current_elo = getattr(stats, elo_field, 1200)
    games_played = getattr(stats, games_field, 0)

    # Calculate K-factor
    k_factor = get_k_factor(games_played, current_elo)

    # Apply disconnect penalty (1.5x K on loss)
    if disconnected and not won:
        k_factor = int(k_factor * 1.5)

    # Calculate new rating
    actual_score = 1.0 if won else 0.0
    new_elo = calculate_new_elo(current_elo, opponent_rating, actual_score, k_factor)

    # Update stats
    setattr(stats, elo_field, new_elo)
    setattr(stats, games_field, games_played + 1)
    stats.updated_at = datetime.utcnow()

    session.add(stats)
    session.commit()
    session.refresh(stats)
    return stats


def update_player_win_loss(
    session: Session,
    persona_id: int,
    game_type: str,
    result: int,
    duration: int = 0,
) -> PlayerStats:
    """
    Update a player's win/loss/disconnect/dsync counters.

    Args:
        session: Database session.
        persona_id: Player's persona ID.
        game_type: Game type (unranked, ranked_1v1, ranked_2v2, clan_1v1, clan_2v2).
        result: Match result (0=win, 1=loss, 3=disconnect, 4=dsync).
        duration: Match duration in seconds.

    Returns:
        Updated PlayerStats.
    """
    stats = get_player_stats(session, persona_id)
    if stats is None:
        stats = PlayerStats(persona_id=persona_id)
        session.add(stats)
        session.commit()
        session.refresh(stats)

    # Update win/loss/dc/dsync counters
    if result == 0:  # Win
        wins_field = f"wins_{game_type}"
        current_wins = getattr(stats, wins_field, 0)
        setattr(stats, wins_field, current_wins + 1)
    elif result == 1:  # Loss
        losses_field = f"losses_{game_type}"
        current_losses = getattr(stats, losses_field, 0)
        setattr(stats, losses_field, current_losses + 1)
    elif result == 3:  # Disconnect
        dc_field = f"disconnects_{game_type}"
        current_dc = getattr(stats, dc_field, 0)
        setattr(stats, dc_field, current_dc + 1)
    elif result == 4:  # Dsync
        dsync_field = f"desyncs_{game_type}"
        current_dsync = getattr(stats, dsync_field, 0)
        setattr(stats, dsync_field, current_dsync + 1)

    # Update average game length
    if duration > 0:
        avg_field = f"avg_game_length_{game_type}"
        wins_field = f"wins_{game_type}"
        losses_field = f"losses_{game_type}"
        total_games = getattr(stats, wins_field, 0) + getattr(stats, losses_field, 0)
        if total_games > 0:
            current_avg = getattr(stats, avg_field, 0)
            new_avg = int((current_avg * (total_games - 1) + duration) / total_games)
            setattr(stats, avg_field, new_avg)

    # Update win ratio
    wins_field = f"wins_{game_type}"
    losses_field = f"losses_{game_type}"
    wins = getattr(stats, wins_field, 0)
    losses = getattr(stats, losses_field, 0)
    total = wins + losses
    if total > 0:
        ratio_field = f"win_ratio_{game_type}"
        setattr(stats, ratio_field, (wins / total) * 100)

    # Update total matches online
    stats.total_matches_online += 1
    stats.updated_at = datetime.utcnow()

    session.add(stats)
    session.commit()
    session.refresh(stats)
    return stats


# =============================================================================
# Competition Session Operations
# =============================================================================


def generate_csid() -> str:
    """Generates a unique Competition Session ID."""
    return secrets.token_urlsafe(16)


def generate_ccid(persona_id: int = 0) -> str:
    """
    Generates a unique Competition Channel ID with embedded persona_id.

    Format: base64url(persona_id as 4 bytes big-endian) + random suffix
    This allows us to recover the persona_id from the ccid later.

    Args:
        persona_id: The persona ID to embed in the ccid.

    Returns:
        A unique ccid string with embedded persona_id.
    """
    # Encode persona_id as 4 bytes big-endian, then base64url (6 chars without padding)
    persona_bytes = persona_id.to_bytes(4, "big")
    encoded = base64.urlsafe_b64encode(persona_bytes).decode().rstrip("=")
    # Add random suffix for uniqueness
    random_suffix = secrets.token_urlsafe(8)
    return f"{encoded}{random_suffix}"


def extract_persona_from_ccid(ccid: str) -> int | None:
    """
    Extract persona_id from a ccid that was generated with generate_ccid.

    Args:
        ccid: The Competition Channel ID.

    Returns:
        The embedded persona_id, or None if extraction fails.
    """
    try:
        # First 6 chars are base64url encoded persona_id (4 bytes -> 6 chars)
        encoded = ccid[:6]
        # Add padding for base64 decoding
        padded = encoded + "=="
        persona_bytes = base64.urlsafe_b64decode(padded)
        return int.from_bytes(persona_bytes, "big")
    except Exception:
        return None


def create_competition_session(session: Session, host_persona_id: int) -> CompetitionSession:
    """
    Creates a new competition session.

    Args:
        session: Database session
        host_persona_id: Persona ID of the match host

    Returns:
        New CompetitionSession with csid and ccid
    """
    csid = generate_csid()
    ccid = generate_ccid(host_persona_id)  # Embed persona_id in ccid

    comp_session = CompetitionSession(
        csid=csid,
        ccid=ccid,
        host_persona_id=host_persona_id,
        status="active",
    )

    session.add(comp_session)
    session.commit()
    session.refresh(comp_session)
    return comp_session


def get_competition_session(session: Session, csid: str) -> CompetitionSession | None:
    """Gets a competition session by csid."""
    stmt = select(CompetitionSession).where(CompetitionSession.csid == csid)
    return session.exec(stmt).first()


def set_report_intention(
    session: Session, csid: str, ccid: str, persona_id: int, full_id: str = ""
) -> PlayerReportIntent | None:
    """
    Signals that a player intends to submit a match report.

    Creates a PlayerReportIntent record and generates a new ccid for this player.

    Args:
        session: Database session.
        csid: Competition Session ID.
        ccid: Competition Channel ID (passed in from request).
        persona_id: Persona ID.
        full_id: Player's full GUID from the game.

    Returns:
        PlayerReportIntent if successful, None otherwise.
    """
    comp_session = get_competition_session(session, csid)
    if comp_session is None:
        return None

    # Generate a unique ccid for this player with embedded persona_id
    player_ccid = generate_ccid(persona_id)

    # Create the report intent record
    intent = PlayerReportIntent(
        csid=csid,
        ccid=player_ccid,
        persona_id=persona_id,
        full_id=full_id,
        reported=False,
    )
    session.add(intent)
    session.commit()
    session.refresh(intent)

    return intent


def get_report_intent(session: Session, csid: str, persona_id: int) -> PlayerReportIntent | None:
    """Gets a report intent by csid and persona_id."""
    stmt = select(PlayerReportIntent).where(
        PlayerReportIntent.csid == csid,
        PlayerReportIntent.persona_id == persona_id,
    )
    return session.exec(stmt).first()


def get_report_intent_by_ccid(session: Session, ccid: str) -> PlayerReportIntent | None:
    """Gets a report intent by ccid."""
    stmt = select(PlayerReportIntent).where(PlayerReportIntent.ccid == ccid)
    return session.exec(stmt).first()


def get_all_report_intents(session: Session, csid: str) -> list[PlayerReportIntent]:
    """Gets all report intents for a competition session."""
    stmt = select(PlayerReportIntent).where(PlayerReportIntent.csid == csid)
    return list(session.exec(stmt).all())


def mark_report_intent_reported(session: Session, ccid: str, full_id: str = "") -> PlayerReportIntent | None:
    """Marks a report intent as reported and updates full_id if provided."""
    intent = get_report_intent_by_ccid(session, ccid)
    if intent:
        intent.reported = True
        if full_id:
            intent.full_id = full_id
        session.add(intent)
        session.commit()
        session.refresh(intent)
    return intent


def submit_match_report(
    session: Session,
    csid: str,
    ccid: str,
    persona_id: int,
    report_data: dict,
) -> MatchReport:
    """
    Submits a match report.

    Args:
        session: Database session
        csid: Competition Session ID
        ccid: Competition Channel ID
        persona_id: Persona ID of reporter
        report_data: Match report data (result, faction, duration, gametype, map_name)

    Returns:
        Created MatchReport
    """
    report = MatchReport(
        csid=csid,
        ccid=ccid,
        persona_id=persona_id,
        submitted_by=str(persona_id),
        result=report_data.get("result", 0),
        faction=report_data.get("faction", ""),
        duration=report_data.get("duration", 0),
        gametype=report_data.get("gametype", 0),
        map_name=report_data.get("map_name", ""),
    )

    session.add(report)
    session.commit()
    session.refresh(report)
    return report


def complete_competition_session(session: Session, csid: str) -> bool:
    """Marks a competition session as completed."""
    comp_session = get_competition_session(session, csid)
    if comp_session:
        comp_session.status = "completed"
        session.add(comp_session)
        session.commit()
        return True
    return False


def increment_received_reports(session: Session, csid: str) -> CompetitionSession | None:
    """Increments the received_reports counter for a competition session."""
    comp_session = get_competition_session(session, csid)
    if comp_session:
        comp_session.received_reports += 1
        session.add(comp_session)
        session.commit()
        session.refresh(comp_session)
    return comp_session


def get_match_reports_for_session(session: Session, csid: str) -> list[MatchReport]:
    """Gets all match reports for a competition session."""
    stmt = select(MatchReport).where(MatchReport.csid == csid)
    return list(session.exec(stmt).all())


def finalize_match(session: Session, csid: str) -> bool:
    """
    Finalize a match by calculating and updating ELO ratings.

    This function should be called when all reports have been received.
    It correlates winners/losers from the reports and updates player stats.

    Args:
        session: Database session.
        csid: Competition Session ID.

    Returns:
        True if match was finalized successfully.
    """
    comp_session = get_competition_session(session, csid)
    if comp_session is None or comp_session.finalized:
        return False

    # Get all match reports for this session
    reports = get_match_reports_for_session(session, csid)
    if not reports:
        return False

    # Calculate match duration from session creation time
    duration = int((datetime.utcnow() - comp_session.created_at).total_seconds())

    # Determine game type string from the gametype int
    # 0=unranked, 1=ranked_1v1, 2=ranked_2v2, 3=clan_1v1, 4=clan_2v2
    game_type_map = {
        0: "unranked",
        1: "ranked_1v1",
        2: "ranked_2v2",
        3: "clan_1v1",
        4: "clan_2v2",
    }

    # Collect player results from reports
    player_results: dict[int, dict] = {}  # persona_id -> {result, faction, elo}

    for report in reports:
        persona_id = report.persona_id
        if persona_id not in player_results:
            # Get current ELO for this player
            stats = get_player_stats(session, persona_id)
            game_type = game_type_map.get(report.gametype, "unranked")

            # Get current ELO based on game type
            current_elo = 1200
            if stats and game_type != "unranked":
                elo_field = f"elo_{game_type}"
                current_elo = getattr(stats, elo_field, 1200)

            player_results[persona_id] = {
                "result": report.result,
                "faction": report.faction,
                "gametype": report.gametype,
                "elo": current_elo,
            }

    # If we have at least 2 players, update stats
    if len(player_results) >= 2:
        # Separate winners and losers
        winners = [pid for pid, data in player_results.items() if data["result"] == 0]
        losers = [pid for pid, data in player_results.items() if data["result"] in (1, 3, 4)]

        # Calculate average opponent ELO for each group
        winner_avg_elo = sum(player_results[pid]["elo"] for pid in winners) / len(winners) if winners else 1200
        loser_avg_elo = sum(player_results[pid]["elo"] for pid in losers) / len(losers) if losers else 1200

        # Get game type from the report with highest gametype value
        # (partial reports may have gametype=0, final report has correct value)
        max_gametype = max(report.gametype for report in reports)
        game_type = game_type_map.get(max_gametype, "unranked")

        # Update each player
        for persona_id, data in player_results.items():
            result = data["result"]
            is_winner = result == 0
            is_disconnect = result == 3

            # Update win/loss counters
            update_player_win_loss(session, persona_id, game_type, result, duration)

            # Update ELO if this is a ranked game type
            if game_type != "unranked":
                opponent_elo = int(loser_avg_elo if is_winner else winner_avg_elo)
                update_player_elo(
                    session,
                    persona_id,
                    game_type,
                    opponent_elo,
                    won=is_winner,
                    disconnected=is_disconnect,
                )

    # Mark session as finalized
    comp_session.finalized = True
    comp_session.status = "completed"
    session.add(comp_session)
    session.commit()

    return True


# =============================================================================
# Auth Certificate Operations
# =============================================================================


def get_available_certificate(session: Session) -> AuthCertificate | None:
    """
    Gets an available certificate from the pool.

    Returns the first unused certificate and marks it as in use.
    """
    stmt = select(AuthCertificate).where(AuthCertificate.in_use == False)
    cert = session.exec(stmt).first()

    if cert:
        cert.in_use = True
        cert.assigned_at = datetime.utcnow()
        session.add(cert)
        session.commit()
        session.refresh(cert)

    return cert


def assign_certificate_to_persona(session: Session, cert_id: int, persona_id: int) -> AuthCertificate | None:
    """Assigns a certificate to a specific persona."""
    cert = session.get(AuthCertificate, cert_id)
    if cert:
        cert.in_use = True
        cert.persona_id = persona_id
        cert.assigned_at = datetime.utcnow()
        session.add(cert)
        session.commit()
        session.refresh(cert)
    return cert


def release_certificate(session: Session, cert_id: int) -> bool:
    """Returns a certificate to the pool."""
    cert = session.get(AuthCertificate, cert_id)
    if cert:
        cert.in_use = False
        cert.persona_id = None
        cert.assigned_at = None
        session.add(cert)
        session.commit()
        return True
    return False


def get_certificate_by_server_data(session: Session, server_data_10: str) -> AuthCertificate | None:
    """Gets a certificate by its first 10 characters of server data."""
    stmt = select(AuthCertificate).where(AuthCertificate.server_data_10 == server_data_10)
    return session.exec(stmt).first()


# =============================================================================
# Leaderboard Operations
# =============================================================================


def get_leaderboard(
    session: Session,
    game_type: str = "ranked_1v1",
    limit: int = 50,
) -> list[dict]:
    """
    Query PlayerStats joined with Persona, sorted by ELO descending.

    Args:
        session: Database session.
        game_type: Game type (ranked_1v1, ranked_2v2, clan_1v1, clan_2v2).
        limit: Maximum number of results to return.

    Returns:
        List of dicts with rank, name, elo, wins, losses, disconnects, win_ratio, total_games.
    """
    # Map game type to field names
    elo_field = f"elo_{game_type}"
    wins_field = f"wins_{game_type}"
    losses_field = f"losses_{game_type}"
    disconnects_field = f"disconnects_{game_type}"
    win_ratio_field = f"win_ratio_{game_type}"

    # Query PlayerStats joined with Persona
    stmt = (
        select(PlayerStats, Persona)
        .join(Persona, PlayerStats.persona_id == Persona.id)
        .order_by(getattr(PlayerStats, elo_field).desc())
        .limit(limit)
    )

    results = session.exec(stmt).all()

    leaderboard = []
    for rank, (stats, persona) in enumerate(results, start=1):
        wins = getattr(stats, wins_field, 0)
        losses = getattr(stats, losses_field, 0)
        total_games = wins + losses

        leaderboard.append(
            {
                "rank": rank,
                "name": persona.name,
                "elo": getattr(stats, elo_field, 1200),
                "wins": wins,
                "losses": losses,
                "disconnects": getattr(stats, disconnects_field, 0),
                "win_ratio": round(getattr(stats, win_ratio_field, 0.0), 1),
                "total_games": total_games,
            }
        )

    return leaderboard


# =============================================================================
# Clan Operations
# =============================================================================


def create_clan(
    session: Session,
    name: str,
    tag: str,
    leader_persona_id: int,
    description: str | None = None,
) -> Clan:
    """
    Create a new clan with the specified persona as leader.

    Args:
        session: Database session
        name: Clan name (unique)
        tag: Clan tag (unique, max 10 chars)
        leader_persona_id: Persona ID of the clan leader
        description: Optional clan description

    Returns:
        Created Clan

    Raises:
        ValueError: If persona is already in a clan
    """
    # Check if persona is already in a clan
    existing = get_persona_clan(session, leader_persona_id)
    if existing:
        raise ValueError("Persona is already in a clan")

    # Create the clan
    clan = Clan(name=name, tag=tag, description=description)
    session.add(clan)
    session.commit()
    session.refresh(clan)

    # Create leader membership
    membership = ClanMembership(
        clan_id=clan.id,
        persona_id=leader_persona_id,
        position=7,  # Leader
    )
    session.add(membership)
    session.commit()

    return clan


def get_clan_by_id(session: Session, clan_id: int) -> Clan | None:
    """Get a clan by ID."""
    return session.get(Clan, clan_id)


def get_clan_by_name(session: Session, name: str) -> Clan | None:
    """Get a clan by name."""
    stmt = select(Clan).where(Clan.name == name)
    return session.exec(stmt).first()


def get_clan_by_tag(session: Session, tag: str) -> Clan | None:
    """Get a clan by tag."""
    stmt = select(Clan).where(Clan.tag == tag)
    return session.exec(stmt).first()


def get_all_clans(session: Session, limit: int = 100, offset: int = 0) -> list[Clan]:
    """Get all clans with pagination."""
    stmt = select(Clan).offset(offset).limit(limit).order_by(Clan.created_at.desc())
    return list(session.exec(stmt).all())


def get_clan_members(session: Session, clan_id: int, position: int | None = None) -> list[ClanMembership]:
    """
    Get clan members, optionally filtered by position.

    Args:
        session: Database session
        clan_id: Clan ID
        position: Optional position filter (0=applicant, 1=member, 7=leader)

    Returns:
        List of ClanMembership objects
    """
    stmt = select(ClanMembership).where(ClanMembership.clan_id == clan_id)
    if position is not None:
        stmt = stmt.where(ClanMembership.position == position)
    return list(session.exec(stmt).all())


def get_clan_leader(session: Session, clan_id: int) -> Persona | None:
    """Get the leader persona of a clan."""
    stmt = select(ClanMembership).where(
        ClanMembership.clan_id == clan_id,
        ClanMembership.position == 7,
    )
    membership = session.exec(stmt).first()
    if membership:
        return get_persona_by_id(session, membership.persona_id)
    return None


def get_persona_clan(session: Session, persona_id: int) -> Clan | None:
    """Get the clan a persona belongs to (if any)."""
    stmt = select(ClanMembership).where(ClanMembership.persona_id == persona_id)
    membership = session.exec(stmt).first()
    if membership:
        return get_clan_by_id(session, membership.clan_id)
    return None


def get_persona_clan_membership(session: Session, persona_id: int) -> ClanMembership | None:
    """Get the clan membership for a persona."""
    stmt = select(ClanMembership).where(ClanMembership.persona_id == persona_id)
    return session.exec(stmt).first()


def join_clan_as_applicant(session: Session, clan_id: int, persona_id: int) -> ClanMembership:
    """
    Request to join a clan as an applicant.

    Args:
        session: Database session
        clan_id: Clan ID to join
        persona_id: Persona ID requesting to join

    Returns:
        Created ClanMembership (with position=0)

    Raises:
        ValueError: If persona is already in a clan
    """
    existing = get_persona_clan_membership(session, persona_id)
    if existing:
        raise ValueError("Persona is already in a clan")

    membership = ClanMembership(
        clan_id=clan_id,
        persona_id=persona_id,
        position=0,  # Applicant
    )
    session.add(membership)
    session.commit()
    session.refresh(membership)
    return membership


def approve_clan_applicant(session: Session, clan_id: int, persona_id: int) -> ClanMembership | None:
    """
    Approve a clan applicant (promote from position 0 to 1).

    Args:
        session: Database session
        clan_id: Clan ID
        persona_id: Persona ID to approve

    Returns:
        Updated ClanMembership or None if not found
    """
    stmt = select(ClanMembership).where(
        ClanMembership.clan_id == clan_id,
        ClanMembership.persona_id == persona_id,
        ClanMembership.position == 0,
    )
    membership = session.exec(stmt).first()
    if membership:
        membership.position = 1  # Member
        membership.joined_at = datetime.utcnow()
        session.add(membership)
        session.commit()
        session.refresh(membership)
    return membership


def reject_clan_applicant(session: Session, clan_id: int, persona_id: int) -> bool:
    """
    Reject a clan applicant (remove from clan).

    Args:
        session: Database session
        clan_id: Clan ID
        persona_id: Persona ID to reject

    Returns:
        True if removed, False if not found
    """
    stmt = select(ClanMembership).where(
        ClanMembership.clan_id == clan_id,
        ClanMembership.persona_id == persona_id,
        ClanMembership.position == 0,
    )
    membership = session.exec(stmt).first()
    if membership:
        session.delete(membership)
        session.commit()
        return True
    return False


def leave_clan(session: Session, persona_id: int) -> bool:
    """
    Leave a clan. Leaders cannot leave unless they transfer leadership first.

    Args:
        session: Database session
        persona_id: Persona ID leaving

    Returns:
        True if left, False if not in clan or is leader

    Raises:
        ValueError: If persona is the clan leader
    """
    membership = get_persona_clan_membership(session, persona_id)
    if not membership:
        return False
    if membership.position == 7:
        raise ValueError("Leaders must transfer leadership before leaving")

    session.delete(membership)
    session.commit()
    return True


def kick_from_clan(session: Session, clan_id: int, persona_id: int) -> bool:
    """
    Kick a member from the clan. Cannot kick the leader.

    Args:
        session: Database session
        clan_id: Clan ID
        persona_id: Persona ID to kick

    Returns:
        True if kicked, False if not found or is leader
    """
    stmt = select(ClanMembership).where(
        ClanMembership.clan_id == clan_id,
        ClanMembership.persona_id == persona_id,
    )
    membership = session.exec(stmt).first()
    if not membership or membership.position == 7:
        return False

    session.delete(membership)
    session.commit()
    return True


def promote_to_leader(session: Session, clan_id: int, old_leader_persona_id: int, new_leader_persona_id: int) -> bool:
    """
    Transfer leadership from one persona to another.

    Args:
        session: Database session
        clan_id: Clan ID
        old_leader_persona_id: Current leader persona ID
        new_leader_persona_id: New leader persona ID

    Returns:
        True if transferred, False if failed
    """
    # Get current leader membership
    old_leader_stmt = select(ClanMembership).where(
        ClanMembership.clan_id == clan_id,
        ClanMembership.persona_id == old_leader_persona_id,
        ClanMembership.position == 7,
    )
    old_leader = session.exec(old_leader_stmt).first()
    if not old_leader:
        return False

    # Get new leader membership (must be a member, not applicant)
    new_leader_stmt = select(ClanMembership).where(
        ClanMembership.clan_id == clan_id,
        ClanMembership.persona_id == new_leader_persona_id,
        ClanMembership.position >= 1,
    )
    new_leader = session.exec(new_leader_stmt).first()
    if not new_leader:
        return False

    # Transfer leadership
    old_leader.position = 1  # Demote to member
    new_leader.position = 7  # Promote to leader

    session.add(old_leader)
    session.add(new_leader)
    session.commit()
    return True


def get_clan_member_count(session: Session, clan_id: int) -> int:
    """Get the number of members in a clan (excluding applicants)."""
    stmt = select(ClanMembership).where(
        ClanMembership.clan_id == clan_id,
        ClanMembership.position >= 1,
    )
    return len(list(session.exec(stmt).all()))


# =============================================================================
# Web Session Operations
# =============================================================================


def create_web_session_record(session: Session, user_id: int, token: str) -> WebSession:
    """Create a new web session record."""
    web_session = WebSession(
        session_token=token,
        user_id=user_id,
        is_active=True,
    )
    session.add(web_session)
    session.commit()
    session.refresh(web_session)
    return web_session


def get_web_session_record(session: Session, token: str) -> WebSession | None:
    """Get an active web session by token."""
    stmt = select(WebSession).where(
        WebSession.session_token == token,
        WebSession.is_active == True,
        WebSession.expires_at > datetime.utcnow(),
    )
    return session.exec(stmt).first()


def delete_web_session_record(session: Session, token: str) -> bool:
    """Delete/invalidate a web session."""
    web_session = get_web_session_record(session, token)
    if web_session:
        web_session.is_active = False
        session.add(web_session)
        session.commit()
        return True
    return False
