from datetime import datetime, timedelta

from pydantic import BaseModel
from sqlmodel import Field, Relationship, SQLModel

# =============================================================================
# Pydantic Models for API (non-database)
# =============================================================================


class UserBase(BaseModel):
    username: str = Field(..., index=True, min_length=3, max_length=50)


class UserCreate(UserBase):
    password: str = Field(..., min_length=6)
    email: str = Field(..., min_length=6)


class UserLogin(UserBase):
    password: str


class UserPublic(UserBase):
    id: int


# =============================================================================
# Database Models
# =============================================================================


class User(SQLModel, table=True):
    """
    User account - the main authentication entity.
    Maps to EA's 'nuid' (Network User ID) concept.

    The userId in FESL responses corresponds to this id.
    """

    id: int | None = Field(default=None, primary_key=True)
    username: str = Field(unique=True, index=True)  # Display name
    email: str = Field(unique=True, index=True)  # nuid for login
    hashed_password: str = Field()
    mac_addr: str | None = Field(default=None)  # Last known MAC address
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)

    # One-to-many relationship with Persona
    # A user can have multiple personas (game characters)
    personas: list["Persona"] = Relationship(back_populates="user")

    # One-to-many relationship with game entitlements
    entitlements: list["GameEntitlement"] = Relationship(back_populates="user")

    # One-to-many relationship with FESL sessions
    fesl_sessions: list["FeslSession"] = Relationship(back_populates="user")


class Friend(SQLModel, table=True):
    """Link table for many-to-many friendship between Personas."""

    persona_id: int | None = Field(default=None, foreign_key="persona.id", primary_key=True)
    friend_id: int | None = Field(default=None, foreign_key="persona.id", primary_key=True)


class Persona(SQLModel, table=True):
    """
    Persona (game character) - belongs to a User.

    The profileId in FESL responses corresponds to this id.
    In Red Alert 3, a persona represents a player's in-game identity.
    """

    id: int | None = Field(default=None, primary_key=True)
    name: str = Field(index=True)  # Unique display name (e.g., "sokiee")
    namespace: str = Field(default="")  # Namespace for the persona

    # Foreign key to User - many personas can belong to one user
    user_id: int | None = Field(default=None, foreign_key="user.id", index=True)
    user: User | None = Relationship(back_populates="personas")

    created_at: datetime = Field(default_factory=datetime.utcnow)

    # Many-to-many relationship for friends
    friends: list["Persona"] = Relationship(
        link_model=Friend,
        sa_relationship_kwargs={
            "primaryjoin": "Persona.id==Friend.persona_id",
            "secondaryjoin": "Persona.id==Friend.friend_id",
        },
    )

    # One-to-many relationship with FESL sessions (when logged in with this persona)
    fesl_sessions: list["FeslSession"] = Relationship(back_populates="persona")

    # One-to-many relationship with GameSpy pre-auth tickets
    preauth_tickets: list["GameSpyPreAuthTicket"] = Relationship(back_populates="persona")


class FeslSession(SQLModel, table=True):
    """
    FESL Session - tracks login sessions with lkey tokens.

    The lkey is generated after NuLogin and updated after NuLoginPersona.
    This allows tracking which user/persona is authenticated.
    """

    __tablename__ = "fesl_session"

    id: int | None = Field(default=None, primary_key=True)

    # The lkey token returned to the client
    lkey: str = Field(unique=True, index=True)

    # User who owns this session
    user_id: int = Field(foreign_key="user.id", index=True)
    user: User | None = Relationship(back_populates="fesl_sessions")

    # Persona associated with this session (set after NuLoginPersona)
    persona_id: int | None = Field(default=None, foreign_key="persona.id", index=True)
    persona: Persona | None = Relationship(back_populates="fesl_sessions")

    # Session metadata
    client_ip: str | None = Field(default=None)
    mac_addr: str | None = Field(default=None)

    created_at: datetime = Field(default_factory=datetime.utcnow)
    expires_at: datetime = Field(default_factory=lambda: datetime.utcnow() + timedelta(hours=24))

    # Session state
    is_active: bool = Field(default=True)


class GameSpyPreAuthTicket(SQLModel, table=True):
    """
    GameSpy Pre-Auth Ticket - used for cross-service handshake between FESL and GPServer.

    Flow:
    1. Client calls GameSpyPreAuth on FESL
    2. FESL generates: challenge (random string) and ticket (base64 of userId|profileId|token)
    3. FESL stores this ticket in the database
    4. Client sends the ticket to GPServer as 'authtoken'
    5. GPServer validates the ticket by looking it up in this table
    6. GPServer extracts userId and profileId from the ticket

    The ticket format is: base64(userId|profileId|secretToken)
    """

    __tablename__ = "gamespy_preauth_ticket"

    id: int | None = Field(default=None, primary_key=True)

    # The full base64-encoded ticket sent to the client
    ticket: str = Field(unique=True, index=True)

    # The challenge string sent with the ticket
    challenge: str = Field()

    # The secret token embedded in the ticket (for verification)
    secret_token: str = Field(index=True)

    # User and Persona this ticket belongs to
    user_id: int = Field(foreign_key="user.id", index=True)
    persona_id: int = Field(foreign_key="persona.id", index=True)
    persona: Persona | None = Relationship(back_populates="preauth_tickets")

    # Ticket lifecycle
    created_at: datetime = Field(default_factory=datetime.utcnow)
    expires_at: datetime = Field(default_factory=lambda: datetime.utcnow() + timedelta(minutes=5))

    # Whether this ticket has been used (one-time use)
    is_used: bool = Field(default=False)
    used_at: datetime | None = Field(default=None)


class GameSpySession(SQLModel, table=True):
    """
    GameSpy Session - tracks active GPServer sessions.

    Created after successful GPServer login using a pre-auth ticket.
    """

    __tablename__ = "gamespy_session"

    id: int | None = Field(default=None, primary_key=True)

    # Session key returned to the client
    sesskey: str = Field(unique=True, index=True)

    # User and Persona this session belongs to
    user_id: int = Field(foreign_key="user.id", index=True)
    persona_id: int = Field(foreign_key="persona.id", index=True)

    # Reference to the pre-auth ticket that was used
    preauth_ticket_id: int | None = Field(default=None, foreign_key="gamespy_preauth_ticket.id")

    # Session metadata
    client_ip: str | None = Field(default=None)
    port: int | None = Field(default=None)
    product_id: int | None = Field(default=None)
    gamename: str | None = Field(default=None)

    created_at: datetime = Field(default_factory=datetime.utcnow)
    expires_at: datetime = Field(default_factory=lambda: datetime.utcnow() + timedelta(hours=24))

    # Session state
    is_active: bool = Field(default=True)
    status: str = Field(default="Online")  # Online, Away, etc.
    stat_string: str = Field(default="Online")
    loc_string: str = Field(default="")


class GameEntitlement(SQLModel, table=True):
    """
    Game Entitlement - represents what game features a user has access to.

    Returned in the entitledGameFeatureWrappers array during NuLogin.
    For Red Alert 3, gameFeatureId 6014 is typically used.
    """

    __tablename__ = "game_entitlement"

    id: int | None = Field(default=None, primary_key=True)

    # User who owns this entitlement
    user_id: int = Field(foreign_key="user.id", index=True)
    user: User | None = Relationship(back_populates="entitlements")

    # Game feature details
    game_feature_id: int = Field()  # e.g., 6014 for RA3

    # Expiration (-1 means never expires)
    expiration_days: int = Field(default=-1)
    expiration_date: str | None = Field(default="")

    # Additional info
    message: str | None = Field(default="")
    status: int = Field(default=0)  # 0 = active

    created_at: datetime = Field(default_factory=datetime.utcnow)


class BuddyRequest(SQLModel, table=True):
    r"""
    Buddy Request - represents a pending friend request between personas.

    Flow:
    1. Player A sends \addbuddy\ for Player B
    2. Server creates BuddyRequest and sends \bm\2\ to Player B
    3. Player B sends \authadd\ to accept
    4. Server creates Friend relationship and updates BuddyRequest status
    """

    __tablename__ = "buddy_request"

    id: int | None = Field(default=None, primary_key=True)

    # The persona who sent the request
    from_persona_id: int = Field(foreign_key="persona.id", index=True)

    # The persona who received the request
    to_persona_id: int = Field(foreign_key="persona.id", index=True)

    # Request reason/message
    reason: str = Field(default="")

    # Request status: pending, accepted, rejected
    status: str = Field(default="pending", index=True)

    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)


class GameInvite(SQLModel, table=True):
    r"""
    Game Invite - represents a game invitation sent via \pinvite\.

    Used to invite buddies to join a game lobby.
    """

    __tablename__ = "game_invite"

    id: int | None = Field(default=None, primary_key=True)

    # The persona who sent the invite
    from_persona_id: int = Field(foreign_key="persona.id", index=True)

    # The persona who received the invite
    to_persona_id: int = Field(foreign_key="persona.id", index=True)

    # Product/game info
    product_id: int = Field(default=11419)  # RA3 product ID

    # Location string (contains lobby info)
    # Format: "<channel_id> <unknown> <flags> PW: #HOST:<host> <topic> #FROM:<inviter> #CHAN:<channel>"
    location: str = Field(default="")

    # Invite status: pending, accepted, rejected, expired
    status: str = Field(default="pending", index=True)

    created_at: datetime = Field(default_factory=datetime.utcnow)
    expires_at: datetime = Field(default_factory=lambda: datetime.utcnow() + timedelta(minutes=5))


# =============================================================================
# Game Stats Models
# =============================================================================


class PlayerStats(SQLModel, table=True):
    """
    Player Stats - Career statistics by game type.

    Stores wins, losses, disconnects, desyncs, and other stats
    for each game type (unranked, ranked 1v1, ranked 2v2, clan 1v1, clan 2v2).
    """

    __tablename__ = "player_stats"

    id: int | None = Field(default=None, primary_key=True)
    persona_id: int = Field(foreign_key="persona.id", unique=True, index=True)

    # Wins per game type
    wins_unranked: int = Field(default=0)
    wins_ranked_1v1: int = Field(default=0)
    wins_ranked_2v2: int = Field(default=0)
    wins_clan_1v1: int = Field(default=0)
    wins_clan_2v2: int = Field(default=0)

    # Losses per game type
    losses_unranked: int = Field(default=0)
    losses_ranked_1v1: int = Field(default=0)
    losses_ranked_2v2: int = Field(default=0)
    losses_clan_1v1: int = Field(default=0)
    losses_clan_2v2: int = Field(default=0)

    # Disconnects per game type
    disconnects_unranked: int = Field(default=0)
    disconnects_ranked_1v1: int = Field(default=0)
    disconnects_ranked_2v2: int = Field(default=0)
    disconnects_clan_1v1: int = Field(default=0)
    disconnects_clan_2v2: int = Field(default=0)

    # Desyncs per game type
    desyncs_unranked: int = Field(default=0)
    desyncs_ranked_1v1: int = Field(default=0)
    desyncs_ranked_2v2: int = Field(default=0)
    desyncs_clan_1v1: int = Field(default=0)
    desyncs_clan_2v2: int = Field(default=0)

    # Average game length (seconds) per game type
    avg_game_length_unranked: int = Field(default=0)
    avg_game_length_ranked_1v1: int = Field(default=0)
    avg_game_length_ranked_2v2: int = Field(default=0)
    avg_game_length_clan_1v1: int = Field(default=0)
    avg_game_length_clan_2v2: int = Field(default=0)

    # Win/loss ratio per game type (stored as percentage * 100, e.g., 50.5% = 5050)
    win_ratio_unranked: float = Field(default=0.0)
    win_ratio_ranked_1v1: float = Field(default=0.0)
    win_ratio_ranked_2v2: float = Field(default=0.0)
    win_ratio_clan_1v1: float = Field(default=0.0)
    win_ratio_clan_2v2: float = Field(default=0.0)

    total_matches_online: int = Field(default=0)

    # ELO ratings per game type (initial 1200)
    elo_ranked_1v1: int = Field(default=1200)
    elo_ranked_2v2: int = Field(default=1200)
    elo_clan_1v1: int = Field(default=1200)
    elo_clan_2v2: int = Field(default=1200)

    # Game counts for K-factor calculation
    games_ranked_1v1: int = Field(default=0)
    games_ranked_2v2: int = Field(default=0)
    games_clan_1v1: int = Field(default=0)
    games_clan_2v2: int = Field(default=0)

    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)


class PlayerLevel(SQLModel, table=True):
    """
    Player Level - Rank and XP score for a player.

    Rank ranges from 1-87, with score representing XP points earned.
    """

    __tablename__ = "player_level"

    id: int | None = Field(default=None, primary_key=True)
    persona_id: int = Field(foreign_key="persona.id", unique=True, index=True)
    rank: int = Field(default=1)  # 1-87
    score: int = Field(default=0)  # XP points


class MatchReport(SQLModel, table=True):
    """
    Match Report - Individual match record from Competition service.

    Records game outcome data for statistics tracking.
    """

    __tablename__ = "match_report"

    id: int | None = Field(default=None, primary_key=True)
    csid: str = Field(index=True)  # Competition Session ID
    ccid: str = Field(index=True)  # Competition Channel ID (player identifier)
    persona_id: int = Field(foreign_key="persona.id", index=True)
    submitted_by: str = Field(default="")  # Who submitted this report

    # Match data
    result: int = Field(default=0)  # 0=Win, 1=Loss, 3=DC
    faction: str = Field(default="")  # Empire, Soviet, etc.
    duration: int = Field(default=0)  # Seconds
    gametype: int = Field(default=0)  # 0=Unranked, 1=Ranked1v1, 2=Ranked2v2, 3=Clan1v1, 4=Clan2v2
    map_name: str = Field(default="")

    created_at: datetime = Field(default_factory=datetime.utcnow)


class PlayerReportIntent(SQLModel, table=True):
    """Tracks player report intentions for match correlation."""

    __tablename__ = "player_report_intent"

    id: int | None = Field(default=None, primary_key=True)
    csid: str = Field(index=True)
    ccid: str = Field(index=True)
    persona_id: int = Field(foreign_key="persona.id", index=True)
    full_id: str = Field(default="")  # Player's full GUID from report
    reported: bool = Field(default=False)
    created_at: datetime = Field(default_factory=datetime.utcnow)


class CompetitionSession(SQLModel, table=True):
    """
    Competition Session - Match session tracking for Competition service.

    Created when a match starts and tracks the session state.
    """

    __tablename__ = "competition_session"

    id: int | None = Field(default=None, primary_key=True)
    csid: str = Field(unique=True, index=True)  # Competition Session ID
    ccid: str = Field(index=True)  # Competition Channel ID
    host_persona_id: int = Field(foreign_key="persona.id")
    status: str = Field(default="active")  # active, completed
    expected_players: int = Field(default=2)
    received_reports: int = Field(default=0)
    finalized: bool = Field(default=False)
    created_at: datetime = Field(default_factory=datetime.utcnow)


class AuthCertificate(SQLModel, table=True):
    """
    Auth Certificate - Certificate pool for RA3 authentication.

    Certificates are allocated from a pool and returned after use.
    Each certificate has a 180-second expiry.
    """

    __tablename__ = "auth_certificate"

    id: int | None = Field(default=None, primary_key=True)
    certificate_data: str = Field()  # Full certificate data
    server_data_10: str = Field(index=True)  # First 10 chars of ServerData for lookup
    in_use: bool = Field(default=False)
    persona_id: int | None = Field(default=None)
    assigned_at: datetime | None = Field(default=None)


# =============================================================================
# Clan Models
# =============================================================================


class Clan(SQLModel, table=True):
    """
    Clan - Represents a player clan/guild.

    Clans have a unique name and tag. Players can be members, applicants, or leaders.
    Position values: 0=applicant, 1=member, 7=leader
    """

    id: int | None = Field(default=None, primary_key=True)
    name: str = Field(unique=True, index=True, max_length=50)
    tag: str = Field(unique=True, index=True, max_length=10)
    description: str | None = Field(default=None, max_length=500)
    created_at: datetime = Field(default_factory=datetime.utcnow)

    # One-to-many relationship with ClanMembership
    members: list["ClanMembership"] = Relationship(back_populates="clan")


class ClanMembership(SQLModel, table=True):
    """
    Clan Membership - Links personas to clans with their position.

    Position values:
    - 0: Applicant (pending approval)
    - 1: Member (regular member)
    - 7: Leader (clan leader)

    A persona can only be in one clan at a time (unique persona_id).
    """

    __tablename__ = "clan_membership"

    id: int | None = Field(default=None, primary_key=True)
    clan_id: int = Field(foreign_key="clan.id", index=True)
    persona_id: int = Field(foreign_key="persona.id", index=True, unique=True)
    position: int = Field(default=0)  # 0=applicant, 1=member, 7=leader
    joined_at: datetime = Field(default_factory=datetime.utcnow)

    # Relationships
    clan: Clan | None = Relationship(back_populates="members")


# =============================================================================
# Web Session Models
# =============================================================================


class WebSession(SQLModel, table=True):
    """
    Web Session - Tracks web portal login sessions.

    Used for session-based authentication on the web portal.
    Sessions expire after 7 days by default.
    """

    __tablename__ = "web_session"

    id: int | None = Field(default=None, primary_key=True)
    session_token: str = Field(unique=True, index=True)
    user_id: int = Field(foreign_key="user.id", index=True)
    created_at: datetime = Field(default_factory=datetime.utcnow)
    expires_at: datetime = Field(default_factory=lambda: datetime.utcnow() + timedelta(days=7))
    is_active: bool = Field(default=True)
