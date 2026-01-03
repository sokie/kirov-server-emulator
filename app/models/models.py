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
