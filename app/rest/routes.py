from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from pydantic import BaseModel
from sqlmodel import Session

from app.db.crud import (
    approve_clan_applicant,
    create_clan,
    create_new_user,
    get_all_clans,
    get_clan_by_id,
    get_clan_by_name,
    get_clan_by_tag,
    get_clan_leader,
    get_clan_member_count,
    get_clan_members,
    get_persona_by_id,
    get_personas_for_user,
    get_user_by_username,
    join_clan_as_applicant,
    kick_from_clan,
    leave_clan,
    promote_to_leader,
    reject_clan_applicant,
)
from app.db.database import get_session
from app.models.models import UserCreate, UserLogin, UserPublic
from app.security import verify_password
from app.web.auth import (
    SESSION_COOKIE_NAME,
    clear_session_cookie,
    create_web_session,
    get_current_user_optional,
    invalidate_web_session,
    set_session_cookie,
)

# The router prefix will be /api/rest, so these endpoints will be
# /api/rest/users/register and /api/rest/users/login
router = APIRouter(prefix="/users", tags=["Users"])


@router.post("/register", response_model=UserPublic, status_code=status.HTTP_201_CREATED)
async def register_new_user(user_in: UserCreate, session: Session = Depends(get_session)):
    """
    Register a new user, now storing them in the SQLite database.
    """
    existing_user = get_user_by_username(session=session, username=user_in.username)
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username already registered.",
        )

    created_user = create_new_user(session=session, user_create=user_in)
    return created_user


@router.post("/login")
async def login_for_access(user_in: UserLogin, session: Session = Depends(get_session)):
    """
    Authenticate a user against the database.
    """
    user = get_user_by_username(session=session, username=user_in.username)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found.",
        )

    if not verify_password(user_in.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return {"message": f"Login successful for user: {user.username}"}


@router.get("/items")
async def read_items():
    return [{"name": "Item Foo"}, {"name": "Item Bar"}]


@router.get("/items/{item_id}")
async def read_item(item_id: int):
    return {"item_id": item_id, "name": f"Item {item_id}"}


@router.post("/web-login")
async def web_login(
    user_in: UserLogin,
    response: Response,
    session: Session = Depends(get_session),
):
    """
    Login for web portal. Sets a session cookie.
    """
    user = get_user_by_username(session=session, username=user_in.username)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found.",
        )

    if not verify_password(user_in.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password.",
        )

    # Create web session
    web_session = create_web_session(session, user.id)
    set_session_cookie(response, web_session.session_token)

    return {"message": "Login successful", "username": user.username}


@router.post("/web-logout")
async def web_logout(
    request: Request,
    response: Response,
    session: Session = Depends(get_session),
):
    """
    Logout from web portal. Clears the session cookie.
    """
    session_token = request.cookies.get(SESSION_COOKIE_NAME)
    if session_token:
        invalidate_web_session(session, session_token)
    clear_session_cookie(response)
    return {"message": "Logged out successfully"}


# =============================================================================
# Clan API Endpoints
# =============================================================================

clans_api_router = APIRouter(prefix="/clans", tags=["Clans"])


class ClanCreate(BaseModel):
    name: str
    tag: str
    description: str | None = None
    leader_persona_id: int


class ClanResponse(BaseModel):
    id: int
    name: str
    tag: str
    description: str | None
    member_count: int
    leader_name: str | None


class ClanDetailResponse(ClanResponse):
    members: list[dict]
    applicants: list[dict]


@clans_api_router.get("")
async def list_clans(
    session: Session = Depends(get_session),
    limit: int = 100,
    offset: int = 0,
):
    """
    List all clans with basic info.
    """
    clans = get_all_clans(session, limit=limit, offset=offset)
    result = []
    for clan in clans:
        leader = get_clan_leader(session, clan.id)
        result.append(
            ClanResponse(
                id=clan.id,
                name=clan.name,
                tag=clan.tag,
                description=clan.description,
                member_count=get_clan_member_count(session, clan.id),
                leader_name=leader.name if leader else None,
            )
        )
    return result


@clans_api_router.get("/{clan_id}")
async def get_clan(
    clan_id: int,
    session: Session = Depends(get_session),
):
    """
    Get detailed clan information.
    """
    clan = get_clan_by_id(session, clan_id)
    if not clan:
        raise HTTPException(status_code=404, detail="Clan not found")

    leader = get_clan_leader(session, clan.id)
    memberships = get_clan_members(session, clan.id)

    members = []
    applicants = []
    for m in memberships:
        persona = get_persona_by_id(session, m.persona_id)
        info = {
            "persona_id": m.persona_id,
            "name": persona.name if persona else "Unknown",
            "position": m.position,
            "joined_at": m.joined_at.isoformat(),
        }
        if m.position >= 1:
            members.append(info)
        else:
            applicants.append(info)

    return {
        "id": clan.id,
        "name": clan.name,
        "tag": clan.tag,
        "description": clan.description,
        "member_count": len(members),
        "leader_name": leader.name if leader else None,
        "members": members,
        "applicants": applicants,
    }


@clans_api_router.post("", status_code=status.HTTP_201_CREATED)
async def create_new_clan(
    clan_in: ClanCreate,
    request: Request,
    session: Session = Depends(get_session),
):
    """
    Create a new clan. Requires authentication.
    """
    # Check authentication
    user = await get_current_user_optional(request, session)
    if not user:
        raise HTTPException(status_code=401, detail="Authentication required")

    # Verify the persona belongs to the user
    personas = get_personas_for_user(session, user.id)
    persona_ids = [p.id for p in personas]
    if clan_in.leader_persona_id not in persona_ids:
        raise HTTPException(status_code=403, detail="Persona does not belong to user")

    # Check for duplicate name or tag
    if get_clan_by_name(session, clan_in.name):
        raise HTTPException(status_code=400, detail="Clan name already taken")
    if get_clan_by_tag(session, clan_in.tag):
        raise HTTPException(status_code=400, detail="Clan tag already taken")

    try:
        clan = create_clan(
            session,
            name=clan_in.name,
            tag=clan_in.tag,
            leader_persona_id=clan_in.leader_persona_id,
            description=clan_in.description,
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from None

    return {"id": clan.id, "name": clan.name, "tag": clan.tag}


@clans_api_router.post("/{clan_id}/join")
async def join_clan(
    clan_id: int,
    request: Request,
    persona_id: int,
    session: Session = Depends(get_session),
):
    """
    Request to join a clan as an applicant.
    """
    user = await get_current_user_optional(request, session)
    if not user:
        raise HTTPException(status_code=401, detail="Authentication required")

    # Verify persona belongs to user
    personas = get_personas_for_user(session, user.id)
    persona_ids = [p.id for p in personas]
    if persona_id not in persona_ids:
        raise HTTPException(status_code=403, detail="Persona does not belong to user")

    clan = get_clan_by_id(session, clan_id)
    if not clan:
        raise HTTPException(status_code=404, detail="Clan not found")

    try:
        join_clan_as_applicant(session, clan_id, persona_id)
        return {"message": "Application submitted", "status": "pending"}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from None


@clans_api_router.post("/{clan_id}/approve/{persona_id}")
async def approve_applicant(
    clan_id: int,
    persona_id: int,
    request: Request,
    session: Session = Depends(get_session),
):
    """
    Approve a clan applicant. Only the clan leader can do this.
    """
    user = await get_current_user_optional(request, session)
    if not user:
        raise HTTPException(status_code=401, detail="Authentication required")

    # Verify user is the clan leader
    leader = get_clan_leader(session, clan_id)
    if not leader:
        raise HTTPException(status_code=404, detail="Clan not found")

    user_personas = get_personas_for_user(session, user.id)
    if leader.id not in [p.id for p in user_personas]:
        raise HTTPException(status_code=403, detail="Only the clan leader can approve applicants")

    membership = approve_clan_applicant(session, clan_id, persona_id)
    if not membership:
        raise HTTPException(status_code=404, detail="Applicant not found")

    return {"message": "Applicant approved"}


@clans_api_router.post("/{clan_id}/reject/{persona_id}")
async def reject_applicant(
    clan_id: int,
    persona_id: int,
    request: Request,
    session: Session = Depends(get_session),
):
    """
    Reject a clan applicant. Only the clan leader can do this.
    """
    user = await get_current_user_optional(request, session)
    if not user:
        raise HTTPException(status_code=401, detail="Authentication required")

    # Verify user is the clan leader
    leader = get_clan_leader(session, clan_id)
    if not leader:
        raise HTTPException(status_code=404, detail="Clan not found")

    user_personas = get_personas_for_user(session, user.id)
    if leader.id not in [p.id for p in user_personas]:
        raise HTTPException(status_code=403, detail="Only the clan leader can reject applicants")

    success = reject_clan_applicant(session, clan_id, persona_id)
    if not success:
        raise HTTPException(status_code=404, detail="Applicant not found")

    return {"message": "Applicant rejected"}


@clans_api_router.post("/leave")
async def leave_clan_endpoint(
    request: Request,
    persona_id: int,
    session: Session = Depends(get_session),
):
    """
    Leave a clan. Leaders cannot leave without transferring leadership.
    """
    user = await get_current_user_optional(request, session)
    if not user:
        raise HTTPException(status_code=401, detail="Authentication required")

    # Verify persona belongs to user
    personas = get_personas_for_user(session, user.id)
    persona_ids = [p.id for p in personas]
    if persona_id not in persona_ids:
        raise HTTPException(status_code=403, detail="Persona does not belong to user")

    try:
        success = leave_clan(session, persona_id)
        if not success:
            raise HTTPException(status_code=404, detail="Not in a clan")
        return {"message": "Left clan successfully"}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from None


@clans_api_router.post("/{clan_id}/kick/{persona_id}")
async def kick_member(
    clan_id: int,
    persona_id: int,
    request: Request,
    session: Session = Depends(get_session),
):
    """
    Kick a member from the clan. Only the clan leader can do this.
    """
    user = await get_current_user_optional(request, session)
    if not user:
        raise HTTPException(status_code=401, detail="Authentication required")

    # Verify user is the clan leader
    leader = get_clan_leader(session, clan_id)
    if not leader:
        raise HTTPException(status_code=404, detail="Clan not found")

    user_personas = get_personas_for_user(session, user.id)
    if leader.id not in [p.id for p in user_personas]:
        raise HTTPException(status_code=403, detail="Only the clan leader can kick members")

    success = kick_from_clan(session, clan_id, persona_id)
    if not success:
        raise HTTPException(status_code=404, detail="Member not found or is the leader")

    return {"message": "Member kicked"}


@clans_api_router.post("/{clan_id}/promote/{persona_id}")
async def promote_member(
    clan_id: int,
    persona_id: int,
    request: Request,
    session: Session = Depends(get_session),
):
    """
    Transfer leadership to another member. Only the clan leader can do this.
    """
    user = await get_current_user_optional(request, session)
    if not user:
        raise HTTPException(status_code=401, detail="Authentication required")

    # Verify user is the clan leader
    leader = get_clan_leader(session, clan_id)
    if not leader:
        raise HTTPException(status_code=404, detail="Clan not found")

    user_personas = get_personas_for_user(session, user.id)
    if leader.id not in [p.id for p in user_personas]:
        raise HTTPException(status_code=403, detail="Only the clan leader can transfer leadership")

    success = promote_to_leader(session, clan_id, leader.id, persona_id)
    if not success:
        raise HTTPException(status_code=404, detail="Member not found or cannot be promoted")

    return {"message": "Leadership transferred"}
