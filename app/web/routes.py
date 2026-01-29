import os
import re

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlmodel import Session

from app.db.crud import (
    get_all_clans,
    get_clan_by_id,
    get_clan_leader,
    get_clan_member_count,
    get_clan_members,
    get_leaderboard,
    get_persona_by_id,
    get_persona_clan,
    get_persona_clan_membership,
    get_personas_for_user,
)
from app.db.database import get_session
from app.models.models import User
from app.servers.sessions import GameSessionRegistry
from app.util.paths import get_base_path
from app.web.auth import (
    SESSION_COOKIE_NAME,
    clear_session_cookie,
    get_current_user_optional,
    invalidate_web_session,
)

router = APIRouter(tags=["Web"])

templates = Jinja2Templates(directory=os.path.join(get_base_path(), "templates"))

GAME_TYPES = ["ranked_1v1", "ranked_2v2", "clan_1v1", "clan_2v2"]


def parse_map_name(map_path: str) -> str:
    """Extract friendly map name from map path."""
    if not map_path:
        return "Unknown Map"
    # Extract map name from path like "data/maps/official/map_mp_2_feasel4/map_mp_2_feasel4.map"
    match = re.search(r"/([^/]+)\.map$", map_path)
    if match:
        raw_name = match.group(1)
        # Clean up the name
        # Remove prefixes like "map_mp_2_", "camp_s01_"
        clean_name = re.sub(r"^(map_mp_\d+_|camp_[a-z]\d+_)", "", raw_name)
        # Replace underscores with spaces and title case
        clean_name = clean_name.replace("_", " ").title()
        return clean_name
    return map_path


def parse_game_mode(fields: dict) -> dict:
    """Parse game mode info from heartbeat fields."""
    gamemode = fields.get("gamemode", "unknown")
    rules = fields.get("rules", "")
    map_path = fields.get("mapname", "")

    # Determine game status
    if gamemode == "openstaging":
        status = "Lobby"
        status_color = "warning"
    elif gamemode == "closedplaying":
        status = "In Progress"
        status_color = "success"
    elif gamemode == "closedstaging":
        status = "Starting"
        status_color = "info"
    else:
        status = gamemode.title()
        status_color = "secondary"

    # Determine game type from rules or map path
    # rules format: "type 100 10000 0 1 10 0 1 0 -1 0 -1 -1 1 "
    # First number seems to be: 0=unranked/custom, 1=ranked 1v1, 2=ranked 2v2, 3=coop
    game_type = "Custom"
    game_type_icon = "controller"

    if "camp_" in map_path.lower():
        game_type = "Co-op Campaign"
        game_type_icon = "people"
    elif rules:
        rules_parts = rules.strip().split()
        if rules_parts:
            try:
                type_num = int(rules_parts[0])
                if type_num == 0:
                    game_type = "Unranked"
                    game_type_icon = "controller"
                elif type_num == 1:
                    game_type = "Ranked 1v1"
                    game_type_icon = "trophy"
                elif type_num == 2:
                    game_type = "Ranked 2v2"
                    game_type_icon = "trophy"
                elif type_num == 3:
                    game_type = "Clan 1v1"
                    game_type_icon = "shield"
                elif type_num == 4:
                    game_type = "Clan 2v2"
                    game_type_icon = "shield"
            except (ValueError, IndexError):
                pass

    return {
        "status": status,
        "status_color": status_color,
        "game_type": game_type,
        "game_type_icon": game_type_icon,
    }


def get_current_matches() -> list[dict]:
    """Get list of current matches from GameSessionRegistry."""
    registry = GameSessionRegistry.get_instance()
    games = registry.get_games()

    matches = []
    for game in games:
        fields = game.fields
        mode_info = parse_game_mode(fields)

        # Get players from UDP heartbeat player data
        players = []
        player_data = fields.get("_players", [])
        for p in player_data:
            # Use 'name' or 'player' field for display name
            name = p.get("name") or p.get("player") or ""
            if name:
                players.append(
                    {
                        "name": name,
                        "pid": p.get("pid", ""),
                        "faction": p.get("faction", ""),
                        "wins": p.get("wins", "0"),
                        "losses": p.get("losses", "0"),
                    }
                )

        match = {
            "hostname": fields.get("hostname", "Unknown"),
            "map_name": parse_map_name(fields.get("mapname", "")),
            "map_path": fields.get("mapname", ""),
            "num_players": int(fields.get("numplayers", 0)),
            "max_players": int(fields.get("maxplayers", 0)),
            "num_required": int(fields.get("numRPlyr", 0)),
            "max_required": int(fields.get("maxRPlyr", 0)),
            "num_observers": int(fields.get("numObs", 0)),
            "has_password": fields.get("pw", "0") == "1",
            "observers_allowed": fields.get("obs", "0") == "1",
            "version": fields.get("vCRC", ""),
            "mod": fields.get("mod", "RA3"),
            "mod_version": fields.get("modv", ""),
            "host_ip": game.public_ip,
            "host_port": game.public_port,
            "local_ip": fields.get("localip0", ""),
            "players": players,
            **mode_info,
        }
        matches.append(match)

    return matches


@router.get("/", response_class=HTMLResponse)
async def home_page(
    request: Request,
    user: User | None = Depends(get_current_user_optional),
):
    """
    Render the home page.
    """
    return templates.TemplateResponse("index.html", {"request": request, "user": user})


@router.get("/register", response_class=HTMLResponse)
async def register_page(
    request: Request,
    user: User | None = Depends(get_current_user_optional),
):
    """
    Render the registration page.
    """
    return templates.TemplateResponse("register.html", {"request": request, "user": user})


@router.get("/login", response_class=HTMLResponse)
async def login_page(
    request: Request,
    user: User | None = Depends(get_current_user_optional),
):
    """
    Render the login page.
    """
    # Redirect if already logged in
    if user:
        return RedirectResponse(url="/", status_code=302)
    return templates.TemplateResponse("login.html", {"request": request, "user": user})


@router.get("/logout")
async def logout_page(
    request: Request,
    session: Session = Depends(get_session),
):
    """
    Handle logout and redirect to home.
    """
    session_token = request.cookies.get(SESSION_COOKIE_NAME)
    if session_token:
        invalidate_web_session(session, session_token)

    response = RedirectResponse(url="/", status_code=302)
    clear_session_cookie(response)
    return response


@router.get("/leaderboard", response_class=HTMLResponse)
async def leaderboard_page(
    request: Request,
    game_type: str = "ranked_1v1",
    session: Session = Depends(get_session),
    user: User | None = Depends(get_current_user_optional),
):
    """
    Render the leaderboard page with player statistics.
    """
    # Validate game type
    if game_type not in GAME_TYPES:
        game_type = "ranked_1v1"

    players = get_leaderboard(session, game_type)

    return templates.TemplateResponse(
        "leaderboard.html",
        {
            "request": request,
            "user": user,
            "players": players,
            "game_type": game_type,
            "game_types": GAME_TYPES,
        },
    )


@router.get("/matches", response_class=HTMLResponse)
async def matches_page(
    request: Request,
    user: User | None = Depends(get_current_user_optional),
):
    """
    Render the current matches page.
    """
    matches = get_current_matches()

    return templates.TemplateResponse(
        "matches.html",
        {
            "request": request,
            "user": user,
            "matches": matches,
            "total_matches": len(matches),
            "total_players": sum(m["num_players"] for m in matches),
        },
    )


# =============================================================================
# Clan Web Routes
# =============================================================================


@router.get("/clans", response_class=HTMLResponse)
async def clans_page(
    request: Request,
    session: Session = Depends(get_session),
    user: User | None = Depends(get_current_user_optional),
):
    """
    Render the clans list page.
    """
    clans = get_all_clans(session)

    # Build clan data with leader names and member counts
    clan_data = []
    for clan in clans:
        leader = get_clan_leader(session, clan.id)
        clan_data.append(
            {
                "id": clan.id,
                "name": clan.name,
                "tag": clan.tag,
                "description": clan.description,
                "member_count": get_clan_member_count(session, clan.id),
                "leader_name": leader.name if leader else None,
            }
        )

    # Check if user can create a clan (has personas not in clans)
    can_create_clan = False
    if user:
        personas = get_personas_for_user(session, user.id)
        for persona in personas:
            if not get_persona_clan(session, persona.id):
                can_create_clan = True
                break

    return templates.TemplateResponse(
        "clans.html",
        {
            "request": request,
            "user": user,
            "clans": clan_data,
            "can_create_clan": can_create_clan,
        },
    )


@router.get("/clans/create", response_class=HTMLResponse)
async def clan_create_page(
    request: Request,
    session: Session = Depends(get_session),
    user: User | None = Depends(get_current_user_optional),
):
    """
    Render the clan creation page.
    """
    # Require login
    if not user:
        return RedirectResponse(url="/login", status_code=302)

    # Get personas that aren't in a clan
    personas = get_personas_for_user(session, user.id)
    available_personas = []
    for persona in personas:
        if not get_persona_clan(session, persona.id):
            available_personas.append(persona)

    # If no available personas, redirect to clans page
    if not available_personas:
        return RedirectResponse(url="/clans", status_code=302)

    return templates.TemplateResponse(
        "clan_create.html",
        {
            "request": request,
            "user": user,
            "personas": available_personas,
        },
    )


@router.get("/clans/{clan_id}", response_class=HTMLResponse)
async def clan_detail_page(
    request: Request,
    clan_id: int,
    session: Session = Depends(get_session),
    user: User | None = Depends(get_current_user_optional),
):
    """
    Render the clan detail page.
    """
    clan = get_clan_by_id(session, clan_id)
    if not clan:
        return RedirectResponse(url="/clans", status_code=302)

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

    # Sort members: leader first, then by name
    members.sort(key=lambda x: (-x["position"], x["name"]))

    # Check if current user is the leader
    is_leader = False
    user_membership = None
    personas = []

    if user:
        user_personas = get_personas_for_user(session, user.id)
        personas = [p for p in user_personas if not get_persona_clan(session, p.id)]

        for p in user_personas:
            membership = get_persona_clan_membership(session, p.id)
            if membership:
                if membership.clan_id == clan.id:
                    user_membership = {
                        "persona_id": p.id,
                        "clan_id": membership.clan_id,
                        "position": membership.position,
                    }
                    if membership.position == 7:
                        is_leader = True
                else:
                    # User has a persona in a different clan
                    user_membership = {
                        "persona_id": p.id,
                        "clan_id": membership.clan_id,
                        "position": membership.position,
                    }

    return templates.TemplateResponse(
        "clan_detail.html",
        {
            "request": request,
            "user": user,
            "clan": {
                "id": clan.id,
                "name": clan.name,
                "tag": clan.tag,
                "description": clan.description,
            },
            "leader": {"name": leader.name} if leader else None,
            "members": members,
            "applicants": applicants,
            "is_leader": is_leader,
            "user_membership": user_membership,
            "personas": personas,
        },
    )
