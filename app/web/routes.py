import os
import re

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from sqlmodel import Session

from app.db.crud import get_leaderboard
from app.db.database import get_session
from app.servers.sessions import GameSessionRegistry
from app.util.paths import get_base_path

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
async def home_page(request: Request):
    """
    Render the home page.
    """
    return templates.TemplateResponse("index.html", {"request": request})


@router.get("/register", response_class=HTMLResponse)
async def register_page(request: Request):
    """
    Render the registration page.
    """
    return templates.TemplateResponse("register.html", {"request": request})


@router.get("/leaderboard", response_class=HTMLResponse)
async def leaderboard_page(
    request: Request,
    game_type: str = "ranked_1v1",
    session: Session = Depends(get_session),
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
            "players": players,
            "game_type": game_type,
            "game_types": GAME_TYPES,
        },
    )


@router.get("/matches", response_class=HTMLResponse)
async def matches_page(request: Request):
    """
    Render the current matches page.
    """
    matches = get_current_matches()

    return templates.TemplateResponse(
        "matches.html",
        {
            "request": request,
            "matches": matches,
            "total_matches": len(matches),
            "total_players": sum(m["num_players"] for m in matches),
        },
    )
