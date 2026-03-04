"""
Clan Service - Endpoints for clan functionality and game-specific rank/ladder services.

These endpoints are called by the game to get clan info, rank icons, and ladder ratings.
Covers RA3, Kane's Wrath (KW), and Tiberium Wars (TW).
"""

import os
from datetime import datetime

from fastapi import APIRouter, Response

from app.db.crud import (
    get_clan_by_id,
    get_persona_clan_membership,
    get_player_level,
    get_player_stats,
    parse_ticket,
)
from app.db.database import create_session
from app.models.game_config import GAME_ID_KW, GAME_ID_RA, GAME_ID_TW
from app.models.models import PlayerStats
from app.soap.models.clan import ClanInfoResponse, NotMemberResponse
from app.util.logging_helper import get_logger
from app.util.paths import get_base_path

logger = get_logger(__name__)

clan_router = APIRouter()


def _load_fixed_ladder_csv(filename: str) -> str:
    """Load fixed ladder entries from a CSV data file."""
    path = os.path.join(get_base_path(), "static", filename)
    with open(path) as f:
        # Join all lines into a single comma-separated string
        entries = [line.strip() for line in f if line.strip()]
    return ",".join(entries)


# Load fixed ladder data at module level
_KW_FIXED_LADDER = _load_fixed_ladder_csv("kw_ladder_fixed.csv")
_TW_FIXED_LADDER = _load_fixed_ladder_csv("tw_ladder_fixed.csv")


def _get_faction_prefix(stats: PlayerStats | None) -> str:
    """Determine faction prefix for KW/TW rank icons based on most-played faction."""
    if stats is None:
        return "BLK"
    # Use allied/soviet/japan stats as proxy for GDI/NOD/SCR
    # (these are the fields we have; KW/TW faction tracking is a future task)
    games_gdi = (
        getattr(stats, "wins_allied_ranked_1v1", 0)
        + getattr(stats, "losses_allied_ranked_1v1", 0)
        + getattr(stats, "wins_allied_ranked_2v2", 0)
        + getattr(stats, "losses_allied_ranked_2v2", 0)
    )
    games_nod = (
        getattr(stats, "wins_soviet_ranked_1v1", 0)
        + getattr(stats, "losses_soviet_ranked_1v1", 0)
        + getattr(stats, "wins_soviet_ranked_2v2", 0)
        + getattr(stats, "losses_soviet_ranked_2v2", 0)
    )
    games_scr = (
        getattr(stats, "wins_japan_ranked_1v1", 0)
        + getattr(stats, "losses_japan_ranked_1v1", 0)
        + getattr(stats, "wins_japan_ranked_2v2", 0)
        + getattr(stats, "losses_japan_ranked_2v2", 0)
    )

    if games_gdi == 0 and games_nod == 0 and games_scr == 0:
        return "BLK"

    # Match PHP reference priority: SCR > NOD > GDI > BLK
    prefix = "BLK"
    if games_gdi > games_nod and games_gdi > games_scr:
        prefix = "GDI"
    if games_scr > games_nod and games_scr > games_gdi:
        prefix = "SCR"
    elif games_nod > games_scr and games_nod > games_gdi:
        prefix = "NOD"
    return prefix


def _resolve_rank_icon(game_id: int, pid: int = 0, gp: str = "", ro: int = 0, size: str = "") -> bytes:
    """Resolve and return rank icon PNG data for KW or TW."""
    icon_base = "kw_icons" if game_id == GAME_ID_KW else "tw_icons"
    base_path = get_base_path()

    # Determine persona_id
    persona_id = pid
    if not persona_id and gp:
        ticket_data = parse_ticket(gp)
        if ticket_data:
            _, persona_id, _ = ticket_data

    # Get player stats for faction prefix
    stats = None
    rank = 0
    if persona_id > 0:
        session = create_session()
        try:
            stats = get_player_stats(session, persona_id, game_id=game_id)
            level = get_player_level(session, persona_id, game_id=game_id)
            if level:
                rank = level.rank
        finally:
            session.close()

    # Override rank if ro is provided
    if ro > 0:
        rank = min(ro, 87)

    prefix = _get_faction_prefix(stats)
    subdir = "IconsLarge" if size == "L" else "Icons"
    icon_name = f"{prefix}{rank}.png"
    icon_path = os.path.join(base_path, "static", icon_base, subdir, icon_name)

    # Fallback to BLK0.png
    if not os.path.exists(icon_path):
        icon_path = os.path.join(base_path, "static", icon_base, subdir, "BLK0.png")

    try:
        with open(icon_path, "rb") as f:
            return f.read()
    except FileNotFoundError:
        logger.warning("Rank icon not found: %s", icon_path)
        return b""


def _get_elo_for_ladder(game_id: int, gp: str) -> tuple[int, int]:
    """Get 1v1 and 2v2 ELO for ladder ratings."""
    elo_1v1 = 1200
    elo_2v2 = 1200
    if gp:
        ticket_data = parse_ticket(gp)
        if ticket_data:
            _, persona_id, _ = ticket_data
            if persona_id > 0:
                session = create_session()
                try:
                    stats = get_player_stats(session, persona_id, game_id=game_id)
                    if stats:
                        elo_1v1 = stats.elo_ranked_1v1
                        elo_2v2 = stats.elo_ranked_2v2
                finally:
                    session.close()
    return elo_1v1, elo_2v2


def format_asof_timestamp() -> str:
    """Format the current time as the asof timestamp string."""
    now = datetime.utcnow()
    return now.strftime("%-m/%-d/%Y %-I:%M:%S %p")


@clan_router.get("/clans/ClanActions.asmx/ClanInfoByProfileID")
async def clan_info_by_profile_id(authToken: str = "", profileid: int = 0):
    """Returns clan info for a profile."""
    response_model = NotMemberResponse.create()

    if profileid > 0:
        session = create_session()
        try:
            membership = get_persona_clan_membership(session, profileid)
            if membership and membership.position >= 1:
                clan = get_clan_by_id(session, membership.clan_id)
                if clan:
                    response_model = ClanInfoResponse.for_member(
                        clan_id=clan.id,
                        clan_tag=clan.tag,
                        clan_name=clan.name,
                        member_id=membership.id,
                        member_rank=membership.position,
                        asof=format_asof_timestamp(),
                    )
        finally:
            session.close()

    response_xml = '<?xml version="1.0" encoding="utf-8"?>\n' + response_model.to_xml(encoding="unicode")
    return Response(content=response_xml, media_type="text/xml; charset=utf-8")


@clan_router.get("/GetPlayerLadderRatings.aspx")
async def get_player_ladder_ratings(gp: str = ""):
    """Returns ladder ratings for a player in CSV format."""
    default_rank = -1
    elo_1v1 = 1200

    if gp:
        ticket_data = parse_ticket(gp)
        if ticket_data:
            _, persona_id, _ = ticket_data
            if persona_id > 0:
                session = create_session()
                try:
                    stats = get_player_stats(session, persona_id, game_id=GAME_ID_RA)
                    if stats:
                        elo_1v1 = stats.elo_ranked_1v1
                finally:
                    session.close()

    ratings = [
        "72587,1,-1,-1",
        "72743,1,-1,-1",
        "75643,1,-1,-1",
        "75677,1,-1,-1",
        "75679,1,-1,-1",
        "75680,1,-1,-1",
        "75681,1,-1,-1",
        "75682,1,-1,-1",
        "75683,1,-1,-1",
        "75684,1,-1,-1",
        "75685,1,-1,-1",
        "75686,1,-1,-1",
        f"58938,32034,{default_rank},{elo_1v1}",
        f"58940,1088,{default_rank},{elo_1v1}",
    ]

    return Response(content=",".join(ratings) + ",", media_type="text/html")


@clan_router.get("/GetPlayerRankIcon.aspx")
async def get_player_rank_icon(gp: str = "", pid: int = 0, size: str = ""):
    """Returns the rank icon for a player as a PNG image."""
    image_name = "rank_icon_large.png" if size == "L" else "rank_icon_small.png"
    image_path = os.path.join(get_base_path(), "static", "images", image_name)

    with open(image_path, "rb") as f:
        image_data = f.read()

    return Response(
        content=image_data,
        media_type="image/png",
        headers={"Content-Length": str(len(image_data))},
    )


# =============================================================================
# Kane's Wrath (KW) Endpoints
# =============================================================================


@clan_router.get("/KWServices/KWGetPlayerLadderRatings.aspx")
async def kw_get_player_ladder_ratings(gp: str = ""):
    """Returns KW ladder ratings for a player in CSV format."""
    default_rank = -1
    elo_1v1, elo_2v2 = _get_elo_for_ladder(GAME_ID_KW, gp)

    dynamic = f"52177,15359,{default_rank},{elo_1v1},52178,6882,{default_rank},{elo_2v2}"
    content = f"{dynamic},{_KW_FIXED_LADDER},"
    return Response(content=content, media_type="text/html")


@clan_router.get("/KWServices/KWGetPlayerRankIcon.aspx")
async def kw_get_player_rank_icon(gp: str = "", pid: int = 0, ro: int = 0, size: str = ""):
    """Returns the KW rank icon for a player as a PNG image."""
    image_data = _resolve_rank_icon(GAME_ID_KW, pid=pid, gp=gp, ro=ro, size=size)
    if not image_data:
        return Response(status_code=404)
    return Response(
        content=image_data,
        media_type="image/png",
        headers={"Content-Length": str(len(image_data))},
    )


# =============================================================================
# Tiberium Wars (TW) Endpoints
# =============================================================================


@clan_router.get("/CC3Services/GetPlayerLadderRatings.aspx")
async def tw_get_player_ladder_ratings(gp: str = ""):
    """Returns TW ladder ratings for a player in CSV format."""
    default_rank = -1
    elo_1v1, elo_2v2 = _get_elo_for_ladder(GAME_ID_TW, gp)

    # TW format: fixed entries first, then dynamic 1v1/2v2, then rest of fixed
    # The 8 pre-dynamic entries are at the start of _TW_FIXED_LADDER
    dynamic = f"43738,31146,{default_rank},{elo_1v1},43783,33248,{default_rank},{elo_2v2}"
    content = f"{dynamic},{_TW_FIXED_LADDER},"
    return Response(content=content, media_type="text/html")


@clan_router.get("/CC3Services/GetPlayerRankIcon.aspx")
async def tw_get_player_rank_icon(gp: str = "", pid: int = 0, ro: int = 0, size: str = ""):
    """Returns the TW rank icon for a player as a PNG image."""
    image_data = _resolve_rank_icon(GAME_ID_TW, pid=pid, gp=gp, ro=ro, size=size)
    if not image_data:
        return Response(status_code=404)
    return Response(
        content=image_data,
        media_type="image/png",
        headers={"Content-Length": str(len(image_data))},
    )
