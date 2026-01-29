"""
Clan Service - Endpoints for clan functionality.

These endpoints are called by the game to get clan info for players.
"""

import os
from datetime import datetime

from fastapi import APIRouter, Response

from app.db.crud import get_clan_by_id, get_persona_clan_membership, get_player_stats, parse_ticket
from app.db.database import create_session
from app.soap.models.clan import ClanInfoResponse, NotMemberResponse
from app.util.paths import get_base_path

clan_router = APIRouter()


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
                    stats = get_player_stats(session, persona_id)
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
