"""
Sake Storage Server - SOAP service for game statistics and configuration.

Endpoint: /SakeStorageServer/StorageServer.asmx

This service handles:
- GetMyRecords: Returns player's career stats (game-specific positional layout)
- GetSpecificRecords: Returns table data (ScoringMultipliers, TickerMgmt)
- SearchForRecords: Search tables (Levels, NewsTicker, PlayerStats, RatingPlayer, custom_maps)

Supports RA3 (game ID 2128), Kane's Wrath (1814), and Tiberium Wars (1422).
"""

import base64
import xml.etree.ElementTree as ET

from fastapi import APIRouter, Request, Response
from sqlmodel import select

from app.db.crud import get_player_level, get_player_stats
from app.db.database import create_session
from app.models.models import Persona, PlayerStats
from app.soap.envelope import (
    create_soap_fault,
    extract_soap_body,
    get_element_text,
    get_operation_name,
    wrap_soap_envelope,
)
from app.soap.models.common import RecordValue
from app.soap.models.sake import (
    GetMyRecordsResponse,
    GetSpecificRecordsResponse,
    SAKEResultCode,
    SearchForRecordsResponse,
)
from app.util.logging_helper import get_logger

logger = get_logger(__name__)

sake_router = APIRouter()

# Namespace definitions
SAKE_NS = "http://gamespy.net/sake"

# Game ID constants
GAME_ID_KW = 1814
GAME_ID_TW = 1422
GAME_ID_RA = 2128

# XP thresholds for 87 ranks (Levels table)
LEVEL_THRESHOLDS = [
    0,
    5,
    13,
    23,
    35,
    50,
    67,
    86,
    106,
    127,
    150,
    175,
    202,
    231,
    262,
    295,
    330,
    367,
    406,
    447,
    490,
    535,
    582,
    631,
    682,
    735,
    790,
    847,
    906,
    967,
    1030,
    1095,
    1162,
    1231,
    1302,
    1375,
    1454,
    1538,
    1628,
    1724,
    1825,
    1927,
    2030,
    2134,
    2239,
    2345,
    2452,
    2560,
    2674,
    2794,
    2920,
    3049,
    3180,
    3314,
    3451,
    3590,
    3738,
    3894,
    4058,
    4230,
    4410,
    4595,
    4784,
    4978,
    5177,
    5380,
    5590,
    5807,
    6031,
    6262,
    6500,
    6744,
    6993,
    7247,
    7506,
    7770,
    8044,
    8328,
    8622,
    8926,
    9240,
    9562,
    9890,
    10224,
    10564,
    10910,
    11310,
]

# Scoring multipliers (fixed values)
SCORING_MULTIPLIERS = [1, 2, 2, 5]

# News ticker messages shown in-game
NEWS_TICKER_MESSAGES = [
    "Welcome to the server! Enjoy your games.",
]

# Custom maps static data
CUSTOM_MAPS_DATA = [8389, -972957748, 66624219, 0, 0, 0, 66624239, 0, 66624260]


def parse_login_ticket(login_ticket: str) -> tuple[int, int]:
    """
    Parse the login ticket to extract user_id and persona_id.

    The ticket format is: base64(user_id|persona_id|token)

    Returns:
        Tuple of (user_id, persona_id).
    """
    try:
        decoded = base64.b64decode(login_ticket).decode("utf-8")
        parts = decoded.split("|")
        if len(parts) >= 2:
            user_id = int(parts[0])
            persona_id = int(parts[1])
            return user_id, persona_id
    except Exception as e:
        logger.warning("Failed to parse login ticket: %s", e)
    return 0, 0


def get_requested_fields(operation: ET.Element) -> list[str]:
    """Extract the list of requested field names from the SOAP request."""
    fields = []
    for child in operation:
        child_tag = child.tag.split("}")[-1] if "}" in child.tag else child.tag
        if child_tag == "fields":
            for field_elem in child:
                field_tag = field_elem.tag.split("}")[-1] if "}" in field_elem.tag else field_elem.tag
                if field_tag == "string" and field_elem.text:
                    fields.append(field_elem.text)
    return fields


# =============================================================================
# Game-specific career stats builders
# =============================================================================


def _get_mode_values(stats: PlayerStats | None, attr_prefix: str) -> list:
    """Get values for all 5 game modes from a PlayerStats object."""
    if stats is None:
        return [0, 0, 0, 0, 0]
    return [
        getattr(stats, f"{attr_prefix}_unranked", 0),
        getattr(stats, f"{attr_prefix}_ranked_1v1", 0),
        getattr(stats, f"{attr_prefix}_ranked_2v2", 0),
        getattr(stats, f"{attr_prefix}_clan_1v1", 0),
        getattr(stats, f"{attr_prefix}_clan_2v2", 0),
    ]


def _build_kw_career_stats(stats: PlayerStats | None) -> list[RecordValue]:
    """
    Build 420-element KW career stats array.

    Layout matches reference getmyrecordskw.php with 6-element groups
    (5 modes + total) for each stat category.
    """
    wins = _get_mode_values(stats, "wins")
    losses = _get_mode_values(stats, "losses")
    disconnects = _get_mode_values(stats, "disconnects")
    desyncs = _get_mode_values(stats, "desyncs")
    avg_gl = _get_mode_values(stats, "avg_game_length")
    win_ratio = _get_mode_values(stats, "win_ratio")

    total_matches = [w + loss + d + ds for w, loss, d, ds in zip(wins, losses, disconnects, desyncs)]
    total_all_online = sum(total_matches)

    records: list[RecordValue] = []

    # [0-23] 24 int(0) padding
    records.extend([RecordValue.from_int(0)] * 24)

    # [24-29] TotalMatches per mode + total
    for tm in total_matches:
        records.append(RecordValue.from_int(tm))
    records.append(RecordValue.from_int(total_all_online))

    # [30-101] 72 int(0) padding
    records.extend([RecordValue.from_int(0)] * 72)

    # [102-107] Career Losses per mode + total
    for val in losses:
        records.append(RecordValue.from_int(val))
    records.append(RecordValue.from_int(sum(losses)))

    # [108-179] 72 int(0) padding
    records.extend([RecordValue.from_int(0)] * 72)

    # [180-185] Career Wins per mode + total
    for val in wins:
        records.append(RecordValue.from_int(val))
    records.append(RecordValue.from_int(sum(wins)))

    # [186-257] 72 int(0) padding
    records.extend([RecordValue.from_int(0)] * 72)

    # [258-263] Win/Loss Ratio per mode + total (float)
    for val in win_ratio:
        records.append(RecordValue.from_float(float(val)))
    records.append(RecordValue.from_float(float(sum(win_ratio))))

    # [264-335] 72 float(0) padding
    records.extend([RecordValue.from_float(0.0)] * 72)

    # [336-341] Average Game Length per mode + average
    for val in avg_gl:
        records.append(RecordValue.from_int(val))
    # Average of non-zero avg game lengths (or first value like reference)
    non_zero = [a for a in avg_gl if a > 0]
    avg_of_avg = sum(non_zero) // len(non_zero) if non_zero else 0
    records.append(RecordValue.from_int(avg_of_avg))

    # [342-347] 6 int(0) - Total time played (not tracked)
    records.extend([RecordValue.from_int(0)] * 6)

    # [348-389] 42 int(0) padding
    records.extend([RecordValue.from_int(0)] * 42)

    # [390-395] 6 float(0) - Unit KDR (not tracked)
    records.extend([RecordValue.from_float(0.0)] * 6)

    # [396-401] 6 int(0) - CareerInputCommands (not tracked)
    records.extend([RecordValue.from_int(0)] * 6)

    # [402-407] 6 int(0) - Avg CareerInputCommands (not tracked)
    records.extend([RecordValue.from_int(0)] * 6)

    # [408-413] Disconnects per mode + total
    for val in disconnects:
        records.append(RecordValue.from_int(val))
    records.append(RecordValue.from_int(sum(disconnects)))

    # [414-419] Desyncs per mode + total
    for val in desyncs:
        records.append(RecordValue.from_int(val))
    records.append(RecordValue.from_int(sum(desyncs)))

    return records


def _build_tw_career_stats(stats: PlayerStats | None) -> list[RecordValue]:
    """
    Build 160-element TW career stats array.

    Layout matches reference getmyrecordstw.php with 5-element groups
    (5 modes, no totals) for each stat category.
    """
    wins = _get_mode_values(stats, "wins")
    losses = _get_mode_values(stats, "losses")
    disconnects = _get_mode_values(stats, "disconnects")
    desyncs = _get_mode_values(stats, "desyncs")
    avg_gl = _get_mode_values(stats, "avg_game_length")
    win_ratio = _get_mode_values(stats, "win_ratio")

    total_matches = [w + loss + d + ds for w, loss, d, ds in zip(wins, losses, disconnects, desyncs)]

    records: list[RecordValue] = []

    # [0-19] 20 int(0) padding
    records.extend([RecordValue.from_int(0)] * 20)

    # [20-24] TotalMatches per mode
    for tm in total_matches:
        records.append(RecordValue.from_int(tm))

    # [25-39] 15 int(0) padding
    records.extend([RecordValue.from_int(0)] * 15)

    # [40-44] Career Losses per mode
    for val in losses:
        records.append(RecordValue.from_int(val))

    # [45-59] 15 int(0) padding
    records.extend([RecordValue.from_int(0)] * 15)

    # [60-64] Career Wins per mode
    for val in wins:
        records.append(RecordValue.from_int(val))

    # [65-79] 15 int(0) padding
    records.extend([RecordValue.from_int(0)] * 15)

    # [80-84] Win/Loss Ratio per mode (float)
    for val in win_ratio:
        records.append(RecordValue.from_float(float(val)))

    # [85-99] 15 float(0) padding
    records.extend([RecordValue.from_float(0.0)] * 15)

    # [100-104] Average Game Length per mode
    for val in avg_gl:
        records.append(RecordValue.from_int(val))

    # [105-144] 40 int(0) padding
    records.extend([RecordValue.from_int(0)] * 40)

    # [145-149] 5 float(0) padding
    records.extend([RecordValue.from_float(0.0)] * 5)

    # [150-154] Disconnects per mode
    for val in disconnects:
        records.append(RecordValue.from_int(val))

    # [155-159] Desyncs per mode
    for val in desyncs:
        records.append(RecordValue.from_int(val))

    return records


def _build_ra_career_stats(stats: PlayerStats | None) -> list[RecordValue]:
    """
    Build 190-element RA3 career stats array.

    Same as TW through position 149, then 30 RA-specific int(0) padding,
    then disconnects and desyncs.
    """
    wins = _get_mode_values(stats, "wins")
    losses = _get_mode_values(stats, "losses")
    disconnects = _get_mode_values(stats, "disconnects")
    desyncs = _get_mode_values(stats, "desyncs")
    avg_gl = _get_mode_values(stats, "avg_game_length")
    win_ratio = _get_mode_values(stats, "win_ratio")

    total_matches = [w + loss + d + ds for w, loss, d, ds in zip(wins, losses, disconnects, desyncs)]

    records: list[RecordValue] = []

    # [0-19] 20 int(0) padding
    records.extend([RecordValue.from_int(0)] * 20)

    # [20-24] TotalMatches per mode
    for tm in total_matches:
        records.append(RecordValue.from_int(tm))

    # [25-39] 15 int(0) padding
    records.extend([RecordValue.from_int(0)] * 15)

    # [40-44] Career Losses per mode
    for val in losses:
        records.append(RecordValue.from_int(val))

    # [45-59] 15 int(0) padding
    records.extend([RecordValue.from_int(0)] * 15)

    # [60-64] Career Wins per mode
    for val in wins:
        records.append(RecordValue.from_int(val))

    # [65-79] 15 int(0) padding
    records.extend([RecordValue.from_int(0)] * 15)

    # [80-84] Win/Loss Ratio per mode (float)
    for val in win_ratio:
        records.append(RecordValue.from_float(float(val)))

    # [85-99] 15 float(0) padding
    records.extend([RecordValue.from_float(0.0)] * 15)

    # [100-104] Average Game Length per mode
    for val in avg_gl:
        records.append(RecordValue.from_int(val))

    # [105-144] 40 int(0) padding
    records.extend([RecordValue.from_int(0)] * 40)

    # [145-149] 5 float(0) padding
    records.extend([RecordValue.from_float(0.0)] * 5)

    # [150-179] 30 int(0) - RA-specific extra padding
    records.extend([RecordValue.from_int(0)] * 30)

    # [180-184] Disconnects per mode
    for val in disconnects:
        records.append(RecordValue.from_int(val))

    # [185-189] Desyncs per mode
    for val in desyncs:
        records.append(RecordValue.from_int(val))

    return records


# =============================================================================
# SOAP operation handlers
# =============================================================================


def handle_get_my_records(
    login_ticket: str,
    profile_id: int,
    requested_fields: list[str],
    game_id: int = GAME_ID_RA,
) -> GetMyRecordsResponse:
    """
    Handle GetMyRecords SOAP operation.

    For small requests (<=10 fields): returns field-based values (score, rank).
    For large requests (>10 fields): returns game-specific positional career stats.
    """
    user_id, ticket_profile_id = parse_login_ticket(login_ticket)
    if user_id == 0 or ticket_profile_id == 0:
        logger.warning("Sake GetMyRecords: Invalid login ticket")
        return GetMyRecordsResponse.error(SAKEResultCode.LOGIN_TICKET_INVALID)

    profile_id = ticket_profile_id

    logger.debug(
        "Sake GetMyRecords: profileId=%s, game_id=%s, num_fields=%d",
        profile_id,
        game_id,
        len(requested_fields),
    )

    if not requested_fields:
        return GetMyRecordsResponse.success_empty()

    session = create_session()
    try:
        # Large request = full positional career stats
        if len(requested_fields) > 10:
            stats = get_player_stats(session, profile_id)

            if game_id == GAME_ID_KW:
                records = _build_kw_career_stats(stats)
            elif game_id == GAME_ID_TW:
                records = _build_tw_career_stats(stats)
            else:
                records = _build_ra_career_stats(stats)

            return GetMyRecordsResponse.success(records)

        # Small request = field-name based (score/rank)
        level = get_player_level(session, profile_id)

        records = []
        for field in requested_fields:
            value = 0
            field_lower = field.lower()

            if field_lower == "score":
                value = level.score if level else 0
            elif field_lower == "rank":
                value = level.rank if level else 1

            records.append(RecordValue.from_int(value))

        return GetMyRecordsResponse.success(records)
    finally:
        session.close()


def handle_get_specific_records(
    table_id: str,
    login_ticket: str,
    game_id: int = GAME_ID_RA,
) -> GetSpecificRecordsResponse:
    """
    Handle GetSpecificRecords SOAP operation.

    Returns table data like ScoringMultipliers and TickerMgmt.
    """
    user_id, profile_id = parse_login_ticket(login_ticket)
    if user_id == 0 or profile_id == 0:
        logger.warning("Sake GetSpecificRecords: Invalid login ticket")
        return GetSpecificRecordsResponse.error(SAKEResultCode.LOGIN_TICKET_INVALID)

    logger.debug("Sake GetSpecificRecords: tableid=%s, game_id=%s", table_id, game_id)

    records = []

    if "ScoringMultipliers" in str(table_id) or table_id == "1":
        for mult in SCORING_MULTIPLIERS:
            records.append(RecordValue.from_short(mult))

    elif "UnrankedLosses" in str(table_id):
        records = [
            RecordValue.from_short(0),
            RecordValue.from_short(0),
            RecordValue.from_short(0),
            RecordValue.from_short(0),
        ]

    elif "TickerMgmt" in str(table_id):
        # Ticker management config: float(30), short(10), float(50), float(25), float(25)
        records = [
            RecordValue.from_float(30.0),
            RecordValue.from_short(10),
            RecordValue.from_float(50.0),
            RecordValue.from_float(25.0),
            RecordValue.from_float(25.0),
        ]

    if records:
        return GetSpecificRecordsResponse.success(records)
    else:
        return GetSpecificRecordsResponse.success_empty()


def handle_search_for_records(
    table_id: str,
    filter_str: str,
    login_ticket: str,
    game_id: int = GAME_ID_RA,
) -> SearchForRecordsResponse:
    """
    Handle SearchForRecords SOAP operation.

    Handles searches for Levels, NewsTicker, PlayerStats, RatingPlayer, and custom_maps.
    """
    user_id, profile_id = parse_login_ticket(login_ticket)
    if user_id == 0 or profile_id == 0:
        logger.warning("Sake SearchForRecords: Invalid login ticket")
        return SearchForRecordsResponse.error(SAKEResultCode.LOGIN_TICKET_INVALID)

    logger.debug("Sake SearchForRecords: tableid=%s, filter=%s, game_id=%s", table_id, filter_str, game_id)

    record_lists: list[list[RecordValue]] = []

    # Handle Levels table - return XP thresholds
    if "Levels" in str(table_id) or "levels" in str(filter_str).lower():
        for threshold in LEVEL_THRESHOLDS:
            record_lists.append([RecordValue.from_int(threshold)])

    # Handle PlayerStats - leaderboard or ownerid lookup
    elif "PlayerStats" in str(table_id) or "playerstats" in str(filter_str).lower():
        if "ownerid=" in filter_str.lower():
            filter_lower = filter_str.lower()
            owner_id_start = filter_lower.find("ownerid=") + len("ownerid=")
            owner_id_str = ""
            for char in filter_str[owner_id_start:]:
                if char.isdigit():
                    owner_id_str += char
                else:
                    break
            owner_id = int(owner_id_str) if owner_id_str else 0

            record_lists.append(
                [
                    RecordValue.from_int(57),
                    RecordValue.from_int(owner_id),
                ]
            )
        else:
            session = create_session()
            try:
                stmt = select(Persona).limit(100)
                personas = session.exec(stmt).all()

                for persona in personas:
                    level = get_player_level(session, persona.id)
                    rank = level.rank if level else 1
                    score = level.score if level else 0

                    record_lists.append(
                        [
                            RecordValue.from_int(persona.id),
                            RecordValue.from_int(rank),
                            RecordValue.from_int(score),
                        ]
                    )
            finally:
                session.close()

    # Handle NewsTicker - return news messages
    elif "NewsTicker" in str(table_id) or "ticker" in str(filter_str).lower():
        for msg in NEWS_TICKER_MESSAGES:
            record_lists.append(
                [
                    RecordValue.from_unicode_string(msg),
                    RecordValue.from_int(0),
                    RecordValue.from_short(1),
                ]
            )

    # Handle RatingPlayer - return player rating data
    elif "RatingPlayer" in str(table_id):
        record_lists.append(
            [
                RecordValue.from_ascii_string(""),
                RecordValue.from_int(profile_id),
                RecordValue.from_int(0),
                RecordValue.from_int(0),
            ]
        )

    # Handle custom_maps - return static map data
    elif "custom_maps" in str(table_id) or "maps" in str(filter_str).lower():
        record_lists.append([RecordValue.from_int(v) for v in CUSTOM_MAPS_DATA])

    if record_lists:
        return SearchForRecordsResponse.success(record_lists)
    else:
        return SearchForRecordsResponse.success_empty()


@sake_router.post("/SakeStorageServer/StorageServer.asmx")
async def sake_storage_handler(request: Request) -> Response:
    """
    Main handler for Sake Storage Server SOAP requests.

    Routes requests based on SOAPAction header.
    """
    try:
        soap_action = request.headers.get("SOAPAction", "").strip('"')
        logger.debug("Sake: SOAPAction=%s", soap_action)

        body = await request.body()
        xml_content = body.decode("utf-8")
        logger.debug("Sake: Request body=%s", xml_content[:500])

        operation = extract_soap_body(xml_content)
        operation_name = get_operation_name(operation)
        logger.debug("Sake: Operation=%s", operation_name)

        # Extract game ID from request
        game_id_str = get_element_text(operation, "gameid")
        game_id = int(game_id_str) if game_id_str else GAME_ID_RA

        if "GetMyRecords" in soap_action or operation_name == "GetMyRecords":
            login_ticket = get_element_text(operation, "loginTicket")
            profile_id_str = get_element_text(operation, "profileId")
            profile_id = int(profile_id_str) if profile_id_str else 0
            requested_fields = get_requested_fields(operation)

            response_model = handle_get_my_records(login_ticket, profile_id, requested_fields, game_id)
            response_xml = wrap_soap_envelope(response_model)

        elif "GetSpecificRecords" in soap_action or operation_name == "GetSpecificRecords":
            table_id = get_element_text(operation, "tableid")
            login_ticket = get_element_text(operation, "loginTicket")
            response_model = handle_get_specific_records(table_id, login_ticket, game_id)
            response_xml = wrap_soap_envelope(response_model)

        elif "SearchForRecords" in soap_action or operation_name == "SearchForRecords":
            table_id = get_element_text(operation, "tableid")
            filter_str = get_element_text(operation, "filter")
            login_ticket = get_element_text(operation, "loginTicket")
            response_model = handle_search_for_records(table_id, filter_str, login_ticket, game_id)
            response_xml = wrap_soap_envelope(response_model)

        else:
            response_model = GetMyRecordsResponse(result="Success")
            response_xml = wrap_soap_envelope(response_model)

        logger.debug("Sake: Response=%s", response_xml[:500])

        return Response(
            content=response_xml,
            media_type="text/xml; charset=utf-8",
        )

    except Exception as e:
        logger.exception("Sake: Error processing request: %s", e)
        fault_xml = create_soap_fault(str(e))
        return Response(
            content=fault_xml,
            media_type="text/xml; charset=utf-8",
            status_code=500,
        )
