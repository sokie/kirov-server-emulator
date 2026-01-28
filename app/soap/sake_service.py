"""
Sake Storage Server - SOAP service for game statistics and configuration.

Endpoint: /SakeStorageServer/StorageServer.asmx

This service handles:
- GetMyRecords: Returns player's career stats (190 RecordValue elements for RA3)
- GetSpecificRecords: Returns table data (ScoringMultipliers, TickerMgmt)
- SearchForRecords: Search tables (Levels, NewsTicker, PlayerStats_v5, custom_maps)

The game relies on this service for displaying stats, ranks, and leaderboards.
"""

import base64
import xml.etree.ElementTree as ET

from fastapi import APIRouter, Request, Response
from sqlmodel import select

from app.db.crud import get_player_level, get_player_stats
from app.db.database import create_session
from app.models.models import Persona
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


def handle_get_my_records(login_ticket: str, profile_id: int, requested_fields: list[str]) -> GetMyRecordsResponse:
    """
    Handle GetMyRecords SOAP operation.

    Returns values for the requested fields.

    Args:
        login_ticket: The login ticket containing user/persona IDs.
        profile_id: The profile ID (fallback if ticket parsing fails).
        requested_fields: List of field names to return values for.

    Returns:
        GetMyRecordsResponse with record values.
    """
    # Validate and extract profile ID from login ticket
    user_id, ticket_profile_id = parse_login_ticket(login_ticket)
    if user_id == 0 or ticket_profile_id == 0:
        logger.warning("Sake GetMyRecords: Invalid login ticket")
        return GetMyRecordsResponse.error(SAKEResultCode.LOGIN_TICKET_INVALID)

    profile_id = ticket_profile_id

    logger.debug(
        "Sake GetMyRecords: profileId=%s, num_fields=%d, fields=%s",
        profile_id,
        len(requested_fields),
        requested_fields[:5] if requested_fields else [],
    )

    # If no fields requested, return empty values
    if not requested_fields:
        return GetMyRecordsResponse.success_empty()

    session = create_session()
    try:
        _stats = get_player_stats(session, profile_id)  # Reserved for future stat fields
        level = get_player_level(session, profile_id)

        # Build record values for each requested field (always return values, using defaults if needed)
        records = []
        for field in requested_fields:
            value = 0
            field_lower = field.lower()

            if field_lower == "score":
                value = level.score if level else 0
            elif field_lower == "rank":
                value = level.rank if level else 1
            # All other fields default to 0

            records.append(RecordValue.from_int(value))

        return GetMyRecordsResponse.success(records)
    finally:
        session.close()


def handle_get_specific_records(table_id: str, login_ticket: str) -> GetSpecificRecordsResponse:
    """
    Handle GetSpecificRecords SOAP operation.

    Returns table data like ScoringMultipliers.

    Args:
        table_id: The table identifier.
        login_ticket: The login ticket for authentication validation.

    Returns:
        GetSpecificRecordsResponse with record values.
    """
    # Validate login ticket
    user_id, profile_id = parse_login_ticket(login_ticket)
    if user_id == 0 or profile_id == 0:
        logger.warning("Sake GetSpecificRecords: Invalid login ticket")
        return GetSpecificRecordsResponse.error(SAKEResultCode.LOGIN_TICKET_INVALID)

    logger.debug("Sake GetSpecificRecords: tableid=%s", table_id)

    records = []

    if "ScoringMultipliers" in str(table_id) or table_id == "1":
        # Return scoring multipliers as short values
        for mult in SCORING_MULTIPLIERS:
            records.append(RecordValue.from_short(mult))
    elif "UnrankedLosses" in str(table_id):
        # Return [unrankedLosses, unrankedWins, rankedLosses, rankedWins] as shorts
        records = [
            RecordValue.from_short(0),  # UnrankedLosses
            RecordValue.from_short(0),  # UnrankedWins
            RecordValue.from_short(0),  # RankedLosses
            RecordValue.from_short(0),  # RankedWins
        ]

    if records:
        return GetSpecificRecordsResponse.success(records)
    else:
        return GetSpecificRecordsResponse.success_empty()


def handle_search_for_records(table_id: str, filter_str: str, login_ticket: str) -> SearchForRecordsResponse:
    """
    Handle SearchForRecords SOAP operation.

    Handles searches for:
    - Levels: XP thresholds for 87 ranks
    - NewsTicker: News/announcements
    - PlayerStats_v5: Leaderboard data
    - custom_maps: Custom map list

    Args:
        table_id: The table identifier.
        filter_str: The filter string for the search.
        login_ticket: The login ticket for authentication validation.

    Returns:
        SearchForRecordsResponse with search results.
    """
    # Validate login ticket
    user_id, profile_id = parse_login_ticket(login_ticket)
    if user_id == 0 or profile_id == 0:
        logger.warning("Sake SearchForRecords: Invalid login ticket")
        return SearchForRecordsResponse.error(SAKEResultCode.LOGIN_TICKET_INVALID)

    logger.debug("Sake SearchForRecords: tableid=%s, filter=%s", table_id, filter_str)

    record_lists: list[list[RecordValue]] = []

    # Handle Levels table - return XP thresholds
    if "Levels" in str(table_id) or "levels" in str(filter_str).lower():
        for threshold in LEVEL_THRESHOLDS:
            # Each level is a single-element ArrayOfRecordValue
            record_lists.append([RecordValue.from_int(threshold)])

    # Handle PlayerStats_v5 - leaderboard or ownerid lookup
    elif "PlayerStats" in str(table_id) or "playerstats" in str(filter_str).lower():
        if "ownerid=" in filter_str.lower():
            # Extract owner ID from filter
            filter_lower = filter_str.lower()
            owner_id_start = filter_lower.find("ownerid=") + len("ownerid=")
            owner_id_str = ""
            for char in filter_str[owner_id_start:]:
                if char.isdigit():
                    owner_id_str += char
                else:
                    break
            owner_id = int(owner_id_str) if owner_id_str else 0

            # Return single ArrayOfRecordValue with [rank, ownerId]
            record_lists.append(
                [
                    RecordValue.from_int(57),
                    RecordValue.from_int(owner_id),
                ]
            )
        else:
            # General leaderboard query
            session = create_session()
            try:
                stmt = select(Persona).limit(100)
                personas = session.exec(stmt).all()

                for persona in personas:
                    level = get_player_level(session, persona.id)
                    rank = level.rank if level else 1
                    score = level.score if level else 0

                    # Each player is an ArrayOfRecordValue with [profileId, rank, score]
                    record_lists.append(
                        [
                            RecordValue.from_int(persona.id),
                            RecordValue.from_int(rank),
                            RecordValue.from_int(score),
                        ]
                    )
            finally:
                session.close()

    # Handle NewsTicker
    elif "NewsTicker" in str(table_id) or "ticker" in str(filter_str).lower():
        # Return empty news ticker (can be expanded)
        pass

    # Handle custom_maps
    elif "custom_maps" in str(table_id) or "maps" in str(filter_str).lower():
        # Return empty custom maps list (can be expanded)
        pass

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

        if "GetMyRecords" in soap_action or operation_name == "GetMyRecords":
            login_ticket = get_element_text(operation, "loginTicket")
            profile_id_str = get_element_text(operation, "profileId")
            profile_id = int(profile_id_str) if profile_id_str else 0
            requested_fields = get_requested_fields(operation)

            response_model = handle_get_my_records(login_ticket, profile_id, requested_fields)
            response_xml = wrap_soap_envelope(response_model)

        elif "GetSpecificRecords" in soap_action or operation_name == "GetSpecificRecords":
            table_id = get_element_text(operation, "tableid")
            login_ticket = get_element_text(operation, "loginTicket")
            response_model = handle_get_specific_records(table_id, login_ticket)
            response_xml = wrap_soap_envelope(response_model)

        elif "SearchForRecords" in soap_action or operation_name == "SearchForRecords":
            table_id = get_element_text(operation, "tableid")
            filter_str = get_element_text(operation, "filter")
            login_ticket = get_element_text(operation, "loginTicket")
            response_model = handle_search_for_records(table_id, filter_str, login_ticket)
            response_xml = wrap_soap_envelope(response_model)

        else:
            # Return generic success for unknown operations
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
