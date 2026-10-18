"""
Sake Storage Server - SOAP service for game statistics and configuration.

Endpoint: /SakeStorageServer/StorageServer.asmx

This service handles:
- GetMyRecords: returns the player's career stats
- GetSpecificRecords: returns table data (ScoringMultipliers, TickerMgmt)
- SearchForRecords: searches tables (Levels, NewsTicker, PlayerStats, RatingMatch, RatingPlayer, custom_maps)
- CreateRecord: stores the RatingMatch and RatingPlayer records that Tiberium Wars and Kane's Wrath create

Supports RA3 (game ID 2128), Kane's Wrath (1814), and Tiberium Wars (1422).
"""

import base64
import xml.etree.ElementTree as ET

from fastapi import APIRouter, Request, Response
from sqlmodel import Session

from app.db.database import create_session
from app.models import cnc3_stats
from app.models.game_config import GAME_ID_RA
from app.soap import cnc3_sake, ra3_sake, sake_records
from app.soap.envelope import (
    create_soap_fault,
    extract_soap_body,
    get_element_text,
    get_operation_name,
    wrap_soap_envelope,
)
from app.soap.models.sake import (
    CreateRecordResponse,
    GetMyRecordsResponse,
    GetSpecificRecordsResponse,
    SAKEResultCode,
    SearchForRecordsResponse,
)
from app.soap.sake_filter import FilterError
from app.soap.sake_records import Record
from app.util.logging_helper import get_logger

logger = get_logger(__name__)

sake_router = APIRouter()

# Namespace definitions
SAKE_NS = "http://gamespy.net/sake"

# Fixed records that the games read. They are answered like the records that the games create.
NEWS_TICKER_MESSAGES = [
    "Welcome to Kirov server! Enjoy your games.",
]
SEED_RECORDS: dict[str, list[Record]] = {
    "newsticker": [
        {
            "recordid": ("intValue", record_id),
            "tickertext": ("unicodeStringValue", message),
            "imagefileid": ("intValue", 0),
            "tickertype": ("shortValue", 1),
            "matchid": ("asciiStringValue", "-1"),
        }
        for record_id, message in enumerate(NEWS_TICKER_MESSAGES, start=1)
    ],
    "tickermgmt": [
        {
            "recordid": ("intValue", 1),
            "displayrateinsec": ("floatValue", 30.0),
            "maxitemstodownload": ("shortValue", 10),
            "adpercentage": ("floatValue", 50.0),
            "cmpercentage": ("floatValue", 25.0),
            "bgpercentage": ("floatValue", 25.0),
        }
    ],
    "custom_maps": [
        {
            "recordid": ("intValue", 8389),
            "mapcrc": ("intValue", -972957748),
            "mappreviewfileid": ("intValue", 66624219),
            "mapinifileid": ("intValue", 0),
            "stringfilefileid": ("intValue", 0),
            "readmefileid": ("intValue", 0),
            "mapartfileid": ("intValue", 66624239),
            "mappicfileid": ("intValue", 0),
            "mapfileid": ("intValue", 66624260),
        }
    ],
}


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


def _tag(element: ET.Element) -> str:
    """Returns the tag of an element without its XML namespace."""
    return element.tag.split("}")[-1]


def get_requested_fields(operation: ET.Element) -> list[str]:
    """Extract the list of requested field names from the SOAP request."""
    fields = []
    for child in operation:
        if _tag(child) == "fields":
            for field_elem in child:
                if _tag(field_elem) == "string" and field_elem.text:
                    fields.append(field_elem.text)
    return fields


def get_int_list(operation: ET.Element, container: str) -> list[int]:
    """Extract the <int> values under a container element, such as recordids or ownerids."""
    for child in operation:
        if _tag(child) == container:
            values = []
            for item in child:
                if _tag(item) == "int" and item.text and item.text.strip().lstrip("-").isdigit():
                    values.append(int(item.text))
            return values
    return []


def _int_text(text: str, default: int) -> int:
    try:
        return int(text)
    except (TypeError, ValueError):
        return default


def get_record_fields(operation: ET.Element) -> list[tuple[str, str, str]]:
    """Returns (name, Sake value type, text) for every RecordField in the request's values."""
    fields = []
    for child in operation:
        if _tag(child) != "values":
            continue
        for record_field in child:
            name = get_element_text(record_field, "name")
            for element in record_field:
                # <value><intValue><value>3</value></intValue></value>
                if name and _tag(element) == "value" and len(element) > 0:
                    typed_value = element[0]
                    fields.append((name, _tag(typed_value), get_element_text(typed_value, "value")))
    return fields


# =============================================================================
# SOAP operation handlers
# =============================================================================


def _records(session: Session, game_id: int, table: str) -> list[Record]:
    """Returns the fixed records of a table, followed by the records the game created."""
    return SEED_RECORDS.get(table.lower(), []) + sake_records.stored_records(session, game_id, table)


def handle_get_my_records(
    login_ticket: str,
    profile_id: int,
    requested_fields: list[str],
    game_id: int = GAME_ID_RA,
    table_id: str = "",
) -> GetMyRecordsResponse:
    """Handle the GetMyRecords SOAP operation: returns the player's stats record."""
    user_id, ticket_profile_id = parse_login_ticket(login_ticket)
    if user_id == 0 or ticket_profile_id == 0:
        logger.warning("Sake GetMyRecords: Invalid login ticket")
        return GetMyRecordsResponse.error(SAKEResultCode.LOGIN_TICKET_INVALID)

    profile_id = ticket_profile_id
    logger.debug("Sake GetMyRecords: profileId=%s, game_id=%s, fields=%d", profile_id, game_id, len(requested_fields))
    if not requested_fields:
        return GetMyRecordsResponse.success_empty()

    game = cnc3_stats.GAMES.get(game_id)
    session = create_session()
    try:
        if game_id == GAME_ID_RA:
            records = ra3_sake.get_my_records(session, profile_id, table_id or "PlayerStats_v5", requested_fields)
        elif game is not None:
            records = cnc3_sake.get_my_records(session, game, profile_id, table_id or game.sake_table, requested_fields)
        else:
            records = None
    finally:
        session.close()
    if records is None:
        logger.info("Sake GetMyRecords: no stats table %r for game %s", table_id, game_id)
        return GetMyRecordsResponse.success_empty()
    return GetMyRecordsResponse.success(records)


def handle_get_specific_records(
    table_id: str,
    login_ticket: str,
    game_id: int = GAME_ID_RA,
    requested_fields: list[str] | None = None,
    record_ids: list[int] | None = None,
) -> GetSpecificRecordsResponse:
    """Handle the GetSpecificRecords SOAP operation: returns the asked records."""
    user_id, profile_id = parse_login_ticket(login_ticket)
    if user_id == 0 or profile_id == 0:
        logger.warning("Sake GetSpecificRecords: Invalid login ticket")
        return GetSpecificRecordsResponse.error(SAKEResultCode.LOGIN_TICKET_INVALID)

    logger.debug("Sake GetSpecificRecords: tableid=%s, game_id=%s", table_id, game_id)
    fields = requested_fields or []
    ids = record_ids or []
    if not fields:
        return GetSpecificRecordsResponse.success_empty()

    if game_id == GAME_ID_RA:
        rows = ra3_sake.get_specific_records(table_id, ids, fields)
    elif game_id in cnc3_stats.GAMES:
        rows = cnc3_sake.get_specific_records(table_id, ids, fields)
    else:
        rows = None
    if rows is None:
        session = create_session()
        try:
            rows = sake_records.specific_records(_records(session, game_id, table_id), ids, fields)
        finally:
            session.close()
    return GetSpecificRecordsResponse.success(rows[0]) if rows else GetSpecificRecordsResponse.success_empty()


def handle_search_for_records(
    table_id: str,
    filter_str: str,
    login_ticket: str,
    game_id: int = GAME_ID_RA,
    search: dict | None = None,
) -> SearchForRecordsResponse:
    """Handle the SearchForRecords SOAP operation.

    `search` holds the request's fields, sort, offset, max, surrounding, ownerids and targetRecordFilter.
    """
    user_id, profile_id = parse_login_ticket(login_ticket)
    if user_id == 0 or profile_id == 0:
        logger.warning("Sake SearchForRecords: Invalid login ticket")
        return SearchForRecordsResponse.error(SAKEResultCode.LOGIN_TICKET_INVALID)

    logger.debug("Sake SearchForRecords: tableid=%s, filter=%s, game_id=%s", table_id, filter_str, game_id)
    search = search or {}
    fields = search.get("fields", [])
    params = {
        "filter_text": filter_str,
        "sort": search.get("sort", ""),
        "offset": search.get("offset", 0),
        "max_rows": search.get("max", 1),
        "surrounding": search.get("surrounding", 0),
        "owner_ids": search.get("ownerids", []),
        "target_filter": search.get("targetRecordFilter", ""),
    }
    game = cnc3_stats.GAMES.get(game_id)
    session = create_session()
    try:
        if game_id == GAME_ID_RA and ra3_sake.handles(table_id):
            rows = ra3_sake.search(session, table_id, fields, **params)
        elif game is not None and cnc3_sake.handles(game, table_id):
            rows = cnc3_sake.search(session, game, table_id, fields, **params)
        else:
            rows = sake_records.search_records(_records(session, game_id, table_id), fields, **params)
    except FilterError as e:
        logger.warning("Sake SearchForRecords: unreadable filter %r (%s); returning no records", filter_str, e)
        rows = []
    finally:
        session.close()
    return SearchForRecordsResponse.success(rows) if rows else SearchForRecordsResponse.success_empty()


def handle_create_record(
    table_id: str, login_ticket: str, game_id: int, values: list[tuple[str, str, str]]
) -> CreateRecordResponse:
    """Handle the CreateRecord SOAP operation: stores the record and returns its id."""
    user_id, profile_id = parse_login_ticket(login_ticket)
    if user_id == 0 or profile_id == 0:
        logger.warning("Sake CreateRecord: Invalid login ticket")
        return CreateRecordResponse.error(SAKEResultCode.LOGIN_TICKET_INVALID)

    session = create_session()
    try:
        record_id = sake_records.create_record(session, game_id, profile_id, table_id, values)
        session.commit()
    finally:
        session.close()
    logger.info("Sake CreateRecord: %s record %d from persona %d (game %s)", table_id, record_id, profile_id, game_id)
    return CreateRecordResponse.success(record_id)


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
            table_id = get_element_text(operation, "tableid")

            response_model = handle_get_my_records(
                login_ticket, profile_id, requested_fields, game_id, table_id=table_id
            )
            response_xml = wrap_soap_envelope(response_model)

        elif "GetSpecificRecords" in soap_action or operation_name == "GetSpecificRecords":
            table_id = get_element_text(operation, "tableid")
            login_ticket = get_element_text(operation, "loginTicket")
            response_model = handle_get_specific_records(
                table_id,
                login_ticket,
                game_id,
                requested_fields=get_requested_fields(operation),
                record_ids=get_int_list(operation, "recordids"),
            )
            response_xml = wrap_soap_envelope(response_model)

        elif "SearchForRecords" in soap_action or operation_name == "SearchForRecords":
            table_id = get_element_text(operation, "tableid")
            filter_str = get_element_text(operation, "filter")
            login_ticket = get_element_text(operation, "loginTicket")
            search = {
                "fields": get_requested_fields(operation),
                "sort": get_element_text(operation, "sort"),
                "offset": _int_text(get_element_text(operation, "offset"), 0),
                "max": _int_text(get_element_text(operation, "max"), 1),
                "surrounding": _int_text(get_element_text(operation, "surrounding"), 0),
                "ownerids": get_int_list(operation, "ownerids"),
                "targetRecordFilter": get_element_text(operation, "targetRecordFilter"),
            }
            response_model = handle_search_for_records(table_id, filter_str, login_ticket, game_id, search=search)
            response_xml = wrap_soap_envelope(response_model)

        elif "CreateRecord" in soap_action or operation_name == "CreateRecord":
            response_model = handle_create_record(
                get_element_text(operation, "tableid"),
                get_element_text(operation, "loginTicket"),
                game_id,
                get_record_fields(operation),
            )
            response_xml = wrap_soap_envelope(response_model)

        else:
            # The games send no UpdateRecord, DeleteRecord, RateRecord or GetRecordLimit.
            raise ValueError(f"Unsupported Sake operation {operation_name}")

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
