"""
Competition SOAP Service - Match session and report handling.

Endpoint: /competitionservice/competitionservice.asmx

This service handles:
- CreateSession: Creates a match session, returns csid/ccid
- SetReportIntention: Signals that a player will submit a report
- SubmitReport: Submits match report binary data

The game uses this service to track match results for ranked games.
"""

import gzip
import json
import os
import uuid
from datetime import datetime

from fastapi import APIRouter, Request, Response

from app.db.crud import (
    complete_competition_session,
    create_competition_session,
    finalize_match,
    get_competition_session,
    increment_received_reports,
    mark_report_intent_reported,
    set_report_intention,
    submit_match_report,
)
from app.db.database import create_session
from app.models.match_report import MatchReport
from app.soap.envelope import (
    create_soap_fault,
    extract_soap_body,
    get_child_element,
    get_element_text,
    get_operation_name,
    wrap_soap_envelope,
)
from app.soap.models.competition import (
    CreateSessionResponse,
    SetReportIntentionResponse,
    SubmitReportResponse,
)
from app.util.logging_helper import get_logger

logger = get_logger(__name__)

competition_router = APIRouter()

# Namespace definitions
COMP_NS = "http://gamespy.net/competition/"


def extract_profile_id_from_certificate(operation: any) -> int:
    """
    Extract profileid from the certificate element in the operation.

    The game sends profileid inside a nested certificate element:
    <SetReportIntention>
        <certificate>
            <profileid>12345</profileid>
            ...
        </certificate>
        ...
    </SetReportIntention>

    Args:
        operation: The parsed XML operation element.

    Returns:
        The profile ID, or 0 if not found.
    """
    cert_element = get_child_element(operation, "certificate")
    if cert_element is not None:
        profile_id_str = get_element_text(cert_element, "profileid")
        if profile_id_str:
            return int(profile_id_str)
    return 0


# Directory to save match reports
REPORT_DIR = os.path.join(os.getcwd(), "Report")


def save_match_report(csid: str, ccid: str, raw_report: bytes, report: MatchReport | None) -> None:
    """
    Save match report to files (binary and parsed JSON).

    Args:
        csid: Competition Session ID (match ID).
        ccid: Competition Channel ID (player ID).
        raw_report: Raw binary report data.
        report: Parsed MatchReport object, or None if parsing failed.
    """
    try:
        os.makedirs(REPORT_DIR, exist_ok=True)

        # Generate timestamp for unique filenames
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

        # Use ccid if available, otherwise use profileid placeholder
        player_id = ccid if ccid else "unknown"

        # Save raw binary report
        bin_filename = f"Report_{csid}_{player_id}_{timestamp}.bin"
        bin_path = os.path.join(REPORT_DIR, bin_filename)
        with open(bin_path, "wb") as f:
            f.write(raw_report)
        logger.info("Saved raw report to %s (%d bytes)", bin_path, len(raw_report))

        # Save parsed report as JSON
        if report:
            json_filename = f"Report_{csid}_{player_id}_{timestamp}.json"
            json_path = os.path.join(REPORT_DIR, json_filename)
            player_list = report.get_player_list()
            report_dict = {
                "save_time": datetime.now().isoformat(),
                "csid": csid,
                "ccid": ccid,
                "protocol_version": report.protocol_version,
                "developer_version": report.developer_version,
                "game_status": report.game_status,
                "flags": report.flags,
                "player_count": report.player_count,
                "team_count": report.team_count,
                "map_path": report.get_map_path(),
                "replay_guid": report.get_replay_guid(),
                "game_type": report.get_game_type(),
                "is_auto_match": report.is_auto_match,
                "is_final_report": len(player_list) > 1,
                "players": [
                    {
                        "full_id": p.full_id,
                        "persona_id": p.persona_id,
                        "faction": p.faction,
                        "is_winner": p.is_winner,
                    }
                    for p in player_list
                ],
                "winner_ids": report.get_winner_id_list(),
                "loser_ids": report.get_loser_id_list(),
            }
            with open(json_path, "w") as f:
                json.dump(report_dict, f, indent=2)
            logger.info("Saved parsed report to %s", json_path)

    except Exception as e:
        logger.warning("Error saving report: %s", e)


def handle_create_session(profile_id: int) -> CreateSessionResponse:
    """
    Handle CreateSession SOAP operation.

    Creates a new match session and returns csid and ccid.

    Args:
        profile_id: The profile ID creating the session.

    Returns:
        CreateSessionResponse with session IDs.
    """
    logger.debug("Competition CreateSession: profileId=%s", profile_id)

    session = create_session()
    try:
        comp_session = create_competition_session(session, profile_id)
        logger.debug(
            "Competition: Created session csid=%s, ccid=%s",
            comp_session.csid,
            comp_session.ccid,
        )
        return CreateSessionResponse.success(
            csid=comp_session.csid,
            ccid=comp_session.ccid,
        )
    finally:
        session.close()


def handle_set_report_intention(csid: str, ccid: str, profile_id: int) -> SetReportIntentionResponse:
    """
    Handle SetReportIntention SOAP operation.

    Signals that a player intends to submit a match report.
    Creates a PlayerReportIntent record and generates a unique ccid for this player.

    Args:
        csid: Competition Session ID.
        ccid: Competition Channel ID (from request).
        profile_id: The profile ID setting the intention.

    Returns:
        SetReportIntentionResponse confirming the intention with the player's ccid.
    """
    logger.debug(
        "Competition SetReportIntention: csid=%s, ccid=%s, profileId=%s",
        csid,
        ccid,
        profile_id,
    )

    session = create_session()
    try:
        intent = set_report_intention(session, csid, ccid, profile_id)
        if intent:
            logger.info(
                "Competition: Created report intent for persona=%d, assigned ccid=%s",
                profile_id,
                intent.ccid,
            )
            return SetReportIntentionResponse.success(csid=csid, ccid=intent.ccid)
        else:
            logger.warning("Competition: Failed to create report intent for csid=%s", csid)
            return SetReportIntentionResponse.error()
    finally:
        session.close()


def handle_submit_report(csid: str, ccid: str, profile_id: int, raw_report: bytes, request_id: str) -> SubmitReportResponse:
    """
    Handle SubmitReport SOAP operation.

    Submits match report data (raw binary). Parses the report using MatchReport,
    saves both raw and parsed data to files, and stores results in the database.
    When the final report is received, triggers match finalization with ELO updates.

    Args:
        csid: Competition Session ID.
        ccid: Competition Channel ID.
        profile_id: The profile ID submitting the report.
        raw_report: Raw binary report data.
        request_id: Unique request ID for logging.

    Returns:
        SubmitReportResponse indicating success or error.
    """
    logger.info(
        "[%s] === SUBMIT REPORT START === csid=%s, ccid=%s, profileId=%d, report_size=%d",
        request_id,
        csid,
        ccid,
        profile_id,
        len(raw_report) if raw_report else 0,
    )

    report: MatchReport | None = None
    report_data: dict = {}
    is_final_report = False
    player_full_id = ""

    # Parse the binary report
    if raw_report:
        try:
            report = MatchReport.from_bytes(raw_report)

            # Extract useful data for database storage
            player_list = report.get_player_list()

            # Find this player's data in the report
            player_result = 0
            player_faction = ""
            for player in player_list:
                if player.persona_id == profile_id:
                    player_result = 0 if player.is_winner else 1
                    player_faction = player.faction
                    player_full_id = player.full_id
                    break

            # Map game type string to int
            # Valid1v1/AutoMatch1v1 -> 1, Valid2v2/AutoMatch2v2 -> 2
            game_type_str = report.get_game_type()
            gametype_int = 0  # Default unranked
            if "1v1" in game_type_str and report.is_auto_match:
                gametype_int = 1  # ranked_1v1
            elif "2v2" in game_type_str and report.is_auto_match:
                gametype_int = 2  # ranked_2v2

            report_data = {
                "result": player_result,
                "faction": player_faction,
                "duration": 0,  # Will be calculated from session timestamps
                "gametype": gametype_int,
                "map_name": report.get_map_path(),
            }

            # Determine if this is a partial or final report
            # Final reports have more than 1 player
            is_final_report = len(player_list) > 1

            logger.info(
                "[%s] Report parsed successfully - protocol_version=%d, developer_version=%d",
                request_id,
                report.protocol_version,
                report.developer_version,
            )
            logger.info(
                "[%s] Report type: %s (player_count=%d)",
                request_id,
                "FINAL REPORT" if is_final_report else "PARTIAL REPORT",
                len(player_list),
            )
            logger.info(
                "[%s] Game info - game_type=%s, map=%s, replay_guid=%s, is_auto_match=%s",
                request_id,
                game_type_str,
                report.get_map_path(),
                report.get_replay_guid(),
                report.is_auto_match,
            )
            logger.info(
                "[%s] Player data - result=%d, faction=%s, gametype=%d",
                request_id,
                player_result,
                player_faction,
                gametype_int,
            )

            # Log each player's result
            for idx, player in enumerate(player_list):
                logger.info(
                    "[%s] Player %d/%d: persona_id=%d, full_id=%s, faction=%s, is_winner=%s",
                    request_id,
                    idx + 1,
                    len(player_list),
                    player.persona_id,
                    player.full_id,
                    player.faction,
                    player.is_winner,
                )

            if is_final_report:
                logger.info("[%s] Winners: %s", request_id, report.get_winner_id_list())
                logger.info("[%s] Losers: %s", request_id, report.get_loser_id_list())

        except Exception as e:
            logger.exception("[%s] Error parsing report: %s", request_id, e)

        # Save report to files
        save_match_report(csid, ccid, raw_report, report)
    else:
        logger.warning("[%s] No report data received!", request_id)

    # Store in database
    logger.info("[%s] Storing report in database...", request_id)
    session = create_session()
    try:
        # Store the match report
        submit_match_report(session, csid, ccid, profile_id, report_data)

        # Mark report intent as reported and update full_id
        if ccid:
            mark_report_intent_reported(session, ccid, player_full_id)

        # Increment received reports counter
        comp_session = increment_received_reports(session, csid)

        # Check if this is the final report (all players have reported)
        if is_final_report and comp_session:
            logger.info(
                "[%s] Final report received, finalizing match (received=%d, expected=%d)",
                request_id,
                comp_session.received_reports,
                comp_session.expected_players,
            )
            if finalize_match(session, csid):
                logger.info("[%s] Match finalized successfully with ELO updates", request_id)
            else:
                logger.warning("[%s] Match finalization returned False", request_id)
        else:
            # Just mark as completed if not final
            complete_competition_session(session, csid)

        logger.info("[%s] === SUBMIT REPORT END === Success", request_id)
        return SubmitReportResponse.success()
    except Exception as e:
        logger.exception("[%s] === SUBMIT REPORT END === Database error: %s", request_id, e)
        raise
    finally:
        session.close()


def extract_submit_report_data(body: bytes, request_id: str) -> tuple[str, str, int, bytes]:
    """
    Extract data from SubmitReport request.

    The game sends SubmitReport as XML followed by binary data:
    - XML SOAP envelope with csid, ccid, certificate
    - Marker: "application/bin\0"
    - Raw binary report data

    Args:
        body: Raw request body bytes.
        request_id: Unique request ID for logging.

    Returns:
        Tuple of (csid, ccid, profile_id, raw_report).
    """
    logger.info("[%s] Extracting SubmitReport data from body (size=%d bytes)", request_id, len(body))

    # Markers to find in the raw bytes
    csid_marker = b"<gsc:csid>"
    csid_end_marker = b"</gsc:csid>"
    ccid_marker = b"<gsc:ccid>"
    ccid_end_marker = b"</gsc:ccid>"
    profileid_marker = b"<gsc:profileid>"
    profileid_end_marker = b"</gsc:profileid>"
    userid_marker = b"<gsc:userid>"
    userid_end_marker = b"</gsc:userid>"
    authoritative_marker = b"<gsc:authoritative>"
    authoritative_end_marker = b"</gsc:authoritative>"
    bin_marker = b"application/bin\x00"

    # Extract csid
    csid = ""
    csid_start = body.find(csid_marker)
    if csid_start != -1:
        csid_start += len(csid_marker)
        csid_end = body.find(csid_end_marker, csid_start)
        if csid_end != -1:
            csid = body[csid_start:csid_end].decode("ascii", errors="ignore")
    logger.info("[%s] Extracted csid=%s", request_id, csid)

    # Extract ccid
    ccid = ""
    ccid_start = body.find(ccid_marker)
    if ccid_start != -1:
        ccid_start += len(ccid_marker)
        ccid_end = body.find(ccid_end_marker, ccid_start)
        if ccid_end != -1:
            ccid = body[ccid_start:ccid_end].decode("ascii", errors="ignore")
    logger.info("[%s] Extracted ccid=%s", request_id, ccid)

    # Extract userid from certificate
    user_id = 0
    userid_start = body.find(userid_marker)
    if userid_start != -1:
        userid_start += len(userid_marker)
        userid_end = body.find(userid_end_marker, userid_start)
        if userid_end != -1:
            try:
                user_id = int(body[userid_start:userid_end].decode("ascii"))
            except ValueError:
                pass
    logger.info("[%s] Extracted userId=%d", request_id, user_id)

    # Extract profileid from certificate
    profile_id = 0
    profileid_start = body.find(profileid_marker)
    if profileid_start != -1:
        profileid_start += len(profileid_marker)
        profileid_end = body.find(profileid_end_marker, profileid_start)
        if profileid_end != -1:
            try:
                profile_id = int(body[profileid_start:profileid_end].decode("ascii"))
            except ValueError:
                pass
    logger.info("[%s] Extracted profileId=%d", request_id, profile_id)

    # Extract authoritative flag
    authoritative = ""
    auth_start = body.find(authoritative_marker)
    if auth_start != -1:
        auth_start += len(authoritative_marker)
        auth_end = body.find(authoritative_end_marker, auth_start)
        if auth_end != -1:
            authoritative = body[auth_start:auth_end].decode("ascii", errors="ignore")
    logger.info("[%s] Extracted authoritative=%s", request_id, authoritative)

    # Extract binary report (after "application/bin\0" marker)
    raw_report = b""
    bin_pos = body.find(bin_marker)
    if bin_pos != -1:
        raw_report = body[bin_pos + len(bin_marker):]
        logger.info("[%s] Found binary report at position %d, size=%d bytes", request_id, bin_pos, len(raw_report))
    else:
        logger.warning("[%s] No binary report marker found in request!", request_id)

    logger.info(
        "[%s] SubmitReport extraction complete: csid=%s, ccid=%s, userId=%d, profileId=%d, authoritative=%s, report_size=%d",
        request_id,
        csid,
        ccid,
        user_id,
        profile_id,
        authoritative,
        len(raw_report),
    )

    return csid, ccid, profile_id, raw_report


@competition_router.post("/competitionservice/competitionservice.asmx")
async def competition_handler(request: Request) -> Response:
    """
    Main handler for Competition Service SOAP requests.

    Routes requests based on SOAPAction header.
    """
    # Generate unique request ID for tracing
    request_id = str(uuid.uuid4())[:8]
    request_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]

    try:
        soap_action = request.headers.get("SOAPAction", "").strip('"')
        operation_name_from_action = soap_action.split("/")[-1] if "/" in soap_action else soap_action

        logger.info(
            "[%s] === REQUEST === time=%s, SOAPAction=%s",
            request_id,
            request_time,
            soap_action,
        )

        body = await request.body()
        original_size = len(body)

        # Check for gzip compression (magic bytes 0x1f 0x8b)
        if len(body) >= 2 and body[0] == 0x1F and body[1] == 0x8B:
            body = gzip.decompress(body)
            logger.info("[%s] Decompressed gzip: %d -> %d bytes", request_id, original_size, len(body))
        else:
            logger.info("[%s] Request body size: %d bytes", request_id, len(body))

        # SubmitReport has binary data appended after XML, handle it specially
        if "SubmitReport" in soap_action:
            logger.info("[%s] Handling SubmitReport (binary data expected)", request_id)
            logger.debug("[%s] Request body (first 500 bytes): %s", request_id, body[:500])
            csid, ccid, profile_id, raw_report = extract_submit_report_data(body, request_id)
            response_model = handle_submit_report(csid, ccid, profile_id, raw_report, request_id)
            response_xml = wrap_soap_envelope(response_model)
        else:
            # For other operations, parse as pure XML
            xml_content = body.decode("utf-8")
            logger.debug("[%s] Request body: %s", request_id, xml_content[:500])

            operation = extract_soap_body(xml_content)
            operation_name = get_operation_name(operation)
            logger.info("[%s] Operation: %s", request_id, operation_name)

            if "CreateSession" in soap_action or operation_name == "CreateSession":
                profile_id = extract_profile_id_from_certificate(operation)
                logger.info("[%s] CreateSession: profileId=%d", request_id, profile_id)
                response_model = handle_create_session(profile_id)
                response_xml = wrap_soap_envelope(response_model)

            elif "SetReportIntention" in soap_action or operation_name == "SetReportIntention":
                csid = get_element_text(operation, "csid")
                ccid = get_element_text(operation, "ccid")
                profile_id = extract_profile_id_from_certificate(operation)
                logger.info(
                    "[%s] SetReportIntention: csid=%s, ccid=%s, profileId=%d",
                    request_id,
                    csid,
                    ccid,
                    profile_id,
                )
                response_model = handle_set_report_intention(csid, ccid, profile_id)
                response_xml = wrap_soap_envelope(response_model)

            else:
                logger.warning("[%s] Unknown operation, returning generic success", request_id)
                response_model = SubmitReportResponse.success()
                response_xml = wrap_soap_envelope(response_model)

        logger.debug("[%s] Response: %s", request_id, response_xml[:500])
        logger.info("[%s] === RESPONSE === Success", request_id)

        return Response(
            content=response_xml,
            media_type="text/xml; charset=utf-8",
        )

    except Exception as e:
        logger.exception("[%s] === RESPONSE === Error: %s", request_id, e)
        fault_xml = create_soap_fault(str(e))
        return Response(
            content=fault_xml,
            media_type="text/xml; charset=utf-8",
            status_code=500,
        )
