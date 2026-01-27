"""
Auth SOAP Service - Certificate management for RA3.

Endpoint: /AuthService/AuthService.asmx

This service handles:
- LoginRemoteAuth: Generates certificates with valid cryptographic signatures

Certificates are dynamically generated with RSA keys and MD5 signatures
computed over actual player data.
"""

import base64
from datetime import datetime

from fastapi import APIRouter, Request, Response
from sqlmodel import select

from app.db.database import create_session
from app.models.models import Persona, User
from app.soap.envelope import (
    create_soap_fault,
    extract_soap_body,
    get_element_text,
    get_operation_name,
    wrap_soap_envelope,
)
from app.soap.models.auth import LoginRemoteAuthResponse, LoginResponseCode
from app.util.gamespy_crypto import GeneratedCertificate, generate_certificate_for_player
from app.util.logging_helper import get_logger

logger = get_logger(__name__)

auth_router = APIRouter()

# Cache generated certificates per profile to ensure consistency across requests
_profile_certificates: dict[int, GeneratedCertificate] = {}


def parse_authtoken(authtoken: str) -> tuple[int, int]:
    """
    Parse the authtoken to extract user_id and persona_id.

    The token format is: base64(user_id|persona_id|token)

    Returns:
        Tuple of (user_id, persona_id).
    """
    try:
        decoded = base64.b64decode(authtoken).decode("utf-8")
        parts = decoded.split("|")
        if len(parts) >= 2:
            user_id = int(parts[0])
            persona_id = int(parts[1])
            return user_id, persona_id
    except Exception as e:
        logger.warning("Failed to parse authtoken: %s", e)
    return 0, 0


def generate_timestamp() -> str:
    """Generate base64 encoded timestamp in the format used by GameSpy."""
    # Format: M/d/yyyy h:mm:ss tt (e.g., "1/25/2026 3:30:45 PM")
    now = datetime.now()
    hour_12 = now.hour % 12 or 12
    am_pm = "AM" if now.hour < 12 else "PM"
    timestamp_str = f"{now.month}/{now.day}/{now.year} {hour_12}:{now.minute:02d}:{now.second:02d} {am_pm}"
    return base64.b64encode(timestamp_str.encode("utf-8")).decode("utf-8")


@auth_router.post("/AuthService/AuthService.asmx")
async def auth_handler(request: Request) -> Response:
    """
    Main handler for Auth Service SOAP requests.

    Routes requests based on SOAPAction header.
    """
    try:
        soap_action = request.headers.get("SOAPAction", "").strip('"')
        logger.debug("Auth: SOAPAction=%s", soap_action)

        body = await request.body()
        xml_content = body.decode("utf-8")
        logger.debug("Auth: Request body=%s", xml_content[:500])

        operation = extract_soap_body(xml_content)
        operation_name = get_operation_name(operation)
        logger.debug("Auth: Operation=%s", operation_name)

        if "LoginRemoteAuth" in soap_action or operation_name == "LoginRemoteAuth":
            authtoken = get_element_text(operation, "authtoken")
            user_id, profile_id = parse_authtoken(authtoken)
            logger.debug("Auth: Parsed authtoken -> user_id=%s, profile_id=%s", user_id, profile_id)

            # Validate authtoken parsing succeeded
            if user_id == 0 or profile_id == 0:
                logger.warning("Auth: Invalid authtoken - failed to parse user_id/profile_id")
                response_model = LoginRemoteAuthResponse.error(LoginResponseCode.INVALID_PASSWORD)
                return Response(
                    content=wrap_soap_envelope(response_model),
                    media_type="text/xml; charset=utf-8",
                )

            # Get real player info from database and verify user/persona exist
            session = create_session()
            try:
                # Verify user exists
                user = session.exec(select(User).where(User.id == user_id)).first()
                if not user:
                    logger.warning("Auth: User not found for user_id=%s", user_id)
                    response_model = LoginRemoteAuthResponse.error(LoginResponseCode.USER_NOT_FOUND)
                    return Response(
                        content=wrap_soap_envelope(response_model),
                        media_type="text/xml; charset=utf-8",
                    )

                # Verify persona exists
                persona = session.exec(select(Persona).where(Persona.id == profile_id)).first()
                if not persona:
                    logger.warning("Auth: Persona not found for profile_id=%s", profile_id)
                    response_model = LoginRemoteAuthResponse.error(LoginResponseCode.INVALID_PROFILE)
                    return Response(
                        content=wrap_soap_envelope(response_model),
                        media_type="text/xml; charset=utf-8",
                    )

                # Verify persona belongs to user
                if persona.user_id != user_id:
                    logger.warning(
                        "Auth: Persona %s does not belong to user %s (actual owner: %s)",
                        profile_id,
                        user_id,
                        persona.user_id,
                    )
                    response_model = LoginRemoteAuthResponse.error(LoginResponseCode.INVALID_PROFILE)
                    return Response(
                        content=wrap_soap_envelope(response_model),
                        media_type="text/xml; charset=utf-8",
                    )

                nickname = persona.name
                email = user.email
            finally:
                session.close()

            # Generate or retrieve cached certificate for this profile
            # We cache by (profile_id, user_id, nickname) to regenerate if player data changes
            cache_key = profile_id
            cached_cert = _profile_certificates.get(cache_key)

            if cached_cert is None:
                logger.info(
                    "Auth: Generating new certificate for profile_id=%s, user_id=%s, nickname=%s",
                    profile_id,
                    user_id,
                    nickname,
                )
                cert = generate_certificate_for_player(
                    userid=user_id,
                    profileid=profile_id,
                    profilenick=nickname,
                    uniquenick=nickname,
                )
                _profile_certificates[cache_key] = cert
            else:
                cert = cached_cert
                logger.debug("Auth: Using cached certificate for profile_id=%s", profile_id)

            # Generate timestamp
            timestamp = generate_timestamp()

            logger.debug(
                "Auth: Building response for profile_id=%s, nickname=%s, modulus=%s...",
                profile_id,
                nickname,
                cert.peerkeymodulus[:32],
            )

            # Build response with real player data and dynamically generated crypto
            response_model = LoginRemoteAuthResponse.success(
                user_id=user_id,
                profile_id=profile_id,
                nickname=nickname,
                email=email,
                peerkeymodulus=cert.peerkeymodulus,
                serverdata=cert.serverdata,
                signature=cert.signature,
                peerkeyprivate=cert.peerkeyprivate,
                timestamp=timestamp,
            )
            response_xml = wrap_soap_envelope(response_model)

            logger.debug("Auth: Response=%s", response_xml[:500])

            return Response(
                content=response_xml,
                media_type="text/xml; charset=utf-8",
            )
        else:
            # Return generic fault for unknown operations
            fault_xml = create_soap_fault("Unknown operation")
            return Response(
                content=fault_xml,
                media_type="text/xml; charset=utf-8",
            )

    except Exception as e:
        logger.exception("Auth: Error processing request: %s", e)
        fault_xml = create_soap_fault(str(e))
        return Response(
            content=fault_xml,
            media_type="text/xml; charset=utf-8",
            status_code=500,
        )
