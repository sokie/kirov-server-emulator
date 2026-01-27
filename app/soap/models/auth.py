"""
Pydantic-XML models for Auth SOAP Service.

Endpoint: /AuthService/AuthService.asmx
Namespace: http://gamespy.net/AuthService/

Response codes from GameSpy AuthService:
https://github.com/openspy/webservices/blob/master/AuthService/modules/ResponseCode.py
"""

from enum import IntEnum

from pydantic_xml import BaseXmlModel, element

AUTH_NS = "http://gamespy.net/AuthService/"


class LoginResponseCode(IntEnum):
    """Response codes for LoginRemoteAuth operation."""

    SUCCESS = 0
    SERVER_INIT_FAILED = 1
    USER_NOT_FOUND = 2
    INVALID_PASSWORD = 3
    INVALID_PROFILE = 4
    UNIQUE_NICK_EXPIRED = 5
    DB_ERROR = 6
    SERVER_ERROR = 7


class Certificate(BaseXmlModel, tag="certificate"):
    """Certificate data containing player info and crypto keys."""

    length: int = element(tag="length", default=305)
    version: int = element(tag="version", default=1)
    partnercode: int = element(tag="partnercode", default=60)
    namespaceid: int = element(tag="namespaceid", default=69)
    userid: int = element(tag="userid")
    profileid: int = element(tag="profileid")
    expiretime: int = element(tag="expiretime", default=0)
    profilenick: str = element(tag="profilenick")
    uniquenick: str = element(tag="uniquenick")
    cdkeyhash: str = element(tag="cdkeyhash", default="")
    peerkeymodulus: str = element(tag="peerkeymodulus")
    peerkeyexponent: str = element(tag="peerkeyexponent", default="010001")
    serverdata: str = element(tag="serverdata")
    signature: str = element(tag="signature")
    timestamp: str = element(tag="timestamp")
    email: str = element(tag="email")


class LoginRemoteAuthResult(BaseXmlModel, tag="LoginRemoteAuthResult"):
    """Result container with response code, certificate, and private key."""

    response_code: int = element(tag="responseCode", default=0)
    certificate: Certificate | None = element(tag="certificate", default=None)
    peerkeyprivate: str | None = element(tag="peerkeyprivate", default=None)


class LoginRemoteAuthResponse(BaseXmlModel, tag="LoginRemoteAuthResponse", nsmap={"": AUTH_NS}):
    """
    Response model for LoginRemoteAuth operation.

    Returns certificate with player info and crypto keys.
    """

    result: LoginRemoteAuthResult = element(tag="LoginRemoteAuthResult")

    @classmethod
    def success(
        cls,
        user_id: int,
        profile_id: int,
        nickname: str,
        email: str,
        peerkeymodulus: str,
        serverdata: str,
        signature: str,
        peerkeyprivate: str,
        timestamp: str,
    ) -> "LoginRemoteAuthResponse":
        """Create a successful response with real player data and dynamically generated crypto."""
        cert = Certificate(
            userid=user_id,
            profileid=profile_id,
            profilenick=nickname,
            uniquenick=nickname,
            email=email,
            peerkeymodulus=peerkeymodulus,
            serverdata=serverdata,
            signature=signature,
            timestamp=timestamp,
        )
        result = LoginRemoteAuthResult(
            response_code=LoginResponseCode.SUCCESS,
            certificate=cert,
            peerkeyprivate=peerkeyprivate,
        )
        return cls(result=result)

    @classmethod
    def error(cls, code: LoginResponseCode) -> "LoginRemoteAuthResponse":
        """Create an error response with only a response code."""
        result = LoginRemoteAuthResult(response_code=code)
        return cls(result=result)
