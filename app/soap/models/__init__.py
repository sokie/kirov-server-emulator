"""
Pydantic-XML models for SOAP services.

This package contains type-safe XML models for request/response serialization.
"""

from app.soap.models.auth import (
    AUTH_NS,
    Certificate,
    LoginRemoteAuthResponse,
    LoginRemoteAuthResult,
)
from app.soap.models.clan import (
    CLAN_NS,
    ClanInfo,
    LadderRatings,
)
from app.soap.models.common import (
    ArrayOfRecordValue,
    FloatValueWrapper,
    IntValueWrapper,
    RecordValue,
    ShortValueWrapper,
)
from app.soap.models.competition import (
    COMP_NS,
    CreateSessionRequest,
    CreateSessionResponse,
    SetReportIntentionRequest,
    SetReportIntentionResponse,
    SubmitReportRequest,
    SubmitReportResponse,
)
from app.soap.models.sake import (
    SAKE_NS,
    GetMyRecordsRequest,
    GetMyRecordsResponse,
    GetSpecificRecordsRequest,
    GetSpecificRecordsResponse,
    SearchForRecordsRequest,
    SearchForRecordsResponse,
    StringList,
    ValuesContainer,
)

__all__ = [
    # Common
    "ArrayOfRecordValue",
    "FloatValueWrapper",
    "IntValueWrapper",
    "RecordValue",
    "ShortValueWrapper",
    # Auth
    "AUTH_NS",
    "Certificate",
    "LoginRemoteAuthResponse",
    "LoginRemoteAuthResult",
    # Clan
    "CLAN_NS",
    "ClanInfo",
    "LadderRatings",
    # Competition
    "COMP_NS",
    "CreateSessionRequest",
    "CreateSessionResponse",
    "SetReportIntentionRequest",
    "SetReportIntentionResponse",
    "SubmitReportRequest",
    "SubmitReportResponse",
    # Sake
    "SAKE_NS",
    "GetMyRecordsRequest",
    "GetMyRecordsResponse",
    "GetSpecificRecordsRequest",
    "GetSpecificRecordsResponse",
    "SearchForRecordsRequest",
    "SearchForRecordsResponse",
    "StringList",
    "ValuesContainer",
]
