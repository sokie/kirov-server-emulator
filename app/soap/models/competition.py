"""
Pydantic-XML models for Competition SOAP Service.

Endpoint: /competitionservice/competitionservice.asmx
Namespace: http://gamespy.net/competition

Response format based on:
https://github.com/openspy/webservices/blob/master/CompetitionService/handlers/
"""

from enum import IntEnum

from pydantic_xml import BaseXmlModel, element

COMP_NS = "http://gamespy.net/competition/"


class CompetitionResultCode(IntEnum):
    """Result codes for Competition Service operations."""

    SUCCESS = 0
    ERROR = 1


# --- CreateSession ---


class CreateSessionRequest(BaseXmlModel, tag="CreateSession", nsmap={"": COMP_NS}):
    """Request model for CreateSession operation."""

    profile_id: int = element(tag="profileId", default=0)


class CreateSessionResult(BaseXmlModel, tag="CreateSessionResult"):
    """Result container for CreateSession with result code, csid, and ccid."""

    result: int = element(tag="result", default=0)
    message: str = element(tag="message", default="")
    csid: str | None = element(tag="csid", default=None)
    ccid: str | None = element(tag="ccid", default=None)


class CreateSessionResponse(BaseXmlModel, tag="CreateSessionResponse", nsmap={"": COMP_NS}):
    """
    Response model for CreateSession operation.

    Returns csid (Competition Session ID) and ccid (Competition Channel ID).
    """

    result: CreateSessionResult = element(tag="CreateSessionResult")

    @classmethod
    def success(cls, csid: str, ccid: str) -> "CreateSessionResponse":
        """Create a successful response with session IDs."""
        return cls(
            result=CreateSessionResult(
                result=CompetitionResultCode.SUCCESS,
                csid=csid,
                ccid=ccid,
            )
        )

    @classmethod
    def error(cls, code: int = CompetitionResultCode.ERROR) -> "CreateSessionResponse":
        """Create an error response."""
        return cls(result=CreateSessionResult(result=code))


# --- SetReportIntention ---


class SetReportIntentionRequest(BaseXmlModel, tag="SetReportIntention", nsmap={"": COMP_NS}):
    """Request model for SetReportIntention operation."""

    csid: str = element(tag="csid", default="")
    ccid: str = element(tag="ccid", default="")
    profile_id: int = element(tag="profileId", default=0)


class SetReportIntentionResult(BaseXmlModel, tag="SetReportIntentionResult"):
    """Result container for SetReportIntention with result code, csid, and ccid."""

    result: int = element(tag="result", default=0)
    message: str = element(tag="message", default="")
    csid: str | None = element(tag="csid", default=None)
    ccid: str | None = element(tag="ccid", default=None)


class SetReportIntentionResponse(BaseXmlModel, tag="SetReportIntentionResponse", nsmap={"": COMP_NS}):
    """
    Response model for SetReportIntention operation.

    Echoes back the ccid to confirm the intention was set.
    """

    result: SetReportIntentionResult = element(tag="SetReportIntentionResult")

    @classmethod
    def success(cls, csid: str, ccid: str) -> "SetReportIntentionResponse":
        """Create a successful response with csid and ccid."""
        return cls(
            result=SetReportIntentionResult(
                result=CompetitionResultCode.SUCCESS,
                csid=csid,
                ccid=ccid,
            )
        )

    @classmethod
    def error(cls, code: int = CompetitionResultCode.ERROR) -> "SetReportIntentionResponse":
        """Create an error response."""
        return cls(result=SetReportIntentionResult(result=code))


# --- SubmitReport ---


class SubmitReportRequest(BaseXmlModel, tag="SubmitReport", nsmap={"": COMP_NS}):
    """Request model for SubmitReport operation."""

    csid: str = element(tag="csid", default="")
    ccid: str = element(tag="ccid", default="")
    profile_id: int = element(tag="profileId", default=0)
    report: str = element(tag="report", default="")  # Base64 encoded report data


class SubmitReportResult(BaseXmlModel, tag="SubmitReportResult"):
    """Result container for SubmitReport with result code."""

    result: int = element(tag="result", default=0)


class SubmitReportResponse(BaseXmlModel, tag="SubmitReportResponse", nsmap={"": COMP_NS}):
    """Response model for SubmitReport operation."""

    result: SubmitReportResult = element(tag="SubmitReportResult")

    @classmethod
    def success(cls) -> "SubmitReportResponse":
        """Create a successful response."""
        return cls(result=SubmitReportResult(result=CompetitionResultCode.SUCCESS))

    @classmethod
    def error(cls, code: int = CompetitionResultCode.ERROR) -> "SubmitReportResponse":
        """Create an error response."""
        return cls(result=SubmitReportResult(result=code))
