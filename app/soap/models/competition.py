"""
Pydantic-XML models for Competition SOAP Service.

Endpoint: /competitionservice/competitionservice.asmx
Namespace: http://gamespy.net/competition
"""

from pydantic_xml import BaseXmlModel, element

COMP_NS = "http://gamespy.net/competition"


# --- CreateSession ---


class CreateSessionRequest(BaseXmlModel, tag="CreateSession", nsmap={"": COMP_NS}):
    """Request model for CreateSession operation."""

    profile_id: int = element(tag="profileId", default=0)


class CreateSessionResponse(BaseXmlModel, tag="CreateSessionResponse", nsmap={"": COMP_NS}):
    """
    Response model for CreateSession operation.

    Returns csid (Competition Session ID) and ccid (Competition Channel ID).
    """

    result: str = element(tag="CreateSessionResult")
    csid: str | None = element(tag="csid", default=None)
    ccid: str | None = element(tag="ccid", default=None)

    @classmethod
    def success(cls, csid: str, ccid: str) -> "CreateSessionResponse":
        """Create a successful response with session IDs."""
        return cls(result="Success", csid=csid, ccid=ccid)

    @classmethod
    def error(cls, message: str = "Error") -> "CreateSessionResponse":
        """Create an error response."""
        return cls(result=message)


# --- SetReportIntention ---


class SetReportIntentionRequest(BaseXmlModel, tag="SetReportIntention", nsmap={"": COMP_NS}):
    """Request model for SetReportIntention operation."""

    csid: str = element(tag="csid", default="")
    ccid: str = element(tag="ccid", default="")
    profile_id: int = element(tag="profileId", default=0)


class SetReportIntentionResponse(BaseXmlModel, tag="SetReportIntentionResponse", nsmap={"": COMP_NS}):
    """
    Response model for SetReportIntention operation.

    Echoes back the ccid to confirm the intention was set.
    """

    result: str = element(tag="SetReportIntentionResult")
    ccid: str | None = element(tag="ccid", default=None)

    @classmethod
    def success(cls, ccid: str) -> "SetReportIntentionResponse":
        """Create a successful response."""
        return cls(result="Success", ccid=ccid)

    @classmethod
    def error(cls, ccid: str = "") -> "SetReportIntentionResponse":
        """Create an error response."""
        return cls(result="Error", ccid=ccid)


# --- SubmitReport ---


class SubmitReportRequest(BaseXmlModel, tag="SubmitReport", nsmap={"": COMP_NS}):
    """Request model for SubmitReport operation."""

    csid: str = element(tag="csid", default="")
    ccid: str = element(tag="ccid", default="")
    profile_id: int = element(tag="profileId", default=0)
    report: str = element(tag="report", default="")  # Base64 encoded report data


class SubmitReportResponse(BaseXmlModel, tag="SubmitReportResponse", nsmap={"": COMP_NS}):
    """Response model for SubmitReport operation."""

    result: str = element(tag="SubmitReportResult")

    @classmethod
    def success(cls) -> "SubmitReportResponse":
        """Create a successful response."""
        return cls(result="Success")

    @classmethod
    def error(cls, message: str = "Error") -> "SubmitReportResponse":
        """Create an error response."""
        return cls(result=message)
