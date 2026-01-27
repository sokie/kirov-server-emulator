"""
Pydantic-XML models for Sake Storage SOAP Service.

Endpoint: /SakeStorageServer/StorageServer.asmx
Namespace: http://gamespy.net/sake
"""

from pydantic_xml import BaseXmlModel, element

from app.soap.models.common import ArrayOfRecordValue, RecordValue

SAKE_NS = "http://gamespy.net/sake"


# --- Result codes (matching OpenSpy reference implementation) ---


class SAKEResultCode:
    """Result codes for SAKE Storage Service operations."""

    SUCCESS = "Success"
    LOGIN_TICKET_INVALID = "LoginTicketInvalid"
    RECORD_NOT_FOUND = "RecordNotFound"
    UNKNOWN = "Unknown"


# --- Shared types ---


class StringList(BaseXmlModel, tag="fields"):
    """List of field name strings."""

    items: list[str] = element(tag="string", default=[])


# --- Values container ---


class ValuesContainer(BaseXmlModel, tag="values"):
    """Container for ArrayOfRecordValue elements in responses."""

    arrays: list[ArrayOfRecordValue] = element(tag="ArrayOfRecordValue", default=[])

    @classmethod
    def single(cls, records: list[RecordValue]) -> "ValuesContainer":
        """Create a container with a single ArrayOfRecordValue."""
        return cls(arrays=[ArrayOfRecordValue(records=records)])

    @classmethod
    def multiple(cls, record_lists: list[list[RecordValue]]) -> "ValuesContainer":
        """Create a container with multiple ArrayOfRecordValue elements."""
        return cls(arrays=[ArrayOfRecordValue(records=recs) for recs in record_lists])


# --- GetMyRecords ---


class GetMyRecordsRequest(BaseXmlModel, tag="GetMyRecords", nsmap={"": SAKE_NS}):
    """Request model for GetMyRecords operation."""

    game_id: int = element(tag="gameid", default=0)
    secret_key: str = element(tag="secretKey", default="")
    login_ticket: str = element(tag="loginTicket", default="")
    table_id: str = element(tag="tableid", default="")
    fields: StringList | None = element(tag="fields", default=None)


class GetMyRecordsResponse(BaseXmlModel, tag="GetMyRecordsResponse", nsmap={"": SAKE_NS}):
    """
    Response model for GetMyRecords operation.

    Returns player's career stats as an array of RecordValue elements.
    """

    result: str = element(tag="GetMyRecordsResult")
    values: ValuesContainer | None = element(tag="values", default=None)

    @classmethod
    def success(cls, records: list[RecordValue]) -> "GetMyRecordsResponse":
        """Create a successful response with record values."""
        if not records:
            return cls(result="Success", values=ValuesContainer(arrays=[]))
        return cls(result="Success", values=ValuesContainer.single(records))

    @classmethod
    def success_empty(cls) -> "GetMyRecordsResponse":
        """Create a successful response with empty values."""
        return cls(result="Success", values=ValuesContainer(arrays=[]))

    @classmethod
    def error(cls, code: str = SAKEResultCode.UNKNOWN) -> "GetMyRecordsResponse":
        """Create an error response with a specific error code."""
        return cls(result=code)


# --- GetSpecificRecords ---


class GetSpecificRecordsRequest(BaseXmlModel, tag="GetSpecificRecords", nsmap={"": SAKE_NS}):
    """Request model for GetSpecificRecords operation."""

    game_id: int = element(tag="gameid", default=0)
    secret_key: str = element(tag="secretKey", default="")
    login_ticket: str = element(tag="loginTicket", default="")
    table_id: str = element(tag="tableid", default="")
    fields: StringList | None = element(tag="fields", default=None)


class GetSpecificRecordsResponse(BaseXmlModel, tag="GetSpecificRecordsResponse", nsmap={"": SAKE_NS}):
    """
    Response model for GetSpecificRecords operation.

    Returns table data like ScoringMultipliers.
    """

    result: str = element(tag="GetSpecificRecordsResult")
    values: ValuesContainer | None = element(tag="values", default=None)

    @classmethod
    def success(cls, records: list[RecordValue]) -> "GetSpecificRecordsResponse":
        """Create a successful response with record values."""
        if not records:
            return cls(result="Success", values=ValuesContainer(arrays=[]))
        return cls(result="Success", values=ValuesContainer.single(records))

    @classmethod
    def success_empty(cls) -> "GetSpecificRecordsResponse":
        """Create a successful response with empty values."""
        return cls(result="Success", values=ValuesContainer(arrays=[]))

    @classmethod
    def error(cls, code: str = SAKEResultCode.UNKNOWN) -> "GetSpecificRecordsResponse":
        """Create an error response with a specific error code."""
        return cls(result=code)


# --- SearchForRecords ---


class SearchForRecordsRequest(BaseXmlModel, tag="SearchForRecords", nsmap={"": SAKE_NS}):
    """Request model for SearchForRecords operation."""

    game_id: int = element(tag="gameid", default=0)
    secret_key: str = element(tag="secretKey", default="")
    login_ticket: str = element(tag="loginTicket", default="")
    table_id: str = element(tag="tableid", default="")
    filter_str: str = element(tag="filter", default="")
    fields: StringList | None = element(tag="fields", default=None)
    max_results: int = element(tag="max", default=100)


class SearchForRecordsResponse(BaseXmlModel, tag="SearchForRecordsResponse", nsmap={"": SAKE_NS}):
    """
    Response model for SearchForRecords operation.

    Returns search results as multiple ArrayOfRecordValue elements.
    """

    result: str = element(tag="SearchForRecordsResult")
    values: ValuesContainer | None = element(tag="values", default=None)

    @classmethod
    def success(cls, record_lists: list[list[RecordValue]]) -> "SearchForRecordsResponse":
        """
        Create a successful response with multiple arrays of record values.

        Each inner list becomes one ArrayOfRecordValue element.
        """
        if not record_lists:
            return cls(result="Success", values=ValuesContainer(arrays=[]))
        return cls(result="Success", values=ValuesContainer.multiple(record_lists))

    @classmethod
    def success_empty(cls) -> "SearchForRecordsResponse":
        """Create a successful response with empty values."""
        return cls(result="Success", values=ValuesContainer(arrays=[]))

    @classmethod
    def error(cls, code: str = SAKEResultCode.UNKNOWN) -> "SearchForRecordsResponse":
        """Create an error response with a specific error code."""
        return cls(result=code)
