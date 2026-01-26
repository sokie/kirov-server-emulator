"""
Pydantic-XML models for Sake Storage SOAP Service.

Endpoint: /SakeStorageServer/StorageServer.asmx
Namespace: http://gamespy.net/sake
"""

from typing import List, Optional

from pydantic_xml import BaseXmlModel, element

from app.soap.models.common import ArrayOfRecordValue, RecordValue

SAKE_NS = "http://gamespy.net/sake"


# --- Shared types ---


class StringList(BaseXmlModel, tag="fields"):
    """List of field name strings."""

    items: List[str] = element(tag="string", default=[])


# --- Values container ---


class ValuesContainer(BaseXmlModel, tag="values"):
    """Container for ArrayOfRecordValue elements in responses."""

    arrays: List[ArrayOfRecordValue] = element(tag="ArrayOfRecordValue", default=[])

    @classmethod
    def single(cls, records: List[RecordValue]) -> "ValuesContainer":
        """Create a container with a single ArrayOfRecordValue."""
        return cls(arrays=[ArrayOfRecordValue(records=records)])

    @classmethod
    def multiple(cls, record_lists: List[List[RecordValue]]) -> "ValuesContainer":
        """Create a container with multiple ArrayOfRecordValue elements."""
        return cls(arrays=[ArrayOfRecordValue(records=recs) for recs in record_lists])


# --- GetMyRecords ---


class GetMyRecordsRequest(BaseXmlModel, tag="GetMyRecords", nsmap={"": SAKE_NS}):
    """Request model for GetMyRecords operation."""

    game_id: int = element(tag="gameid", default=0)
    secret_key: str = element(tag="secretKey", default="")
    login_ticket: str = element(tag="loginTicket", default="")
    table_id: str = element(tag="tableid", default="")
    fields: Optional[StringList] = element(tag="fields", default=None)


class GetMyRecordsResponse(BaseXmlModel, tag="GetMyRecordsResponse", nsmap={"": SAKE_NS}):
    """
    Response model for GetMyRecords operation.

    Returns player's career stats as an array of RecordValue elements.
    """

    result: str = element(tag="GetMyRecordsResult")
    values: Optional[ValuesContainer] = element(tag="values", default=None)

    @classmethod
    def success(cls, records: List[RecordValue]) -> "GetMyRecordsResponse":
        """Create a successful response with record values."""
        if not records:
            return cls(result="Success", values=ValuesContainer(arrays=[]))
        return cls(result="Success", values=ValuesContainer.single(records))

    @classmethod
    def success_empty(cls) -> "GetMyRecordsResponse":
        """Create a successful response with empty values."""
        return cls(result="Success", values=ValuesContainer(arrays=[]))

    @classmethod
    def error(cls, message: str = "Error") -> "GetMyRecordsResponse":
        """Create an error response."""
        return cls(result=message)


# --- GetSpecificRecords ---


class GetSpecificRecordsRequest(BaseXmlModel, tag="GetSpecificRecords", nsmap={"": SAKE_NS}):
    """Request model for GetSpecificRecords operation."""

    game_id: int = element(tag="gameid", default=0)
    secret_key: str = element(tag="secretKey", default="")
    login_ticket: str = element(tag="loginTicket", default="")
    table_id: str = element(tag="tableid", default="")
    fields: Optional[StringList] = element(tag="fields", default=None)


class GetSpecificRecordsResponse(BaseXmlModel, tag="GetSpecificRecordsResponse", nsmap={"": SAKE_NS}):
    """
    Response model for GetSpecificRecords operation.

    Returns table data like ScoringMultipliers.
    """

    result: str = element(tag="GetSpecificRecordsResult")
    values: Optional[ValuesContainer] = element(tag="values", default=None)

    @classmethod
    def success(cls, records: List[RecordValue]) -> "GetSpecificRecordsResponse":
        """Create a successful response with record values."""
        if not records:
            return cls(result="Success", values=ValuesContainer(arrays=[]))
        return cls(result="Success", values=ValuesContainer.single(records))

    @classmethod
    def success_empty(cls) -> "GetSpecificRecordsResponse":
        """Create a successful response with empty values."""
        return cls(result="Success", values=ValuesContainer(arrays=[]))

    @classmethod
    def error(cls, message: str = "Error") -> "GetSpecificRecordsResponse":
        """Create an error response."""
        return cls(result=message)


# --- SearchForRecords ---


class SearchForRecordsRequest(BaseXmlModel, tag="SearchForRecords", nsmap={"": SAKE_NS}):
    """Request model for SearchForRecords operation."""

    game_id: int = element(tag="gameid", default=0)
    secret_key: str = element(tag="secretKey", default="")
    login_ticket: str = element(tag="loginTicket", default="")
    table_id: str = element(tag="tableid", default="")
    filter_str: str = element(tag="filter", default="")
    fields: Optional[StringList] = element(tag="fields", default=None)
    max_results: int = element(tag="max", default=100)


class SearchForRecordsResponse(BaseXmlModel, tag="SearchForRecordsResponse", nsmap={"": SAKE_NS}):
    """
    Response model for SearchForRecords operation.

    Returns search results as multiple ArrayOfRecordValue elements.
    """

    result: str = element(tag="SearchForRecordsResult")
    values: Optional[ValuesContainer] = element(tag="values", default=None)

    @classmethod
    def success(cls, record_lists: List[List[RecordValue]]) -> "SearchForRecordsResponse":
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
    def error(cls, message: str = "Error") -> "SearchForRecordsResponse":
        """Create an error response."""
        return cls(result=message)
