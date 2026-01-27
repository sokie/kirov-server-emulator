"""
Common pydantic_xml models shared across SOAP services.

These models handle the RecordValue structure used by Sake and other services.
"""

from pydantic_xml import BaseXmlModel, element


class IntValueWrapper(BaseXmlModel, tag="intValue"):
    """Wrapper for integer values with nested <value> tag."""

    value: int = element(tag="value")


class FloatValueWrapper(BaseXmlModel, tag="floatValue"):
    """Wrapper for float values with nested <value> tag."""

    value: float = element(tag="value")


class ShortValueWrapper(BaseXmlModel, tag="shortValue"):
    """Wrapper for short integer values with nested <value> tag."""

    value: int = element(tag="value")


class RecordValue(BaseXmlModel, tag="RecordValue"):
    """
    A single record value that can be int, float, or short.

    Only one of int_value, float_value, or short_value should be set.
    """

    int_value: IntValueWrapper | None = element(tag="intValue", default=None)
    float_value: FloatValueWrapper | None = element(tag="floatValue", default=None)
    short_value: ShortValueWrapper | None = element(tag="shortValue", default=None)

    @classmethod
    def from_int(cls, value: int) -> "RecordValue":
        """Create a RecordValue containing an integer."""
        return cls(int_value=IntValueWrapper(value=value))

    @classmethod
    def from_float(cls, value: float) -> "RecordValue":
        """Create a RecordValue containing a float."""
        return cls(float_value=FloatValueWrapper(value=value))

    @classmethod
    def from_short(cls, value: int) -> "RecordValue":
        """Create a RecordValue containing a short integer."""
        return cls(short_value=ShortValueWrapper(value=value))


class ArrayOfRecordValue(BaseXmlModel, tag="ArrayOfRecordValue"):
    """
    An array of RecordValue elements.

    Used to group related values together in Sake responses.
    """

    records: list[RecordValue] = element(tag="RecordValue", default=[])

    @classmethod
    def from_ints(cls, values: list[int]) -> "ArrayOfRecordValue":
        """Create an ArrayOfRecordValue from a list of integers."""
        return cls(records=[RecordValue.from_int(v) for v in values])

    @classmethod
    def from_floats(cls, values: list[float]) -> "ArrayOfRecordValue":
        """Create an ArrayOfRecordValue from a list of floats."""
        return cls(records=[RecordValue.from_float(v) for v in values])

    @classmethod
    def from_shorts(cls, values: list[int]) -> "ArrayOfRecordValue":
        """Create an ArrayOfRecordValue from a list of short integers."""
        return cls(records=[RecordValue.from_short(v) for v in values])
