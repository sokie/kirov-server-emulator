"""
SOAP envelope helpers for wrapping and parsing SOAP messages.

This module provides utilities to wrap pydantic_xml models in SOAP envelopes
and parse SOAP request bodies into pydantic_xml models.
"""

import xml.etree.ElementTree as ET
from typing import TypeVar

from pydantic_xml import BaseXmlModel

# Namespace definitions
SOAP_NS = "http://schemas.xmlsoap.org/soap/envelope/"
XSI_NS = "http://www.w3.org/2001/XMLSchema-instance"
XSD_NS = "http://www.w3.org/2001/XMLSchema"

T = TypeVar("T", bound=BaseXmlModel)


def wrap_soap_envelope(body_content: BaseXmlModel) -> str:
    """
    Wrap a pydantic_xml model in a SOAP envelope.

    Args:
        body_content: A pydantic_xml model instance to wrap.

    Returns:
        Complete SOAP envelope as an XML string.
    """
    body_xml = body_content.to_xml(encoding="unicode")
    return (
        '<?xml version="1.0" encoding="utf-8"?>'
        '<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" '
        'xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" '
        'xmlns:xsd="http://www.w3.org/2001/XMLSchema">'
        f"<soap:Body>{body_xml}</soap:Body>"
        "</soap:Envelope>"
    )


def wrap_soap_envelope_raw(body_content: str) -> str:
    """
    Wrap raw XML string content in a SOAP envelope.

    Args:
        body_content: Raw XML string to wrap.

    Returns:
        Complete SOAP envelope as an XML string.
    """
    return (
        '<?xml version="1.0" encoding="utf-8"?>'
        '<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" '
        'xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" '
        'xmlns:xsd="http://www.w3.org/2001/XMLSchema">'
        f"<soap:Body>{body_content}</soap:Body>"
        "</soap:Envelope>"
    )


def extract_soap_body(xml_content: str | bytes) -> ET.Element:
    """
    Extract the operation element from a SOAP envelope body.

    Args:
        xml_content: The raw SOAP envelope XML.

    Returns:
        The first child element inside the SOAP Body.

    Raises:
        ValueError: If SOAP Body or operation is not found.
    """
    if isinstance(xml_content, bytes):
        xml_content = xml_content.decode("utf-8")

    root = ET.fromstring(xml_content)

    # Find the Body element
    body = None
    for child in root:
        tag = child.tag.split("}")[-1] if "}" in child.tag else child.tag
        if tag == "Body":
            body = child
            break

    if body is None:
        raise ValueError("SOAP Body not found")

    # Get the first child of Body (the operation element)
    operation = None
    for child in body:
        operation = child
        break

    if operation is None:
        raise ValueError("SOAP operation not found in Body")

    return operation


def get_operation_name(operation: ET.Element) -> str:
    """
    Extract the operation name from an operation element.

    Args:
        operation: The operation element from SOAP Body.

    Returns:
        The operation name without namespace prefix.
    """
    tag = operation.tag
    return tag.split("}")[-1] if "}" in tag else tag


def parse_soap_body(xml_content: str | bytes, model_class: type[T]) -> T:
    """
    Extract SOAP body and parse with a pydantic_xml model.

    Args:
        xml_content: The raw SOAP envelope XML.
        model_class: The pydantic_xml model class to parse into.

    Returns:
        An instance of the model class populated with parsed data.

    Raises:
        ValueError: If SOAP Body is not found or parsing fails.
    """
    operation = extract_soap_body(xml_content)

    # Convert the operation element back to XML string for pydantic_xml
    operation_xml = ET.tostring(operation, encoding="unicode")

    return model_class.from_xml(operation_xml)


def get_element_text(element: ET.Element, tag: str) -> str:
    """
    Get text content of a child element by tag name.

    Args:
        element: Parent element to search in.
        tag: Tag name to find (without namespace).

    Returns:
        The text content of the found element, or empty string if not found.
    """
    for child in element:
        child_tag = child.tag.split("}")[-1] if "}" in child.tag else child.tag
        if child_tag == tag:
            return child.text or ""
    return ""


def create_soap_fault(fault_string: str, fault_code: str = "soap:Server") -> str:
    """
    Create a SOAP fault response.

    Args:
        fault_string: The error message.
        fault_code: The fault code (default: soap:Server).

    Returns:
        Complete SOAP fault envelope as an XML string.
    """
    return wrap_soap_envelope_raw(
        f"<soap:Fault><faultcode>{fault_code}</faultcode><faultstring>{fault_string}</faultstring></soap:Fault>"
    )
