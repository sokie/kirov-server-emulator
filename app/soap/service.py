from typing import Optional
from fastapi_soap import SoapRouter, XMLBody, SoapResponse
from pydantic_xml import BaseXmlModel, element


# Request/Response models for say_hello operation
class SayHelloRequest(BaseXmlModel, tag="SayHelloRequest"):
    name: str = element(default="World")
    times: int = element(default=1)


class SayHelloResponse(BaseXmlModel, tag="SayHelloResponse"):
    message: str = element()


# Request/Response models for add_numbers operation
class AddNumbersRequest(BaseXmlModel, tag="AddNumbersRequest"):
    num1: int = element()
    num2: int = element()


class AddNumbersResponse(BaseXmlModel, tag="AddNumbersResponse"):
    result: int = element()


# Create the SOAP router
soap_router = SoapRouter(name="HelloWorldService", prefix="/api/soap")


@soap_router.operation(
    name="SayHello",
    request_model=SayHelloRequest,
    response_model=SayHelloResponse
)
def say_hello(body: SayHelloRequest = XMLBody(SayHelloRequest)):
    """
    A simple SOAP method that returns a greeting.
    """
    name = body.name if body.name else "World"
    message = f"Hello, {name * body.times}"
    return SoapResponse(SayHelloResponse(message=message))


@soap_router.operation(
    name="AddNumbers",
    request_model=AddNumbersRequest,
    response_model=AddNumbersResponse
)
def add_numbers(body: AddNumbersRequest = XMLBody(AddNumbersRequest)):
    """
    Adds two integers and returns the result.
    """
    result = body.num1 + body.num2
    return SoapResponse(AddNumbersResponse(result=result))
