import random
import time
from typing import TypeVar

from app.models.fesl_types import (
    FeslBaseModel,
    HelloClient,
    HelloServer,
    MemcheckServer,
    DomainPartition,
    FeslHeader,
)
from app.util.logging_helper import get_logger

logger = get_logger(__name__)


class FsysFactory:

    @staticmethod
    def handle_hello(model_data: HelloClient) -> list[FeslBaseModel]:
        """
        Handle Hello request - returns both MemCheck and Hello response.
        The game expects both packets together.
        """
        assert isinstance(model_data, HelloClient)

        # MemCheck must be sent with Hello
        memcheck_response = MemcheckServer(
            txn="MemCheck", type=0, salt=random.getrandbits(32)
        )

        domain_partition = DomainPartition(domain="eagames", subDomain="CNCRA3")
        time_buff = time.strftime('"%b-%d-%Y %H:%M:%S UTC"', time.gmtime())
        hello_response = HelloServer(
            txn="Hello",
            theaterIp="0.0.0.0",
            theaterPort=0,
            messengerIp="0.0.0.0",
            messengerPort=0,
            activityTimeoutSecs=0,
            curTime=time_buff,
            domainPartition=domain_partition,
        )

        # Order matters: Hello first (uses client's packet number), then MemCheck (server-initiated, packet 0)
        return [hello_response, memcheck_response]

    @staticmethod
    def parse(header: FeslHeader, model_data: FeslBaseModel) -> FeslBaseModel | list[FeslBaseModel] | None:
        package_counter = header.packet_number
        logger.debug("Parsing TXN: %s", model_data.txn)
        match model_data.txn:
            case "Hello":
                if isinstance(model_data, HelloClient):
                    return FsysFactory.handle_hello(model_data)
            case "MemCheck":
                pass

        return None
