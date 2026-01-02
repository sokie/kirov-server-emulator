import asyncio
import threading

from app.models.fesl_types import MemcheckServer, FeslType, FeslBaseModel
from app.raw.acct_factory import AcctFactory
from app.raw.fesl import create_packet, parse_game_data
from app.raw.fsys_factory import FsysFactory
from app.util.logging_helper import get_logger, format_hex

logger = get_logger(__name__)


class FeslServer(asyncio.Protocol):

    def __init__(self):
        logger.debug("Initializing")
        self.clients_lock = threading.Lock()
        self.transport = None
        self.peername = None
        self.client_data = {}

    def connection_made(self, transport):
        self.transport = transport
        self.peername = transport.get_extra_info("peername")
        logger.debug("New connection from %s", self.peername)

    def data_received(self, data):
        logger.debug("Received %d bytes from %s", len(data), self.peername)
        logger.debug("RX hex: %s", format_hex(data))

        parsed_header, parsed_model = parse_game_data(data)

        if parsed_header and parsed_model is not None:
            logger.debug("Successfully parsed header: %s", parsed_header)
            logger.debug("Data Payload: %s", parsed_model)

            if parsed_header and isinstance(parsed_model, FeslBaseModel):
                response = None
                if parsed_header.fesl_command == "fsys":
                    response = FsysFactory.parse(parsed_header, parsed_model)
                elif parsed_header.fesl_command == "acct":
                    response = AcctFactory.parse(parsed_header, parsed_model)

                if response:
                    # Handle both single responses and lists of responses
                    responses = response if isinstance(response, list) else [response]
                    for resp in responses:
                        # MemCheck is server-initiated, uses packet_number=0
                        # Other responses use the client's packet number
                        if isinstance(resp, MemcheckServer):
                            packet_num = 0
                        else:
                            packet_num = parsed_header.packet_number

                        generated_packet = create_packet(
                            parsed_header.fesl_command,
                            FeslType.TAG_SINGLE_SERVER,  # Server responses use SERVER tag
                            packet_num,
                            resp,
                        )
                        logger.debug("Sending %d bytes to %s", len(generated_packet), self.peername)
                        logger.debug("TX hex: %s", format_hex(generated_packet))
                        self.transport.write(generated_packet)  # type: ignore

    def connection_lost(self, exc):
        logger.debug("Connection closed for %s", self.peername)
