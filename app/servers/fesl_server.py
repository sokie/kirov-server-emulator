"""
FESL Server - EA Frontend Server Layer Server.

Handles the FESL protocol for Red Alert 3 authentication and account management.
This module combines the server protocol handler with packet parsing/serialization.
"""

import asyncio
import random
import struct
import threading
import time

from app.models.fesl_types import (
    CLIENT_STRING_MAP,
    AddSubAccountClient,
    FeslBaseModel,
    FeslErrorResponse,
    FeslHeader,
    FeslType,
    GameSpyPreAuthClient,
    GetSubAccountsClient,
    HelloClient,
    HelloServer,
    LoginClient,
    LoginSubAccountClient,
    MemcheckClient,
    MemcheckServer,
    NuAddPersonaClient,
    NuGetPersonasClient,
    NuLoginClient,
    NuLoginPersonaClient,
    NuLoginServer,
    client_data_var,
)
from app.servers.fesl_handlers import FeslHandlers
from app.util.logging_helper import format_hex, get_logger

logger = get_logger(__name__)

# =============================================================================
# Global Client Tracking
# =============================================================================

# Global dictionary of connected FESL clients: peername -> FeslServer instance
fesl_clients: dict[tuple, "FeslServer"] = {}
fesl_clients_lock = threading.Lock()

# MemCheck interval in seconds (send periodic MemCheck to keep sessions alive)
# TODO: client disconnects after 4 minutes of inactivity, so this can be 2 minutes also?
MEMCHECK_INTERVAL = 60  # 1 minute


# =============================================================================
# Packet Parsing
# =============================================================================


def get_model_for_txn(data_dict: dict, header: FeslHeader):
    """
    Factory function that returns a specific data model based on the TXN value.

    Args:
        data_dict: The dictionary parsed from the payload.
        header: The FESL packet header.

    Returns:
        An instance of a specific data model (e.g., HelloClient, NuLoginClient),
        or the original dictionary if no model is found.
    """
    txn_type = data_dict.get("TXN")

    # Special case: MemCheck - the game client sends responses with SERVER tag (0x80)
    # but the payload contains client response fields. Detect by payload content.
    if txn_type == "MemCheck":
        # Client response has 'result' field, server request has 'type' and 'salt'
        if "result" in data_dict:
            return MemcheckClient.from_dict(data_dict)
        else:
            return MemcheckServer.from_dict(data_dict)

    if header.fesl_type == FeslType.TAG_SINGLE_SERVER or header.fesl_type == FeslType.TAG_MULTI_SERVER:
        match txn_type:
            case "Hello":
                return HelloServer.from_dict(data_dict)
            case "NuLogin":
                return NuLoginServer.from_dict(data_dict)

    elif header.fesl_type == FeslType.TAG_SINGLE_CLIENT or header.fesl_type == FeslType.TAG_MULTI_CLIENT:
        match txn_type:
            case "Hello":
                return HelloClient.from_dict(data_dict)
            case "NuLogin":
                return NuLoginClient.from_dict(data_dict)
            case "Login":
                return LoginClient.from_dict(data_dict)
            case "NuGetPersonas":
                return NuGetPersonasClient.from_dict(data_dict)
            case "GetSubAccounts":
                return GetSubAccountsClient.from_dict(data_dict)
            case "NuLoginPersona":
                return NuLoginPersonaClient.from_dict(data_dict)
            case "LoginSubAccount":
                return LoginSubAccountClient.from_dict(data_dict)
            case "NuAddPersona":
                return NuAddPersonaClient.from_dict(data_dict)
            case "AddSubAccount":
                return AddSubAccountClient.from_dict(data_dict)
            case "GameSpyPreAuth":
                return GameSpyPreAuthClient.from_dict(data_dict)

    # Return the dictionary if no specific model is found
    return data_dict


def _model_to_string(model: FeslBaseModel | FeslErrorResponse) -> str:
    """Serializes a data model to its key-value string representation."""
    logger.debug("_model_to_string: %s", model)
    if not isinstance(model, (FeslBaseModel, FeslErrorResponse)):
        raise TypeError("data_model must be an instance of a BaseModel or FeslErrorResponse subclass")

    return model.to_key_value_string()


def create_packet(
    fesl_command: str, fesl_type: FeslType, packet_number: int, data_model: FeslBaseModel | FeslErrorResponse
) -> bytearray | None:
    """
    Generates a complete FESL packet byte array from provided data.

    Args:
        fesl_command: The 4-character command (e.g., 'acct', 'fsys').
        fesl_type: The type of the packet.
        packet_number: The packet's sequence number.
        data_model: An instance of a data model (e.g., HelloServer).

    Returns:
        A bytearray containing the full packet, or None on error.
    """
    if len(fesl_command) > 4:
        logger.error("FeslCommand cannot be longer than 4 characters.")
        return None

    # 1. Serialize data model to a string, then encode to bytes with a null terminator.
    payload_string = _model_to_string(data_model)
    payload_bytes_with_null = payload_string.encode("utf-8") + b"\0"
    data_size = len(payload_bytes_with_null)

    # 2. Calculate final packet size
    packet_size = FeslHeader.HEADER_SIZE + data_size

    # 3. Construct the FeslTypeAndNumber field
    fesl_type_and_number = (fesl_type.value << 24) | packet_number

    # 4. Pack the header into bytes
    header_bytes = struct.pack(
        FeslHeader.HEADER_FORMAT, fesl_command.encode("utf-8"), fesl_type_and_number, packet_size
    )

    # 5. Combine header and payload into a final bytearray
    return bytearray(header_bytes + payload_bytes_with_null)


def parse_game_data(byte_array: bytes):
    """
    Parses a complete game data byte array, including header and payload.
    The payload is expected to be a key-value string with pairs separated by newlines.

    Args:
        byte_array: The raw byte array from the game.

    Returns:
        A tuple containing the parsed FeslHeader object and a model object.
        Returns (None, None) if parsing fails.
    """
    header, expected_data_size = FeslHeader.from_bytes(byte_array)

    if not header:
        return None, None

    # Find the null terminator to determine the end of the data payload
    data_start = FeslHeader.HEADER_SIZE
    null_terminator_index = byte_array.find(b"\0", data_start)

    if null_terminator_index == -1:
        logger.warning("No null terminator found for the data payload.")
        # Attempt to extract data based on packet size as a fallback
        data_bytes = byte_array[data_start:]
    else:
        data_bytes = byte_array[data_start:null_terminator_index]

    # Note: expected_data_size includes the null terminator, but data_bytes excludes it
    if len(data_bytes) + 1 != expected_data_size:
        logger.warning(
            "Actual data size (%d) does not match expected data size from header (%d).",
            len(data_bytes) + 1,
            expected_data_size,
        )

    data_string = data_bytes.decode("utf-8", "ignore")
    data_dict = {}

    if not data_string:
        return header, data_dict

    # Split the string into lines and parse key-value pairs
    lines = data_string.splitlines()

    # The first key-value pair should be the transaction type 'TXN'
    if not lines or not lines[0].startswith("TXN="):
        logger.warning("Data payload does not start with 'TXN'. Payload: \"%s\"", data_string)

    for line in lines:
        if "=" in line:
            # Split only on the first equals sign
            key, value = line.split("=", 1)
            data_dict[key] = value
        elif line:  # Handle non-empty lines that are not key-value pairs
            logger.warning("Malformed line found in data payload: '%s'", line)

    # Convert the dictionary to a specific model
    model_object = get_model_for_txn(data_dict, header)

    return header, model_object


# =============================================================================
# Server Protocol
# =============================================================================


class FeslServer(asyncio.Protocol):
    """
    FESL TCP Server Protocol handler.

    Handles the FESL protocol for authentication and account management:
    - fsys: Hello, MemCheck (connection initialization)
    - acct: NuLogin, NuGetPersonas, NuLoginPersona, GameSpyPreAuth
    """

    def __init__(self):
        logger.debug("Initializing")
        self.transport = None
        self.peername = None
        self.client_data = {}
        self.active_game = None
        self.last_memcheck_time = time.time()

    def connection_made(self, transport):
        self.transport = transport
        self.peername = transport.get_extra_info("peername")
        logger.debug("New connection from %s", self.peername)

        # Register client in global tracking
        with fesl_clients_lock:
            fesl_clients[self.peername] = self
            logger.debug("Registered FESL client %s (total: %d)", self.peername, len(fesl_clients))

    def data_received(self, data):
        logger.debug("Received %d bytes from %s", len(data), self.peername)
        logger.debug("RX hex: %s", format_hex(data))

        parsed_header, parsed_model = parse_game_data(data)

        if parsed_header and parsed_model is not None:
            logger.debug("Successfully parsed header: %s", parsed_header)
            logger.debug("Data Payload: %s", parsed_model)

            if parsed_header and isinstance(parsed_model, FeslBaseModel):
                # Detect game type from Hello packet's clientString
                if isinstance(parsed_model, HelloClient) and parsed_model.clientString:
                    self.active_game = CLIENT_STRING_MAP.get(parsed_model.clientString)
                    self.client_data["active_game"] = self.active_game
                    logger.debug(
                        "Detected game type: %s (clientString=%s)", self.active_game, parsed_model.clientString
                    )

                # Set client_data context for handlers
                client_data_var.set(self.client_data)

                response = FeslHandlers.parse(parsed_header, parsed_model)

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
                        self.transport.write(generated_packet)

    def connection_lost(self, exc):
        logger.debug("Connection closed for %s", self.peername)

        # Unregister client from global tracking
        with fesl_clients_lock:
            if self.peername in fesl_clients:
                del fesl_clients[self.peername]
                logger.debug("Unregistered FESL client %s (total: %d)", self.peername, len(fesl_clients))

    def send_memcheck(self):
        """Send a MemCheck packet to this client."""
        if not self.transport or self.transport.is_closing():
            return False

        memcheck = MemcheckServer(txn="MemCheck", type=0, salt=random.getrandbits(32))
        packet = create_packet("fsys", FeslType.TAG_SINGLE_SERVER, 0, memcheck)

        if packet:
            logger.debug("Sending periodic MemCheck to %s", self.peername)
            logger.debug("TX hex: %s", format_hex(packet))
            self.transport.write(packet)
            self.last_memcheck_time = time.time()
            return True
        return False


# =============================================================================
# Periodic MemCheck Sender
# =============================================================================


def memcheck_sender(loop: asyncio.AbstractEventLoop):
    """
    Periodic MemCheck sender thread.
    Sends MemCheck to all connected FESL clients to keep sessions alive.
    Similar to the IRC ping_sender pattern.
    """
    while True:
        try:
            time.sleep(MEMCHECK_INTERVAL)

            logger.debug("Sending periodic MemCheck to all FESL clients...")

            with fesl_clients_lock:
                clients_to_remove: list[FeslServer] = []

                for peername, client in list(fesl_clients.items()):
                    try:
                        # Send MemCheck using thread-safe method
                        future = asyncio.run_coroutine_threadsafe(_send_memcheck_async(client), loop)

                        try:
                            success = future.result(timeout=5)
                            if not success:
                                logger.warning("Failed to send MemCheck to %s", peername)
                                clients_to_remove.append(client)
                        except TimeoutError:
                            logger.warning("Timeout sending MemCheck to %s", peername)
                            clients_to_remove.append(client)

                    except Exception as e:
                        logger.error("Error in memcheck loop for %s: %s", peername, e)

                # Close connections for failed clients
                for client in clients_to_remove:
                    try:
                        if client.transport and not client.transport.is_closing():
                            client.transport.close()
                    except Exception as e:
                        logger.error("Error closing client connection: %s", e)

        except Exception as e:
            logger.error("Error in memcheck_sender: %s", e)
            time.sleep(1)


async def _send_memcheck_async(client: FeslServer) -> bool:
    """Async wrapper to send MemCheck from the main event loop."""
    return client.send_memcheck()


# =============================================================================
# Server Startup
# =============================================================================


async def start_fesl_server(host: str, port: int) -> asyncio.Server:
    """
    Start the FESL server.

    Args:
        host: Host address to bind to
        port: Port to listen on

    Returns:
        The asyncio server instance
    """
    loop = asyncio.get_running_loop()
    server = await loop.create_server(lambda: FeslServer(), host, port)
    logger.info("FESL server listening on %s:%d", host, port)

    # Start the periodic MemCheck sender thread
    memcheck_thread = threading.Thread(target=memcheck_sender, args=(loop,), daemon=True, name="FESL-MemCheck-Sender")
    memcheck_thread.start()
    logger.info("Started FESL MemCheck sender thread (interval: %ds)", MEMCHECK_INTERVAL)

    return server
