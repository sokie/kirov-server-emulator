import struct
from typing import List

from app.models.fesl_types import FeslBaseModel, EntitledGameFeatureWrapper, \
    HelloServer, NuLoginServer, HelloClient, NuLoginClient, MemcheckServer, MemcheckClient, FeslType, client_data_var, \
    FeslHeader, NuGetPersonasClient, NuGetPersonasServer, NuLoginPersonaClient, NuLoginPersonaServer, \
    GameSpyPreAuthClient, GameSpyPreAuthServer, NuAddPersonaClient, NuAddPersonaServer
from app.util.logging_helper import get_logger

logger = get_logger(__name__)


def get_model_for_txn(data_dict, header):
    """
    Factory function that returns a specific data model based on the TXN value.

    Args:
        data_dict (dict): The dictionary parsed from the payload.

    Returns:
        An instance of a specific data model (e.g., Login, GetStats),
        or the original dictionary if no model is found.
    """
    txn_type = data_dict.get('TXN')
    # Use lowercase for dictionary keys to match model field names
    data_lower = {k.lower(): v for k, v in data_dict.items()}

    # Special case: MemCheck - the game client sends responses with SERVER tag (0x80)
    # but the payload contains client response fields. Detect by payload content.
    if txn_type == 'MemCheck':
        # Client response has 'result' field, server request has 'type' and 'salt'
        if 'result' in data_dict:
            return MemcheckClient.from_dict(data_dict)
        else:
            return MemcheckServer.from_dict(data_dict)

    if header.fesl_type == FeslType.TAG_SINGLE_SERVER or header.fesl_type == FeslType.TAG_MULTI_SERVER:
        match txn_type:
            case 'Hello':
                return HelloServer.from_dict(data_dict)
            case 'NuLogin':
                return NuLoginServer.from_dict(data_dict)

    elif header.fesl_type == FeslType.TAG_SINGLE_CLIENT or header.fesl_type == FeslType.TAG_MULTI_CLIENT:
        match txn_type:
            case 'Hello':
                return HelloClient.from_dict(data_dict)
            case 'NuLogin':
                return NuLoginClient.from_dict(data_dict)
            case 'NuGetPersonas':
                return NuGetPersonasClient.from_dict(data_dict)
            case 'NuLoginPersona':
                return NuLoginPersonaClient.from_dict(data_dict)
            case 'NuAddPersona':
                return NuAddPersonaClient.from_dict(data_dict)
            case 'GameSpyPreAuth':
                return GameSpyPreAuthClient.from_dict(data_dict)

    # Return the dictionary if no specific model is found
    return data_dict


def _model_to_string(model):
    """(Private) Serializes a data model to its key-value string representation."""
    logger.debug("_model_to_string: %s", model)
    if not isinstance(model, FeslBaseModel):
        raise TypeError("data_model must be an instance of a BaseModel subclass")

    return model.to_key_value_string()


def create_packet(fesl_command, fesl_type, packet_number, data_model):
    """
    Generates a complete FESL packet byte array from provided data.

    Args:
        fesl_command (str): The 4-character command (e.g., 'acct').
        fesl_type (FeslType): The type of the packet.
        packet_number (int): The packet's sequence number.
        data_model (BaseModel): An instance of a data model (e.g., Login).

    Returns:
        A bytearray containing the full packet, or None on error.
    """
    if len(fesl_command) > 4:
        logger.error("FeslCommand cannot be longer than 4 characters.")
        return None

    # 1. Serialize data model to a string, then encode to bytes with a null terminator.
    payload_string = _model_to_string(data_model)
    payload_bytes_with_null = payload_string.encode('utf-8') + b'\0'
    data_size = len(payload_bytes_with_null)

    # 2. Calculate final packet size
    packet_size = FeslHeader.HEADER_SIZE + data_size

    # 3. Construct the FeslTypeAndNumber field
    fesl_type_and_number = (fesl_type.value << 24) | packet_number

    # 4. Pack the header into bytes
    header_bytes = struct.pack(
        FeslHeader.HEADER_FORMAT,
        fesl_command.encode('utf-8'),
        fesl_type_and_number,
        packet_size
    )

    # 5. Combine header and payload into a final bytearray
    return bytearray(header_bytes + payload_bytes_with_null)


def parse_game_data(byte_array):
    """
    Parses a complete game data byte array, including header and payload.
    The payload is expected to be a key-value string with pairs separated by newlines (0x0A).

    Args:
        byte_array (bytearray): The raw byte array from the game.

    Returns:
        A tuple containing the parsed FeslHeader object and a dictionary
        of the data payload. Returns (None, None) if parsing fails.
    """
    header, expected_data_size = FeslHeader.from_bytes(byte_array)

    if not header:
        return None, None

    # Find the null terminator to determine the end of the data payload
    data_start = FeslHeader.HEADER_SIZE
    null_terminator_index = byte_array.find(b'\0', data_start)

    if null_terminator_index == -1:
        logger.warning("No null terminator found for the data payload.")
        # Attempt to extract data based on packet size as a fallback
        data_bytes = byte_array[data_start:]
    else:
        data_bytes = byte_array[data_start:null_terminator_index]

    # Note: expected_data_size includes the null terminator, but data_bytes excludes it
    # So we add 1 to account for the null terminator
    if len(data_bytes) + 1 != expected_data_size:
        logger.warning("Actual data size (%d) does not match expected data size from header (%d).",
                      len(data_bytes) + 1, expected_data_size)

    data_string = data_bytes.decode('utf-8', 'ignore')
    data_dict = {}

    if not data_string:
        return header, data_dict

    # Split the string into lines and parse key-value pairs
    lines = data_string.splitlines()

    # The first key-value pair should be the transaction type 'TXN'
    if not lines or not lines[0].startswith('TXN='):
        logger.warning("Data payload does not start with 'TXN'. Payload: \"%s\"", data_string)

    for line in lines:
        if '=' in line:
            # Split only on the first equals sign
            key, value = line.split('=', 1)
            data_dict[key] = value
        elif line:  # Handle non-empty lines that are not key-value pairs
            logger.warning("Malformed line found in data payload: '%s'", line)

        # Convert the dictionary to a specific model
    model_object = get_model_for_txn(data_dict, header)

    return header, model_object