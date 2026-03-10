"""Parse CINFO key-value messages from automatch clients."""


def parse_cinfo(message: str) -> dict[str, str]:
    """
    Parse a CINFO message into a key-value dictionary.

    Input format: \\CINFO\\key1\\value1\\key2\\value2...
    The message may or may not have a leading backslash.

    Returns:
        Dict of key-value pairs from the CINFO message.
    """
    # Strip the \\CINFO prefix if present
    if message.startswith("\\CINFO"):
        message = message[6:]

    # Split on backslash, skip empty first element
    tokens = message.split("\\")
    tokens = [t for t in tokens if t]

    # Pair up keys and values
    return dict(zip(tokens[::2], tokens[1::2]))
