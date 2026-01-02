"""
Logging utilities for the RA3 backend server.

Provides centralized logging configuration and helper functions.
"""

import logging
import sys
from typing import Optional


def format_hex(data: bytes) -> str:
    """Format bytes as hex string for debug logging."""
    return ' '.join(f'{b:02x}' for b in data)


def get_logger(name: str, level: Optional[int] = None) -> logging.Logger:
    """
    Get a configured logger instance.

    Args:
        name: Logger name (typically __name__ or module name)
        level: Optional log level override

    Returns:
        Configured logger instance
    """
    logger = logging.getLogger(name)

    if level is not None:
        logger.setLevel(level)

    return logger


def setup_logging(level: int = logging.INFO, debug_modules: Optional[list[str]] = None) -> None:
    """
    Configure root logging for the application.

    Args:
        level: Default log level for the application
        debug_modules: List of module names to set to DEBUG level
    """
    # Create formatter
    formatter = logging.Formatter(
        fmt='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )

    # Create console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(formatter)

    # Configure root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(level)

    # Remove existing handlers to avoid duplicates
    root_logger.handlers.clear()
    root_logger.addHandler(console_handler)

    # Set debug level for specific modules if requested
    if debug_modules:
        for module in debug_modules:
            logging.getLogger(module).setLevel(logging.DEBUG)


# Module-level loggers for each component
FESL_LOGGER = 'app.raw.fesl_server'
GP_LOGGER = 'app.raw.gp_server'
ACCT_LOGGER = 'app.raw.acct_factory'
FSYS_LOGGER = 'app.raw.fsys_factory'
IRC_LOGGER = 'app.raw.irc_factory'
PEERCHAT_LOGGER = 'app.raw.peerchat'
NATNEG_LOGGER = 'app.raw.natneg_server'
NATNEG_SESSION_LOGGER = 'app.raw.natneg_session'
NATNEG_PROTOCOL_LOGGER = 'app.raw.natneg_protocol'
