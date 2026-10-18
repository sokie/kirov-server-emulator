"""
Logging utilities for the RA3 backend server.

Provides centralized logging configuration and helper functions.
"""

import logging
import sys
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import TYPE_CHECKING

from app.util.paths import get_runtime_path

if TYPE_CHECKING:
    from app.config.app_settings import LoggingSettings

_configured = False


def format_hex(data: bytes) -> str:
    """Format bytes as hex string for debug logging."""
    return " ".join(f"{b:02x}" for b in data)


def get_logger(name: str, level: int | None = None) -> logging.Logger:
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


def setup_logging(
    level: int = logging.INFO,
    debug_modules: list[str] | None = None,
    log_file: str | Path | None = None,
    max_bytes: int = 10 * 1024 * 1024,
    backup_count: int = 5,
    sql: bool = False,
) -> Path | None:
    """
    Configure root logging for the application. A second call replaces the handlers of the first.

    Args:
        level: Default log level for the application
        debug_modules: List of module names to set to DEBUG level
        log_file: Optional path for a rotating UTF-8 log file
        max_bytes: Maximum file size before rotation
        backup_count: Number of rotated files to retain
        sql: Log every SQL statement

    Returns:
        The resolved log path when file logging is enabled, otherwise None
    """
    global _configured
    # Create formatter
    formatter = logging.Formatter(fmt="%(asctime)s [%(levelname)s] %(name)s: %(message)s", datefmt="%Y-%m-%d %H:%M:%S")

    # Create console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(formatter)

    # Configure root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(level)

    # Close the handlers of an earlier call, so its log file is not left open.
    for handler in list(root_logger.handlers):
        root_logger.removeHandler(handler)
        handler.close()
    root_logger.addHandler(console_handler)

    resolved_log_file = None
    if log_file is not None:
        resolved_log_file = Path(log_file).resolve()
        resolved_log_file.parent.mkdir(parents=True, exist_ok=True)

        file_handler = RotatingFileHandler(
            resolved_log_file,
            maxBytes=max_bytes,
            backupCount=backup_count,
            encoding="utf-8",
        )
        file_handler.setFormatter(formatter)
        root_logger.addHandler(file_handler)

    # Uvicorn configures separate handlers by default. Route those records through
    # the root logger so startup errors and HTTP requests reach the same log file.
    for logger_name in ("uvicorn", "uvicorn.error", "uvicorn.access"):
        uvicorn_logger = logging.getLogger(logger_name)
        uvicorn_logger.handlers.clear()
        uvicorn_logger.propagate = True
        uvicorn_logger.setLevel(level)

    logging.getLogger("sqlalchemy.engine").setLevel(logging.INFO if sql else logging.WARNING)

    # Set debug level for specific modules if requested
    if debug_modules:
        for module in debug_modules:
            logging.getLogger(module).setLevel(logging.DEBUG)

    _configured = True
    return resolved_log_file


def configure_logging(settings: "LoggingSettings") -> Path | None:
    """
    Configure logging from the logging section of the config, if nothing has configured it yet.

    A relative log file goes in the runtime directory: the executable's directory, or the working directory
    when the server runs from source. Returns the log file path, or None.
    """
    if _configured:
        return None
    log_file = None
    if settings.file:
        log_file = Path(settings.file)
        if not log_file.is_absolute():
            log_file = Path(get_runtime_path()) / log_file
    resolved_log_file = setup_logging(
        level=getattr(logging, settings.level),
        log_file=log_file,
        max_bytes=settings.max_bytes,
        backup_count=settings.backup_count,
        sql=settings.sql,
    )
    if resolved_log_file is not None:
        logging.getLogger(__name__).info("Logging to %s", resolved_log_file)
    return resolved_log_file


# Module-level loggers for each component
FESL_LOGGER = "app.raw.fesl_server"
GP_LOGGER = "app.raw.gp_server"
ACCT_LOGGER = "app.raw.acct_factory"
FSYS_LOGGER = "app.raw.fsys_factory"
IRC_LOGGER = "app.raw.irc_factory"
PEERCHAT_LOGGER = "app.raw.peerchat"
NATNEG_LOGGER = "app.raw.natneg_server"
NATNEG_SESSION_LOGGER = "app.raw.natneg_session"
NATNEG_PROTOCOL_LOGGER = "app.raw.natneg_protocol"
