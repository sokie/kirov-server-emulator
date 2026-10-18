#!/usr/bin/env python3
"""
Entry point for PyInstaller executable.
Starts the uvicorn server programmatically.
"""

import os
import sys


def main():
    # Change to executable directory for relative paths (config, database)
    if getattr(sys, "frozen", False):
        os.chdir(os.path.dirname(sys.executable))

    # Import uvicorn and app after path setup
    import logging

    import uvicorn

    from app.config.app_settings import app_config
    from app.util.logging_helper import configure_logging

    # Logging starts before the app is imported, so an error while it loads also reaches the log file.
    configure_logging(app_config.logging)
    try:
        from app.main import app
    except Exception:
        logging.getLogger(__name__).exception("The server could not load")
        raise

    # Run the server
    # Use httptools instead of h11 to avoid h11 state machine issues
    # (h11 0.16.0 has stricter state handling that can cause errors)
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=80,
        log_level=app_config.logging.level.lower(),
        log_config=None,  # keeps uvicorn from replacing the handlers configure_logging added
        http="httptools",
    )


if __name__ == "__main__":
    main()
