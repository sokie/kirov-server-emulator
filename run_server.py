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
    import uvicorn

    from app.main import app

    # Run the server
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=80,
        log_level="info",
    )


if __name__ == "__main__":
    main()
