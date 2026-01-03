"""Path utilities for PyInstaller frozen executable support."""

import os
import sys


def is_frozen() -> bool:
    """Check if running as a PyInstaller bundle."""
    return getattr(sys, "frozen", False)


def get_base_path() -> str:
    """
    Get the base path for bundled resources (static files, etc.).

    When running as a PyInstaller bundle, this returns the temp directory
    where bundled files are extracted (sys._MEIPASS).
    When running normally, this returns the project root directory.
    """
    if is_frozen():
        return sys._MEIPASS
    # Return the project root (parent of 'app' directory)
    return os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def get_runtime_path() -> str:
    """
    Get the runtime path for user files (config, database).

    When running as a PyInstaller bundle, this returns the directory
    where the executable is located.
    When running normally, this returns the current working directory.
    """
    if is_frozen():
        return os.path.dirname(sys.executable)
    return os.getcwd()
