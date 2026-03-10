"""Automatch bot system for Kirov server emulator."""

from app.servers.automatch.coordinator import BotCoordinator

# Module-level coordinator reference, set during startup
bot_coordinator: BotCoordinator | None = None
