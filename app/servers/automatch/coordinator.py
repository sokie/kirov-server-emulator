"""Coordinates all automatch bot instances."""

from typing import Any

from app.servers.automatch.base import GameFactory
from app.util.logging_helper import get_logger

logger = get_logger(__name__)


class BotCoordinator:
    """Manages all automatch bots across all games."""

    def __init__(self):
        self._bots: dict[str, Any] = {}  # game_id -> bot instance

    async def start(self, factories: list[GameFactory]):
        """Start all configured bots."""
        for factory in factories:
            bot = factory.create_bot()
            self._bots[factory.game_id] = bot
            await bot.start()

        logger.info(f"BotCoordinator started {len(self._bots)} bot(s)")

    async def stop(self):
        """Stop all bots."""
        for bot in self._bots.values():
            await bot.stop()

        self._bots.clear()
        logger.info("BotCoordinator stopped all bots")

    async def enable_bot(self, game_id: str):
        """Start a specific bot by game_id."""
        bot = self._bots.get(game_id)
        if bot:
            await bot.start()

    async def disable_bot(self, game_id: str):
        """Stop a specific bot by game_id."""
        bot = self._bots.get(game_id)
        if bot:
            await bot.stop()

    def on_player_disconnect(self, nickname: str):
        """Notify all bots that a player disconnected."""
        for bot in self._bots.values():
            bot.on_player_disconnect(nickname)
