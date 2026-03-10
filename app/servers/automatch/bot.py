"""Core automatch bot engine driven by GameFactory."""

import asyncio
import time

from app.models.irc_types import IRCMessage
from app.models.peerchat_state import irc_channels, irc_clients, irc_clients_lock, join_channel
from app.servers.automatch.base import BasePlayer, GameFactory
from app.servers.automatch.bot_client import BotClient
from app.servers.automatch.cinfo_parser import parse_cinfo
from app.util.logging_helper import get_logger

logger = get_logger(__name__)


class AutoMatchBot:
    """
    Automatch bot engine for a single game.

    Creates a virtual BotClient, registers it in IRC state, joins configured
    channels, and runs a background match loop.
    """

    def __init__(self, factory: GameFactory):
        self.factory = factory
        self.bot_client = BotClient(factory.nickname, factory.username)
        self.bot_client._message_handler = self._on_message
        self._players: dict[str, BasePlayer] = {}
        self._match_task: asyncio.Task | None = None
        self._running = False

    async def start(self):
        """Register bot in IRC state, join channels, start match loop."""
        logger.info(f"[{self.factory.game_id}] Starting automatch bot '{self.factory.nickname}'")

        with irc_clients_lock:
            irc_clients[self.factory.nickname] = self.bot_client

        for channel_name in self.factory.channels:
            await join_channel(self.bot_client, channel_name)
            logger.info(f"[{self.factory.game_id}] Bot joined {channel_name}")

        self._running = True
        self._match_task = asyncio.create_task(self._match_loop())
        logger.info(f"[{self.factory.game_id}] Automatch bot started")

    async def stop(self):
        """Unregister bot, cancel match loop."""
        self._running = False

        if self._match_task:
            self._match_task.cancel()
            try:
                await self._match_task
            except asyncio.CancelledError:
                pass

        for channel_name in list(self.bot_client.user.channels):
            if channel_name in irc_channels:
                channel = irc_channels[channel_name]
                channel.users.discard(self.factory.nickname)
                channel.operators.discard(self.factory.nickname)
                if self.factory.nickname in channel.user_stats:
                    del channel.user_stats[self.factory.nickname]

        self.bot_client.user.channels.clear()

        with irc_clients_lock:
            irc_clients.pop(self.factory.nickname, None)

        self.bot_client.disconnect()
        self._players.clear()
        logger.info(f"[{self.factory.game_id}] Automatch bot stopped")

    async def _on_message(self, message: IRCMessage):
        """Handle an incoming PRIVMSG to the bot."""
        if not message.prefix or len(message.params) < 2:
            return

        sender_nick = message.prefix.split("!")[0]
        text = message.params[1]

        if "\\CINFO\\" in text or text.startswith("\\CINFO"):
            await self._handle_cinfo(sender_nick, text)
        else:
            # Check for game-specific commands
            supported = self.factory.get_supported_commands()
            for cmd in supported:
                if f"\\{cmd}\\" in text or text.startswith(f"\\{cmd}") or text.strip() == f"\\{cmd}":
                    player = self._players.get(sender_nick)
                    if not player:
                        await self._send_to_player(sender_nick, f"MBOT:CANTSEND{cmd}NOW")
                        return
                    response = self.factory.handle_extra_command(cmd, player)
                    if response:
                        logger.info(f"[{self.factory.game_id}] {cmd} for {sender_nick}")
                        await self._send_to_player(sender_nick, response)
                    return

    async def _handle_cinfo(self, sender_nick: str, raw_text: str):
        """Process CINFO message: parse, validate, add to queue."""
        logger.info(f"[{self.factory.game_id}] CINFO from {sender_nick}")

        self._players.pop(sender_nick, None)

        infos = parse_cinfo(raw_text)
        if not infos:
            logger.warning(f"[{self.factory.game_id}] Empty CINFO from {sender_nick}")
            return

        num_players = int(infos.get("NumPlayers", "2"))
        if num_players not in self.factory.valid_num_players:
            logger.warning(f"[{self.factory.game_id}] Invalid NumPlayers {num_players} from {sender_nick}")
            await self._send_to_player(sender_nick, "MBOT:BADCINFO")
            return

        maps = infos.get("Maps", "")
        if not maps:
            await self._send_to_player(sender_nick, "MBOT:BADMAPS")
            return

        profile_id = 0
        with irc_clients_lock:
            real_client = irc_clients.get(sender_nick)
            if real_client and hasattr(real_client, "user") and real_client.user.profile_id:
                profile_id = real_client.user.profile_id

        player = self.factory.build_player(sender_nick, profile_id, infos)
        self._players[sender_nick] = player

        pool_size = len(self._players)
        await self._send_to_player(sender_nick, f"MBOT:WORKING {pool_size}")

        for nick in self._players:
            if nick != sender_nick:
                await self._send_to_player(nick, f"MBOT:WORKING {pool_size}")

        logger.info(f"[{self.factory.game_id}] {sender_nick} queued. Pool size: {pool_size}, NumPlayers: {num_players}")

    async def _match_loop(self):
        """Background task that periodically attempts to match players."""
        logger.info(f"[{self.factory.game_id}] Match loop started (interval: {self.factory.match_interval}s)")

        pool_announce_interval = 30.0
        next_pool_announce = time.time() + pool_announce_interval

        while self._running:
            try:
                await asyncio.sleep(self.factory.match_interval)

                if not self._players:
                    continue

                now = time.time()

                # Game-specific tick (e.g. widen timers)
                tick_messages = self.factory.on_match_loop_tick(self._players, now)
                for nick, msg in tick_messages:
                    logger.info(f"[{self.factory.game_id}] Tick message for {nick}")
                    await self._send_to_player(nick, msg)

                # Periodic pool size announcement
                if now >= next_pool_announce:
                    next_pool_announce = now + pool_announce_interval
                    pool_size = len(self._players)
                    for nick in self._players:
                        await self._send_to_player(nick, f"MBOT:POOLSIZE {pool_size}")

                # Attempt matching
                matches = self.factory.try_match(self._players)
                if matches:
                    for matched_players, matched_msg in matches:
                        for p in matched_players:
                            self._players.pop(p.nickname, None)
                        for p in matched_players:
                            await self._send_to_player(p.nickname, matched_msg)
                        names = ", ".join(p.nickname for p in matched_players)
                        logger.info(f"[{self.factory.game_id}] MATCHED: {names}")

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"[{self.factory.game_id}] Match loop error: {e}")

        logger.info(f"[{self.factory.game_id}] Match loop stopped")

    async def _send_to_player(self, nickname: str, text: str):
        """Send a PRIVMSG from bot to a real player."""
        with irc_clients_lock:
            client = irc_clients.get(nickname)

        if not client or client is self.bot_client:
            return

        try:
            msg = IRCMessage(
                command="PRIVMSG",
                params=[nickname, text],
                prefix=self.bot_client.user.get_prefix(),
            )
            await client.send_message(msg)
        except Exception as e:
            logger.error(f"[{self.factory.game_id}] Error sending to {nickname}: {e}")

    def on_player_disconnect(self, nickname: str):
        """Remove a disconnected player from the queue."""
        if nickname in self._players:
            del self._players[nickname]
            logger.info(f"[{self.factory.game_id}] Removed disconnected player: {nickname}")
