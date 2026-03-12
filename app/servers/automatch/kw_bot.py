"""Kane's Wrath automatch bot — UTM-based QMREQ/QMRES/QMRDY/QMGO protocol."""

import asyncio
import time

from app.models.irc_types import IRCMessage
from app.models.peerchat_state import irc_channels, irc_clients, irc_clients_lock, join_channel
from app.servers.automatch.bot_client import BotClient
from app.servers.automatch.games.kw import KWGameFactory, KWPlayer
from app.servers.sessions import GameSessionRegistry
from app.util.logging_helper import get_logger

logger = get_logger(__name__)

READY_TIMEOUT = 120.0

# Delay before sending QMGO after matching players.
# The game client transitions from automatch_state_handler → match_orchestrator
# when sb_updatecomplete fires (event 0x11).  qmgo_handler is ONLY registered
# by match_orchestrator's callback table.  If QMGO arrives while the client is
# still in automatch_state_handler, it's silently dropped (automatch only
# handles "QMREQ" in its UTM event processing).
#
# The transition requires a non-empty SB game list response.  The SB timer
# fires every ~30 seconds.  The FIRST SB query from a player often returns
# 0 games (their own heartbeat hasn't registered yet, or the opponent hasn't
# connected yet).  The SECOND query (30s later) finds the opponent and
# triggers the transition.  We must wait long enough for the slowest
# player's SB timer to fire and deliver a non-empty result.
QMGO_DELAY = 35.0


class KWBot:
    """
    Automatch bot for Kane's Wrath using UTM protocol.

    Flow:
    1. Player joins #GPG!2157, creates staging room, sets b_flags=s
    2. Bot detects b_flags=s → immediately sends QMREQ/ (keeps player waiting)
    3. Player sends QMRES/ Key=Value (game preferences) + QMRDY/
    4. When 2+ players are ready → Bot matches and sends QMGO/ with host's room
    """

    def __init__(self, factory: KWGameFactory):
        self.factory = factory
        self.bot_client = BotClient(factory.nickname, factory.username)
        self.bot_client._message_handler = self._on_message
        self._players: dict[str, KWPlayer] = {}  # nick -> player (got QMREQ/)
        self._staging_rooms: dict[str, str] = {}  # nick -> staging room name
        self._ready: set[str] = set()  # nicks that sent QMRDY/
        self._ready_at: dict[str, float] = {}  # nick -> time became ready
        self._match_task: asyncio.Task | None = None
        self._running = False

    async def start(self):
        """Register bot in IRC state, join channels, start match loop."""
        logger.info(f"[{self.factory.game_id}] Starting KW automatch bot '{self.factory.nickname}'")

        with irc_clients_lock:
            irc_clients[self.factory.nickname] = self.bot_client

        for channel_name in self.factory.channels:
            await join_channel(self.bot_client, channel_name)
            logger.info(f"[{self.factory.game_id}] Bot joined {channel_name}")

        self._running = True
        self._match_task = asyncio.create_task(self._match_loop())
        logger.info(f"[{self.factory.game_id}] KW automatch bot started")

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
        self._staging_rooms.clear()
        self._ready.clear()
        self._ready_at.clear()
        logger.info(f"[{self.factory.game_id}] KW automatch bot stopped")

    # ── Match loop ──────────────────────────────────────────────────────────

    async def _match_loop(self):
        """Periodically check for ready players and clean up timeouts."""
        logger.info(f"[{self.factory.game_id}] Match loop started (interval: {self.factory.match_interval}s)")

        while self._running:
            try:
                await asyncio.sleep(self.factory.match_interval)
                self._check_timeouts()

                # Try matching ready players (fallback for race conditions)
                if len(self._ready) >= 2:
                    await self._try_match_ready()

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"[{self.factory.game_id}] Match loop error: {e}")

        logger.info(f"[{self.factory.game_id}] Match loop stopped")

    # ── Message handling ──────────────────────────────────────────────────

    async def _on_message(self, message: IRCMessage):
        """Handle incoming messages: UTM (QMRES/QMRDY) and 702 BCAST (b_flags)."""
        if message.command == "702" and len(message.params) >= 5 and message.params[3] == "BCAST":
            await self._handle_ckey_broadcast(message)
            return

        if not message.prefix or len(message.params) < 2:
            return

        sender = message.prefix.split("!")[0]
        text = message.params[1]

        if text.startswith("QMRES/ "):
            self._handle_qmres(sender, text)
        elif text.strip() == "QMRDY/":
            await self._handle_qmrdy(sender)

    async def _handle_ckey_broadcast(self, message: IRCMessage):
        """React instantly to SETCKEY broadcasts — detect b_flags=s and send QMREQ/."""
        channel_name = message.params[0]
        if channel_name != self.factory.channels[0]:
            return

        nick = message.params[2]
        if nick == self.factory.nickname:
            return

        # Parse \key\val\key\val... from the broadcast
        raw = message.params[4]
        parts = raw.split("\\")
        keys: dict[str, str] = {}
        i = 1  # skip leading empty string from \key\val
        while i + 1 < len(parts):
            keys[parts[i]] = parts[i + 1]
            i += 2

        if "b_flags" not in keys:
            return

        b_flags = keys["b_flags"]
        if "s" not in b_flags:
            return

        # Player just set b_flags=s — they're searching
        if nick in self._players:
            return  # already got QMREQ/

        logger.info(f"[{self.factory.game_id}] Detected {nick} searching (b_flags={b_flags})")

        # Build player from channel keys
        channel = irc_channels.get(channel_name)
        if not channel:
            return
        all_keys = channel.user_stats.get(nick, {})

        profile_id = 0
        # No lock — we're already inside broadcast_to_channel which holds irc_clients_lock
        client = irc_clients.get(nick)
        if client and hasattr(client, "user") and client.user.profile_id:
            profile_id = client.user.profile_id

        player = self.factory.build_player(nick, profile_id, all_keys)

        # Capture staging room while player is still in it
        staging_room = None
        if client and hasattr(client, "user"):
            for ch in client.user.channels:
                if ch.startswith("#GSP!cc3xp1!"):
                    staging_room = ch
                    break

        self._players[nick] = player
        if staging_room:
            self._staging_rooms[nick] = staging_room
            logger.info(f"[{self.factory.game_id}] Captured staging room for {nick}: {staging_room}")

        # Send QMREQ/ immediately — must arrive BEFORE the player PARTs their
        # staging room, so we write directly to the client socket instead of
        # deferring via create_task. Safe because we already have the client
        # reference and send_message just writes to the socket (no lock needed).
        if client and client is not self.bot_client:
            try:
                msg = IRCMessage(
                    command="UTM",
                    params=[nick, "QMREQ/"],
                    prefix=self.bot_client.user.get_prefix(),
                )
                await client.send_message(msg)
                logger.info(f"[{self.factory.game_id}] Sent QMREQ/ to {nick}")
            except Exception as e:
                logger.error(f"[{self.factory.game_id}] Error sending QMREQ/ to {nick}: {e}")

    def _handle_qmres(self, nick: str, text: str):
        """Handle QMRES/ Key=Value — player sending game preferences after QMREQ/."""
        player = self._players.get(nick)
        if not player:
            return

        # Parse "QMRES/ Key=Value"
        kv_part = text[len("QMRES/ ") :]
        if "=" not in kv_part:
            return
        key, _, value = kv_part.partition("=")
        key = key.strip()
        value = value.strip()

        # Apply to player
        if key == "Faction":
            player.faction = int(value)
        elif key == "Color":
            player.color = int(value)
        elif key == "IP":
            player.ip = int(value)
        elif key == "NAT":
            player.nat = int(value)
        elif key == "Rank":
            player.points = max(1, int(value))
        elif key == "ProfileID":
            player.profile_id = int(value)
        elif key == "BroadcastEnabled":
            player.broadcast_enabled = int(value)

        logger.debug(f"[{self.factory.game_id}] QMRES/ from {nick}: {key}={value}")

    async def _handle_qmrdy(self, nick: str):
        """Handle QMRDY/ — player confirms ready to start."""
        if nick not in self._players:
            return

        self._ready.add(nick)
        self._ready_at[nick] = time.time()

        logger.info(f"[{self.factory.game_id}] QMRDY/ from {nick} (ready: {len(self._ready)})")

        # Try to match if we have enough ready players
        if len(self._ready) >= 2:
            await self._try_match_ready()

    # ── Matching & game start ─────────────────────────────────────────────

    async def _try_match_ready(self):
        """Match ready players and send QMGO/."""
        ready_players = {nick: self._players[nick] for nick in self._ready if nick in self._players}
        if len(ready_players) < 2:
            return

        matches = self.factory.find_matches(ready_players)
        if not matches:
            return

        for matched_players, _map_index in matches:
            await self._start_game(matched_players)

    async def _start_game(self, players: list[KWPlayer]):
        """Send QMGO/ to each player with the host's staging room."""
        # First player is the host. All players receive QMGO/ with the host's
        # staging room name so they know which room to JOIN for the game.
        host = players[0]
        host_room = self._staging_rooms.get(host.nickname)
        if not host_room:
            logger.warning(f"[{self.factory.game_id}] No staging room for host {host.nickname}")
            return

        # Remove players from ready set NOW so _match_loop can't re-match them
        # during the QMGO_DELAY sleep.
        for p in players:
            self._ready.discard(p.nickname)
            self._ready_at.pop(p.nickname, None)

        # Wait for game clients to transition from automatch_state_handler to
        # match_orchestrator.  qmgo_handler is only registered in
        # match_orchestrator's callback table; sending QMGO too early causes
        # automatch_state_handler to silently drop it.
        #
        # Phase 1: Wait until both players' cc3xp1am heartbeats are in the
        # GameSessionRegistry (so the SB query will find the opponent).
        # Phase 2: Wait for the SB timer to fire and deliver the game list.
        await self._wait_for_sb_transition(players)

        for p in players:
            with irc_clients_lock:
                client = irc_clients.get(p.nickname)
            if not client or client is self.bot_client:
                logger.warning(f"[{self.factory.game_id}] Client not found for {p.nickname}")
                continue

            # Send QMGO as a CHANNEL UTM targeting the player's staging room.
            # The game's irc_handle_utm_receive (0x009b22e6) dispatches channel
            # UTMs through the channel struct handler → callback table, where
            # match_orchestrator registered qmgo_handler at index 9.
            # Private UTMs (target=nickname) go through param_1+0x980 → event
            # queue as event 0x10, which match_orchestrator does NOT process.
            player_room = self._staging_rooms.get(p.nickname, host_room)
            try:
                msg = IRCMessage(
                    command="UTM",
                    params=[player_room, f"QMGO/ {host_room}"],
                    prefix=self.bot_client.user.get_prefix(),
                )
                await client.send_message(msg)
                logger.info(
                    f"[{self.factory.game_id}] Sent QMGO/ to {p.nickname} "
                    f"via channel {player_room} (host room: {host_room})"
                )
            except Exception as e:
                logger.error(f"[{self.factory.game_id}] Error sending QMGO/ to {p.nickname}: {e}")

        # Notify lobby
        await self._send_channel_utm(self.factory.channels[0], "QM:STARTINGGAME")

        # Clean up matched players
        names = ", ".join(p.nickname for p in players)
        for p in players:
            self._cleanup_player(p.nickname)

        logger.info(f"[{self.factory.game_id}] MATCHED: {names}")

    def _cleanup_player(self, nick: str):
        """Remove player from all tracking state."""
        self._players.pop(nick, None)
        self._staging_rooms.pop(nick, None)
        self._ready.discard(nick)
        self._ready_at.pop(nick, None)

    # ── SB transition waiting ────────────────────────────────────────────

    async def _wait_for_sb_transition(self, players: list[KWPlayer]):
        """Wait until both players have likely transitioned to match_orchestrator.

        The transition requires a non-empty cc3xp1am SB response.  We first
        wait until both players' heartbeats are in the GameSessionRegistry
        (so the next SB poll will find the opponent), then wait for the SB
        timer cycle (~30s) plus a small buffer for event processing.
        """
        nicks = {p.nickname for p in players}
        registry = GameSessionRegistry.get_instance()
        gamename = "cc3xp1am"

        # Phase 1: Wait for both heartbeats in the registry (max 15s)
        start = time.time()
        max_registry_wait = 15.0
        while time.time() - start < max_registry_wait:
            games = registry.get_games(gamename=gamename)
            registered_nicks = set()
            for g in games:
                for pi in (g.fields.get("_players") or []):
                    if isinstance(pi, dict):
                        registered_nicks.add(pi.get("player", ""))
            if nicks.issubset(registered_nicks):
                logger.info(
                    f"[{self.factory.game_id}] Both players registered in {gamename} "
                    f"registry ({time.time() - start:.1f}s)"
                )
                break
            await asyncio.sleep(2.0)
        else:
            logger.warning(
                f"[{self.factory.game_id}] Not all players found in {gamename} registry "
                f"after {max_registry_wait}s — proceeding anyway"
            )

        # Phase 2: Wait for SB timer to deliver opponent's game list + transition
        elapsed = time.time() - start
        remaining = max(0.0, QMGO_DELAY - elapsed)
        logger.info(
            f"[{self.factory.game_id}] Waiting {remaining:.1f}s more for SB transition "
            f"(total elapsed: {elapsed:.1f}s)"
        )
        if remaining > 0:
            await asyncio.sleep(remaining)

    # ── Timeout handling ────────────────────────────────────────────────────

    def _check_timeouts(self):
        """Remove players who have been ready too long without being matched."""
        now = time.time()
        expired = [nick for nick, t in self._ready_at.items() if now - t > READY_TIMEOUT]
        for nick in expired:
            self._cleanup_player(nick)
            logger.warning(f"[{self.factory.game_id}] Player {nick} timed out waiting for match")

    # ── Message sending ─────────────────────────────────────────────────────

    async def _send_utm(self, nickname: str, text: str):
        """Send a UTM message from bot to a player."""
        with irc_clients_lock:
            client = irc_clients.get(nickname)

        if not client or client is self.bot_client:
            return

        try:
            msg = IRCMessage(
                command="UTM",
                params=[nickname, text],
                prefix=self.bot_client.user.get_prefix(),
            )
            await client.send_message(msg)
        except Exception as e:
            logger.error(f"[{self.factory.game_id}] Error sending UTM to {nickname}: {e}")

    async def _send_channel_utm(self, channel_name: str, text: str):
        """Broadcast a UTM message to all channel members."""
        channel = irc_channels.get(channel_name)
        if not channel:
            return

        msg = IRCMessage(
            command="UTM",
            params=[channel_name, text],
            prefix=self.bot_client.user.get_prefix(),
        )

        for nick in channel.users:
            if nick == self.factory.nickname:
                continue
            with irc_clients_lock:
                client = irc_clients.get(nick)
            if client:
                try:
                    await client.send_message(msg)
                except Exception as e:
                    logger.warning(f"[{self.factory.game_id}] Error broadcasting to {nick}: {e}")

    # ── Cleanup ─────────────────────────────────────────────────────────────

    def on_player_disconnect(self, nickname: str):
        """Remove disconnected player from all state."""
        self._cleanup_player(nickname)
        logger.info(f"[{self.factory.game_id}] Removed disconnected player: {nickname}")
