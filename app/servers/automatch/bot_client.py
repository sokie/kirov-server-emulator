"""Lightweight virtual IRC client for automatch bots."""

from collections.abc import Callable, Coroutine
from typing import Any

from app.models.irc_types import IRCMessage, IRCUser


class BotClient:
    """
    Virtual IRC client that duck-types as IRCClient.

    Registered in irc_clients so existing handlers (WHO, GETCKEY, NAMES, PRIVMSG)
    work without modification. Has no real socket - incoming PRIVMSGs are routed
    to a message handler callback.
    """

    def __init__(self, nickname: str, username: str, hostname: str = "*"):
        self.user = IRCUser(
            nickname=nickname,
            username=username,
            hostname=hostname,
            authenticated=True,
        )
        self.addr = ("bot", 0)
        self.connected = True
        self.last_pong_time = float("inf")  # Never timeout from ping_sender
        self.last_ping_time = float("inf")
        self.writer = None  # No real socket
        self._message_handler: Callable[[IRCMessage], Coroutine[Any, Any, None]] | None = None

    async def send_message(self, message: IRCMessage):
        """Route incoming messages to the bot's message handler."""
        if not self._message_handler or not message.params:
            return

        if message.command in ("PRIVMSG", "UTM") and not message.params[0].startswith("#"):
            await self._message_handler(message)
        elif message.command == "702" and len(message.params) >= 5 and message.params[3] == "BCAST":
            # SETCKEY broadcast: 702 <chan> <chan> <nick> BCAST \key\val...
            await self._message_handler(message)

    async def send_numeric(self, *args, **kwargs):
        """Ignore server numerics."""
        pass

    async def broadcast_to_channel(self, channel_name: str, message: IRCMessage, exclude_self: bool = True):
        """Ignore channel broadcasts directed at us."""
        pass

    def disconnect(self):
        """Mark bot as disconnected."""
        self.connected = False
