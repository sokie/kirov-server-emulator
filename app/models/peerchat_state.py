"""
Shared state for Peerchat IRC server.

This module contains the global state (channels, clients, locks) and
helper functions used by both peerchat_server.py and peerchat_handlers.py.
Extracted to break circular import between those modules.
"""

import threading
from typing import Any

from app.models.irc_types import IRCChannel
from app.util.logging_helper import get_logger

logger = get_logger(__name__)


# Global state (thread-safe with locks)
irc_channels: dict[str, IRCChannel] = {}  # channel_name -> IRCChannel
irc_clients: dict[str, Any] = {}  # nickname -> IRCClient (Any to avoid circular import)
irc_clients_lock = threading.Lock()


async def join_channel(client, channel_name: str):
    """
    Add a user to a channel.

    Args:
        client: IRC client joining (IRCClient instance)
        channel_name: Channel name to join
    """
    # Create channel if it doesn't exist
    if channel_name not in irc_channels:
        irc_channels[channel_name] = IRCChannel(name=channel_name)
        logger.info(f"Created new channel: {channel_name}")

    channel = irc_channels[channel_name]

    # Add user to channel
    channel.users.add(client.user.nickname)
    client.user.channels.add(channel_name)

    # First user becomes operator
    if len(channel.users) == 1:
        channel.operators.add(client.user.nickname)
        logger.info(f"{client.user.nickname} is now operator of {channel_name}")

    # Initialize user stats for this channel (GameSpy)
    if client.user.nickname not in channel.user_stats:
        channel.user_stats[client.user.nickname] = {}

    logger.info(f"{client.user.nickname} joined {channel_name}")


async def part_channel(client, channel_name: str, reason: str = ""):
    """
    Remove a user from a channel.

    Args:
        client: IRC client leaving (IRCClient instance)
        channel_name: Channel name to leave
        reason: Optional part reason
    """
    if channel_name not in irc_channels:
        return

    channel = irc_channels[channel_name]

    # Remove user
    channel.users.discard(client.user.nickname)
    channel.operators.discard(client.user.nickname)
    client.user.channels.discard(channel_name)

    # Remove user stats
    if client.user.nickname in channel.user_stats:
        del channel.user_stats[client.user.nickname]

    # Delete empty private channels (GameSpy lobbies)
    if len(channel.users) == 0 and channel.is_private():
        del irc_channels[channel_name]
        logger.info(f"Deleted empty private channel: {channel_name}")
