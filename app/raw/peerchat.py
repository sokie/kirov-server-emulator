"""
Peerchat IRC server implementation.
Implements a standard IRC server with GameSpy extensions for Red Alert 3.
"""

import asyncio
import threading
import time
from typing import Dict, Optional, List
from contextvars import ContextVar

from app.models.irc_types import (
    IRCMessage, IRCUser, IRCChannel, IRCNumeric,
    IRCCommand, GameSpyCommand, irc_client_data_var
)
from app.util.peerchat_crypt import PeerchatCipherFactory
from app.config.app_settings import app_config
from app.util.logging_helper import get_logger

logger = get_logger(__name__)


# Global state (thread-safe with locks)
irc_channels: Dict[str, IRCChannel] = {}  # channel_name -> IRCChannel
irc_clients: Dict[str, 'IRCClient'] = {}  # nickname -> IRCClient
irc_clients_lock = threading.Lock()


class IRCClient:
    """
    Represents a connected IRC client with its state and encryption.
    """

    def __init__(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, addr: tuple):
        self.reader = reader
        self.writer = writer
        self.addr = addr
        self.user = IRCUser(hostname=addr[0])

        # Encryption state (GameSpy)
        self.cipher_factory: Optional[PeerchatCipherFactory] = None
        self.send_cipher = None  # Server-to-client cipher
        self.recv_cipher = None  # Client-to-server cipher
        self.encryption_enabled = False

        # Connection state
        self.connected = True
        self.last_ping_time = time.time()
        self.last_pong_time = time.time()

    async def send_message(self, message: IRCMessage):
        """
        Send an IRC message to this client.

        Args:
            message: IRCMessage to send
        """
        try:
            line = message.serialize() + '\r\n'
            data = line.encode('utf-8')

            # Apply encryption if enabled
            if self.encryption_enabled and self.send_cipher:
                data = self.send_cipher.crypt2(data)

            self.writer.write(data)
            await self.writer.drain()
            logger.debug(f"Sent to {self.addr}: {line.strip()}")

        except Exception as e:
            logger.error(f"Error sending message to {self.addr}: {e}")
            raise

    async def send_numeric(self, code: str, *params: str, prefix: Optional[str] = None):
        """
        Send a numeric reply to this client.

        Args:
            code: Numeric reply code (e.g., '001', '433')
            params: Message parameters
            prefix: Optional server prefix
        """
        if prefix is None:
            prefix = 's'  # GameSpy uses short server name

        target = self.user.nickname or '*'
        message = IRCMessage(
            command=code,
            params=[target] + list(params),
            prefix=prefix
        )
        await self.send_message(message)

    async def broadcast_to_channel(self, channel_name: str, message: IRCMessage, exclude_self: bool = True):
        """
        Broadcast a message to all users in a channel.

        Args:
            channel_name: Channel to broadcast to
            message: Message to broadcast
            exclude_self: If True, don't send to this client
        """
        if channel_name not in irc_channels:
            return

        channel = irc_channels[channel_name]
        with irc_clients_lock:
            for nickname in channel.users:
                if exclude_self and nickname == self.user.nickname:
                    continue

                if nickname in irc_clients:
                    client = irc_clients[nickname]
                    try:
                        await client.send_message(message)
                    except Exception as e:
                        logger.error(f"Error broadcasting to {nickname}: {e}")

    def disconnect(self):
        """Mark client as disconnected."""
        self.connected = False


async def handle_irc_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    """
    Handle an IRC client connection (similar to FESL's handle_client).

    Args:
        reader: AsyncIO stream reader
        writer: AsyncIO stream writer
    """
    addr = writer.get_extra_info('peername')
    logger.info(f"IRC connection from {addr}")

    client = IRCClient(reader, writer, addr)

    # Set context variable
    client_data = {
        "address": addr,
        "writer": writer,
        "client": client
    }
    token = irc_client_data_var.set(client_data)

    # Buffer for encrypted data that may contain multiple commands
    data_buffer = b''

    try:
        while client.connected:
            try:
                if client.encryption_enabled and client.recv_cipher:
                    # When encrypted, read raw bytes and decrypt
                    raw_data = await reader.read(4096)
                    if not raw_data:
                        logger.info(f"IRC client {addr} disconnected")
                        break

                    # Decrypt the data
                    try:
                        decrypted = client.recv_cipher.crypt2(raw_data)
                        data_buffer += bytes(decrypted)
                    except Exception as e:
                        logger.error(f"Error decrypting data from {addr}: {e}")
                        continue

                    # Process complete lines from buffer
                    while b'\n' in data_buffer:
                        line_bytes, data_buffer = data_buffer.split(b'\n', 1)
                        try:
                            line = line_bytes.decode('utf-8').strip()
                        except UnicodeDecodeError as e:
                            logger.error(f"Error decoding line from {addr}: {e}")
                            continue

                        if not line:
                            continue

                        logger.debug(f"Received from {addr}: {line}")

                        # Parse and handle IRC message
                        try:
                            message = IRCMessage.parse(line)
                            from app.raw.irc_factory import IRCFactory
                            await IRCFactory.handle(client, message)
                        except Exception as e:
                            logger.error(f"Error handling message from {addr}: {e}")
                else:
                    # Unencrypted: use readline()
                    line_bytes = await reader.readline()

                    if not line_bytes:
                        logger.info(f"IRC client {addr} disconnected")
                        break

                    # Decode and parse
                    try:
                        line = line_bytes.decode('utf-8').strip()
                    except UnicodeDecodeError as e:
                        logger.error(f"Error decoding line from {addr}: {e}")
                        continue

                    if not line:
                        continue

                    logger.debug(f"Received from {addr}: {line}")

                    # Parse and handle IRC message
                    try:
                        message = IRCMessage.parse(line)
                        from app.raw.irc_factory import IRCFactory
                        await IRCFactory.handle(client, message)
                    except Exception as e:
                        logger.error(f"Error handling message from {addr}: {e}")

            except asyncio.CancelledError:
                logger.info(f"IRC connection from {addr} cancelled")
                break
            except Exception as e:
                logger.error(f"Error reading from {addr}: {e}")
                break

    except Exception as e:
        logger.error(f"Error with IRC client {addr}: {e}")
    finally:
        # Cleanup
        logger.info(f"Cleaning up IRC client {addr}")
        await cleanup_client(client)

        try:
            writer.close()
            await writer.wait_closed()
        except Exception as e:
            logger.error(f"Error closing writer for {addr}: {e}")

        irc_client_data_var.reset(token)


async def cleanup_client(client: IRCClient):
    """
    Clean up client state (remove from channels, etc.).

    Args:
        client: IRCClient to clean up
    """
    if not client.user.nickname:
        return

    nickname = client.user.nickname

    # Remove from all channels
    for channel_name in list(client.user.channels):
        await part_channel(client, channel_name, reason="Client disconnected")

    # Remove from global client list
    with irc_clients_lock:
        if nickname in irc_clients:
            del irc_clients[nickname]

    logger.info(f"Cleaned up IRC client {nickname}")


async def join_channel(client: IRCClient, channel_name: str):
    """
    Add a user to a channel.

    Args:
        client: IRC client joining
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


async def part_channel(client: IRCClient, channel_name: str, reason: str = ""):
    """
    Remove a user from a channel.

    Args:
        client: IRC client leaving
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


def ping_sender(loop: asyncio.AbstractEventLoop):
    """
    Periodic ping sender thread (similar to FESL's memcheck_sender).
    Sends PING to all clients every 60 seconds and checks for timeout.
    """
    while True:
        try:
            time.sleep(60)  # Ping every 60 seconds

            logger.debug("Sending periodic PING to all IRC clients...")

            with irc_clients_lock:
                clients_to_remove: List[IRCClient] = []

                for nickname, client in list(irc_clients.items()):
                    try:
                        # Check for timeout (no PONG in 90 seconds)
                        if time.time() - client.last_pong_time > 90:
                            logger.warning(f"IRC client {nickname} timed out")
                            clients_to_remove.append(client)
                            continue

                        # Send PING
                        ping_message = IRCMessage(
                            command='PING',
                            params=['s']
                        )

                        future = asyncio.run_coroutine_threadsafe(
                            client.send_message(ping_message), loop
                        )

                        try:
                            future.result(timeout=2)
                            client.last_ping_time = time.time()
                        except asyncio.TimeoutError:
                            logger.warning(f"Timeout sending PING to {nickname}")
                            clients_to_remove.append(client)
                        except Exception as e:
                            logger.error(f"Error sending PING to {nickname}: {e}")
                            clients_to_remove.append(client)

                    except Exception as e:
                        logger.error(f"Error in ping loop for {nickname}: {e}")

                # Disconnect timed-out clients
                for client in clients_to_remove:
                    try:
                        client.disconnect()
                        asyncio.run_coroutine_threadsafe(cleanup_client(client), loop)
                    except Exception as e:
                        logger.error(f"Error disconnecting client: {e}")

        except Exception as e:
            logger.error(f"Error in ping_sender: {e}")
            time.sleep(1)


async def start_irc_server(host: str = '0.0.0.0', port: int = 6667) -> asyncio.Server:
    """
    Start the IRC server.

    Args:
        host: Host to bind to
        port: Port to bind to

    Returns:
        The asyncio.Server object for lifecycle management
    """
    server = await asyncio.start_server(handle_irc_client, host, port)

    addr = server.sockets[0].getsockname()
    logger.info(f'IRC server serving on {addr}')

    # Get the current event loop for the ping thread
    loop = asyncio.get_running_loop()

    # Start periodic ping sender in a separate thread
    ping_thread = threading.Thread(target=ping_sender, args=(loop,), daemon=True)
    ping_thread.start()
    logger.info("IRC ping sender thread started")

    return server


# --- For unit testing ---
if __name__ == "__main__":
    try:
        asyncio.run(start_irc_server())
    except KeyboardInterrupt:
        logger.info("IRC server stopped by user")
    except Exception as e:
        logger.error(f"Error running IRC server: {e}")
