r"""
GameStats Server - Handles GameSpy stats protocol communications.

Port: 29920 (TCP)

This server handles game statistics reporting and retrieval using the
GameSpy stats protocol. Messages are XOR encrypted with "GameSpy3D" key.

Protocol format:
- Messages end with \final\
- All messages (except initial challenge) are XOR encrypted
- Format: \key\value\key\value\...\final\

Commands:
- auth: Game authentication (validates game credentials)
- authp: Player authentication (validates player via authtoken)
- getpd: Get profile data (returns player stats)
- setpd: Set profile data (saves player stats)
- ka: Keepalive ping-pong
"""

import asyncio
import hashlib
import json
import secrets
import string
from typing import TYPE_CHECKING

from app.db.crud import (
    create_or_update_player_stats,
    get_player_stats,
    validate_and_consume_preauth_ticket,
)
from app.db.database import create_session
from app.util.cipher import gs_chresp_num, gs_xor
from app.util.logging_helper import format_hex, get_logger

logger = get_logger(__name__)

if TYPE_CHECKING:
    pass

# Game keys for authentication
GAME_KEYS = {
    "redalert3pc": "NANOud",  # Red Alert 3 PC
    "redalert3ps3": "t9kE8q",  # Red Alert 3 PS3
}


class GameStatsServer(asyncio.Protocol):
    r"""
    GameStats Protocol Server.

    Handles GameStats protocol commands:
    - \auth\: Authenticate game
    - \authp\: Authenticate player using FESL pre-auth ticket
    - \getpd\: Get profile data (stats)
    - \setpd\: Set profile data (stats)
    - \ka\: Keepalive
    """

    def __init__(self):
        logger.debug("Initializing GameStats server protocol")
        self.transport = None
        self.peername = None
        self.buffer = b""

        # Database session (reused across all operations for this connection)
        self._db_session = None

        # Session state
        self.authenticated_game = False
        self.authenticated_player = False
        self.user_id: int | None = None
        self.persona_id: int | None = None
        self.sesskey: str | None = None
        self.server_challenge: str = ""

    @property
    def db_session(self):
        """Lazy initialization of database session."""
        if self._db_session is None:
            self._db_session = create_session()
        return self._db_session

    @db_session.setter
    def db_session(self, value):
        self._db_session = value

    def connection_made(self, transport):
        self.transport = transport
        self.peername = transport.get_extra_info("peername")
        logger.debug("GameStats: New connection from %s", self.peername)

        # Create database session for this connection
        self.db_session = create_session()

        # Generate and send initial challenge (NOT encrypted)
        self.server_challenge = self._generate_challenge()
        challenge_response = f"\\lc\\1\\challenge\\{self.server_challenge}\\id\\1\\final\\"
        response_bytes = challenge_response.encode("latin-1")
        logger.debug("GameStats: Sending challenge: %s", challenge_response)
        logger.debug("GameStats TX hex: %s", format_hex(response_bytes))
        self.transport.write(response_bytes)

    def _generate_challenge(self) -> str:
        """Generate a random challenge string - 10 characters."""
        return "".join(secrets.choice(string.ascii_uppercase + string.digits) for _ in range(10))

    def data_received(self, data):
        try:
            logger.debug("GameStats: Received %d bytes from %s", len(data), self.peername)
            logger.debug("GameStats RX hex: %s", format_hex(data))

            # Add to buffer
            self.buffer += data

            # Process complete messages (ending with \final\)
            while True:
                # Decrypt the buffer to find message boundaries
                decrypted = gs_xor(self.buffer)
                final_marker = b"\\final\\"

                final_pos = decrypted.find(final_marker)
                if final_pos == -1:
                    # No complete message yet
                    break

                # Extract the complete message (encrypted)
                message_len = final_pos + len(final_marker)
                encrypted_message = self.buffer[:message_len]
                self.buffer = self.buffer[message_len:]

                # Decrypt and process
                decrypted_message = gs_xor(encrypted_message).decode("latin-1")
                logger.debug("GameStats RX decrypted: %s", decrypted_message)

                self._process_message(decrypted_message)

        except Exception as e:
            logger.exception("GameStats: Error processing request: %s", e)
            self._send_error(str(e))

    def _process_message(self, message: str):
        """Process a single decrypted message."""
        # Parse the command from the message
        parts = message.strip().split("\\")
        if len(parts) < 2:
            self._send_error("Invalid request format")
            return

        # Find the command (first non-empty part after leading backslash)
        command = None
        for part in parts:
            if part and part != "final":
                command = part
                break

        if not command:
            self._send_error("No command found")
            return

        request_data = self._parse_request(message)
        logger.debug("GameStats: Command=%s, Data=%s", command, request_data)

        response = ""
        if command == "auth":
            response = self._handle_auth(request_data)
        elif command == "authp":
            response = self._handle_authp(request_data)
        elif command == "getpd":
            response = self._handle_getpd(request_data)
        elif command == "setpd":
            response = self._handle_setpd(request_data)
        elif command == "ka":
            response = "\\ka\\\\final\\"
        else:
            logger.debug("GameStats: Unknown command: %s", command)
            response = self._format_error(f"Unknown command: {command}", request_data.get("id", "1"))

        if response:
            self._send_response(response)

    def _parse_request(self, data: str) -> dict[str, str]:
        """Parses the GameStats request string into a dictionary."""
        parts = data.strip().split("\\")

        # Remove empty strings and 'final'
        while parts and parts[0] == "":
            parts.pop(0)
        while parts and parts[-1] == "":
            parts.pop()
        if parts and parts[-1] == "final":
            parts.pop()

        # Parse key-value pairs
        result = {}
        i = 0
        while i < len(parts):
            key = parts[i]
            if key:
                value = parts[i + 1] if i + 1 < len(parts) else ""
                result[key] = value
            i += 2

        return result

    def _format_response(self, data: dict[str, str]) -> str:
        """Formats a dictionary as a GameStats response string."""
        return "".join([f"\\{k}\\{v}" for k, v in data.items()]) + "\\final\\"

    def _format_error(self, message: str, request_id: str = "1") -> str:
        """Formats an error response."""
        return f"\\error\\\\errmsg\\{message}\\id\\{request_id}\\final\\"

    def _send_response(self, response: str):
        """Sends an encrypted response to the client."""
        if not self.transport:
            return

        logger.debug("GameStats TX (plaintext): %s", response)
        encrypted = gs_xor(response.encode("latin-1"))
        logger.debug("GameStats TX hex: %s", format_hex(encrypted))
        self.transport.write(encrypted)

    def _send_error(self, message: str):
        """Sends an error response to the client."""
        response = self._format_error(message)
        self._send_response(response)

    def _handle_auth(self, request_data: dict[str, str]) -> str:
        r"""
        Handle \auth\ command - Game authentication.

        Validates the game using MD5(gs_chresp_num(challenge) + gamekey).

        Request fields:
        - gamename: Game name (e.g., "redalert3pc")
        - response: MD5 hash for verification
        - port: Client port
        - id: Request ID

        Response fields:
        - lc: Login code (2 = success)
        - sesskey: Session key
        - proof: MD5 proof of authentication
        - id: Request ID
        """
        logger.debug("GameStats: Processing auth")

        gamename = request_data.get("gamename", "")
        client_response = request_data.get("response", "")
        request_id = request_data.get("id", "1")

        if not gamename:
            return self._format_error("Missing gamename", request_id)

        # Get the game key
        gamekey = GAME_KEYS.get(gamename.lower())
        if not gamekey:
            logger.debug("GameStats: Unknown game: %s", gamename)
            return self._format_error("Unknown game", request_id)

        # Calculate expected response: MD5(gs_chresp_num(challenge) + gamekey)
        chresp = gs_chresp_num(self.server_challenge)
        expected_response = hashlib.md5(f"{chresp}{gamekey}".encode()).hexdigest()

        logger.debug("GameStats: Challenge=%s, chresp_num=%s, gamekey=%s", self.server_challenge, chresp, gamekey)
        logger.debug("GameStats: Expected response=%s, Got=%s", expected_response, client_response)

        if client_response != expected_response:
            logger.debug("GameStats: Auth failed - response mismatch")
            return self._format_error("Invalid response", request_id)

        self.authenticated_game = True

        # Generate a session key
        sesskey = str(secrets.randbelow(999999999) + 100000000)
        self.sesskey = sesskey

        # Calculate proof
        proof = hashlib.md5(f"{chresp}{gamekey}".encode()).hexdigest()

        response_data = {
            "lc": "2",
            "sesskey": sesskey,
            "proof": proof,
            "id": request_id,
        }

        logger.debug("GameStats: Auth successful for game: %s", gamename)
        return self._format_response(response_data)

    def _handle_authp(self, request_data: dict[str, str]) -> str:
        r"""
        Handle \authp\ command - Player authentication.

        Validates the player using their authtoken from FESL/GP session.

        Request fields:
        - authtoken: Base64-encoded ticket from FESL GameSpyPreAuth
        - lid: Local ID
        - pid: Profile ID
        - id: Request ID

        Response fields:
        - pauthr: Auth result (0 = success)
        - lid: Local ID (echo back)
        - id: Request ID
        """
        logger.debug("GameStats: Processing authp")

        authtoken = request_data.get("authtoken", "")
        lid = request_data.get("lid", "1")
        request_id = request_data.get("id", "1")

        if not authtoken:
            return self._format_error("Missing authtoken", request_id)

        # Validate the pre-auth ticket
        result = validate_and_consume_preauth_ticket(self.db_session, authtoken)

        if not result:
            logger.debug("GameStats: Invalid or expired authtoken")
            # Return error code instead of success
            response_data = {
                "pauthr": "-1",
                "lid": lid,
                "errmsg": "Invalid authtoken",
                "id": request_id,
            }
            return self._format_response(response_data)

        user_id, persona_id, preauth_ticket = result

        self.user_id = user_id
        self.persona_id = persona_id
        self.authenticated_player = True

        response_data = {
            "pauthr": str(persona_id),
            "lid": lid,
            "id": request_id,
        }

        logger.debug("GameStats: Player auth successful: user=%s, persona=%s", user_id, persona_id)
        return self._format_response(response_data)

    def _handle_getpd(self, request_data: dict[str, str]) -> str:
        r"""
        Handle \getpd\ command - Get profile data.

        Returns player stats for the specified profile.

        Request fields:
        - pid: Profile ID
        - ptype: Profile type
        - dindex: Data index
        - keys: Comma-separated list of keys to retrieve
        - lid: Local ID
        - id: Request ID

        Response fields:
        - pid: Profile ID
        - lid: Local ID
        - mod: Modified timestamp
        - length: Data length
        - data: JSON-encoded stats data
        - id: Request ID
        """
        logger.debug("GameStats: Processing getpd")

        request_id = request_data.get("id", "1")

        # Require both game and player authentication
        if not self.authenticated_game:
            logger.debug("GameStats: getpd rejected - game not authenticated")
            return self._format_error("Game not authenticated", request_id)

        if not self.authenticated_player:
            logger.debug("GameStats: getpd rejected - player not authenticated")
            return self._format_error("Player not authenticated", request_id)

        pid_str = request_data.get("pid", "")
        lid = request_data.get("lid", "1")
        _keys_str = request_data.get("keys", "")  # Reserved for future use

        if not pid_str:
            return self._format_error("Missing pid", request_id)

        try:
            pid = int(pid_str)
        except ValueError:
            return self._format_error("Invalid pid", request_id)

        # Get player stats from database
        stats = get_player_stats(self.db_session, pid)

        # Build response data
        stats_data = {}
        if stats:
            stats_data = {
                "wins_unranked": stats.wins_unranked,
                "wins_ranked_1v1": stats.wins_ranked_1v1,
                "wins_ranked_2v2": stats.wins_ranked_2v2,
                "wins_clan_1v1": stats.wins_clan_1v1,
                "wins_clan_2v2": stats.wins_clan_2v2,
                "losses_unranked": stats.losses_unranked,
                "losses_ranked_1v1": stats.losses_ranked_1v1,
                "losses_ranked_2v2": stats.losses_ranked_2v2,
                "losses_clan_1v1": stats.losses_clan_1v1,
                "losses_clan_2v2": stats.losses_clan_2v2,
                "disconnects_unranked": stats.disconnects_unranked,
                "disconnects_ranked_1v1": stats.disconnects_ranked_1v1,
                "disconnects_ranked_2v2": stats.disconnects_ranked_2v2,
                "disconnects_clan_1v1": stats.disconnects_clan_1v1,
                "disconnects_clan_2v2": stats.disconnects_clan_2v2,
                "desyncs_unranked": stats.desyncs_unranked,
                "desyncs_ranked_1v1": stats.desyncs_ranked_1v1,
                "desyncs_ranked_2v2": stats.desyncs_ranked_2v2,
                "desyncs_clan_1v1": stats.desyncs_clan_1v1,
                "desyncs_clan_2v2": stats.desyncs_clan_2v2,
                "avg_game_length_unranked": stats.avg_game_length_unranked,
                "avg_game_length_ranked_1v1": stats.avg_game_length_ranked_1v1,
                "avg_game_length_ranked_2v2": stats.avg_game_length_ranked_2v2,
                "avg_game_length_clan_1v1": stats.avg_game_length_clan_1v1,
                "avg_game_length_clan_2v2": stats.avg_game_length_clan_2v2,
                "win_ratio_unranked": stats.win_ratio_unranked,
                "win_ratio_ranked_1v1": stats.win_ratio_ranked_1v1,
                "win_ratio_ranked_2v2": stats.win_ratio_ranked_2v2,
                "win_ratio_clan_1v1": stats.win_ratio_clan_1v1,
                "win_ratio_clan_2v2": stats.win_ratio_clan_2v2,
                "total_matches_online": stats.total_matches_online,
            }

        # Encode as JSON
        data_json = json.dumps(stats_data)
        data_len = len(data_json)

        response_data = {
            "pid": str(pid),
            "lid": lid,
            "mod": "0",
            "length": str(data_len),
            "data": data_json,
            "id": request_id,
        }

        logger.debug("GameStats: Returning stats for pid=%s, length=%d", pid, data_len)
        return self._format_response(response_data)

    def _handle_setpd(self, request_data: dict[str, str]) -> str:
        r"""
        Handle \setpd\ command - Set profile data.

        Saves player stats for the specified profile.

        Request fields:
        - pid: Profile ID
        - ptype: Profile type
        - dindex: Data index
        - length: Data length
        - data: JSON-encoded stats data
        - lid: Local ID
        - id: Request ID

        Response fields:
        - pid: Profile ID
        - lid: Local ID
        - mod: Modified timestamp
        - id: Request ID
        """
        logger.debug("GameStats: Processing setpd")

        request_id = request_data.get("id", "1")

        # Require both game and player authentication
        if not self.authenticated_game:
            logger.debug("GameStats: setpd rejected - game not authenticated")
            return self._format_error("Game not authenticated", request_id)

        if not self.authenticated_player:
            logger.debug("GameStats: setpd rejected - player not authenticated")
            return self._format_error("Player not authenticated", request_id)

        pid_str = request_data.get("pid", "")
        data_str = request_data.get("data", "{}")
        lid = request_data.get("lid", "1")

        if not pid_str:
            return self._format_error("Missing pid", request_id)

        try:
            pid = int(pid_str)
        except ValueError:
            return self._format_error("Invalid pid", request_id)

        # Verify player can only modify their own stats
        if pid != self.persona_id:
            logger.debug(
                "GameStats: setpd rejected - pid mismatch (requested=%d, authenticated=%s)",
                pid,
                self.persona_id,
            )
            return self._format_error("Cannot modify other player's stats", request_id)

        # Parse the stats data
        try:
            stats_data = json.loads(data_str)
        except json.JSONDecodeError:
            stats_data = {}

        # Update player stats
        if stats_data:
            create_or_update_player_stats(self.db_session, pid, stats_data)

        response_data = {
            "pid": str(pid),
            "lid": lid,
            "mod": "1",
            "id": request_id,
        }

        logger.debug("GameStats: Stats saved for pid=%s", pid)
        return self._format_response(response_data)

    def connection_lost(self, exc):
        logger.debug("GameStats: Connection closed for %s", self.peername)

        # Close the database session
        if self._db_session is not None:
            try:
                self._db_session.close()
            except Exception as e:
                logger.warning("GameStats: Error closing database session: %s", e)
            self._db_session = None


# =============================================================================
# Server Startup
# =============================================================================


async def start_gamestats_server(host: str, port: int) -> asyncio.Server:
    """
    Start the GameStats server.

    Args:
        host: Host address to bind to
        port: Port to listen on (default 29920)

    Returns:
        The asyncio server instance
    """
    loop = asyncio.get_running_loop()
    server = await loop.create_server(lambda: GameStatsServer(), host, port)
    logger.info("GameStats server listening on %s:%d", host, port)
    return server
