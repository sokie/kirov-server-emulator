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

from app.config.app_settings import app_config
from app.db.crud import (
    DEFAULT_GAME_ID,
    create_or_update_generals_stats,
    create_or_update_player_stats,
    get_generals_player_stats,
    get_player_stats,
    validate_and_consume_preauth_ticket,
)
from app.db.database import create_session
from app.models.fesl_types import GAMESPY_GAME_KEY_MAP
from app.util.cipher import gs_chresp_num, gs_xor
from app.util.logging_helper import format_hex, get_logger

logger = get_logger(__name__)

# Map gamename to game_id for per-game stats
GAMENAME_TO_GAME_ID = {
    "redalert3pc": 2128,
    "cncra3pc": 2128,
    "cc3xp1": 1814,
    "cnc3ep1pc": 1814,
    "cc3": 1422,
    "cc3tibwars": 1422,
    "cnc3pc": 1422,
}

if TYPE_CHECKING:
    pass


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
        self.gamename: str | None = None

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

        # Generate and send initial challenge
        self.server_challenge = self._generate_challenge()
        challenge_msg = f"\\lc\\1\\challenge\\{self.server_challenge}\\id\\1\\final\\"
        logger.debug("GameStats: Sending challenge: %s", challenge_msg)
        self._send_response(challenge_msg)

    def _generate_challenge(self) -> str:
        """Generate a random challenge string - 10 characters."""
        return "".join(secrets.choice(string.ascii_uppercase + string.digits) for _ in range(10))

    def data_received(self, data):
        try:
            logger.debug("GameStats: Received %d bytes from %s", len(data), self.peername)
            logger.debug("GameStats RX hex: %s", format_hex(data))

            self.buffer += data

            # \final\ is a plaintext delimiter - split on it, decrypt each segment
            final_marker = b"\\final\\"
            while final_marker in self.buffer:
                final_pos = self.buffer.find(final_marker)
                encrypted_segment = self.buffer[:final_pos]
                self.buffer = self.buffer[final_pos + len(final_marker) :]

                if not encrypted_segment:
                    continue

                decrypted_message = gs_xor(encrypted_segment).decode("latin-1")
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
        elif command == "newgame":
            response = self._handle_newgame(request_data)
        elif command == "updgame":
            response = self._handle_updgame(request_data)
        elif command == "ka":
            response = "\\ka\\\\final\\"
        else:
            logger.debug("GameStats: Unknown command: %s", command)
            response = self._format_error(f"Unknown command: {command}", request_data.get("id", "1"))

        if response:
            self._send_response(response)

    def _parse_request(self, data: str) -> dict[str, str]:
        r"""
        Parses the GameStats request string into a dictionary.

        Handles the length-based \data\ field used by Generals/Zero Hour where the
        data field itself contains backslashes (e.g., \length\30\data\wins0\5\losses0\3\).
        The \length\ field specifies how many bytes the \data\ field contains.
        This is backward-compatible with CNC3/RA3 JSON data which has no internal backslashes.
        """
        stripped = data.strip()

        # Extract length-delimited data field before splitting
        # Look for \length\N\data\ pattern and extract exactly N bytes
        data_value = None
        length_marker = "\\length\\"
        data_marker = "\\data\\"
        length_pos = stripped.find(length_marker)

        if length_pos != -1:
            after_length = length_pos + len(length_marker)
            # Find the end of the length value (next backslash)
            next_sep = stripped.find("\\", after_length)
            if next_sep != -1:
                try:
                    data_length = int(stripped[after_length:next_sep])
                except ValueError:
                    data_length = -1

                if data_length >= 0:
                    # Find \data\ marker after length value
                    data_pos = stripped.find(data_marker, next_sep)
                    if data_pos != -1:
                        data_start = data_pos + len(data_marker)
                        data_value = stripped[data_start : data_start + data_length]
                        # Reconstruct the string without the raw data blob
                        # Keep everything before \length\, add length and data as simple values,
                        # then append everything after the data blob
                        remainder_start = data_start + data_length
                        stripped = stripped[:length_pos] + stripped[remainder_start:]

        parts = stripped.split("\\")

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

        # Re-insert extracted data value and length
        if data_value is not None:
            result["data"] = data_value
            result["length"] = str(len(data_value))

        return result

    def _format_response(self, data: dict[str, str]) -> str:
        """Formats a dictionary as a GameStats response string."""
        return "".join([f"\\{k}\\{v}" for k, v in data.items()]) + "\\final\\"

    def _format_error(self, message: str, request_id: str = "1") -> str:
        """Formats an error response."""
        return f"\\error\\\\errmsg\\{message}\\id\\{request_id}\\final\\"

    def _send_response(self, response: str):
        r"""Sends an encrypted response to the client.

        XOR encrypts the payload (everything before \final\) and appends
        \final\ as a plaintext delimiter.
        """
        if not self.transport:
            return

        logger.debug("GameStats TX (plaintext): %s", response)
        # Split off \final\, XOR only the payload, re-append \final\ as plaintext
        payload = response.replace("\\final\\", "")
        encrypted = gs_xor(payload.encode("latin-1")) + b"\\final\\"
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

        # Get the game key from config
        config_key = GAMESPY_GAME_KEY_MAP.get(gamename.lower())
        gamekey = app_config.game.gamekeys.get(config_key, "") if config_key else ""
        if not gamekey:
            logger.debug("GameStats: No gamekey configured for game: %s", gamename)
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
        self.gamename = gamename

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

        Two variants depending on game:

        CNC3/RA3 (EA login):
          \authp\\authtoken\<ticket>\resp\<hash>\final\
          Validates the player using their authtoken from FESL/GP pre-auth.

        Generals/Zero Hour (classic GameSpy):
          \authp\\pid\<n>\resp\<hash>\lid\<n>\final\
          No authtoken — GameSpy SDK sends pid + resp (challenge-response hash).
          The resp field is ignored (matches reference implementation); the pid
          is accepted directly since game auth (\auth\) was already verified.

        Response fields:
        - pauthr: Profile ID (success) or -1 (failure)
        - lid: Local ID (echo back)
        """
        logger.debug("GameStats: Processing authp")

        authtoken = request_data.get("authtoken", "")
        pid_str = request_data.get("pid", "")
        lid = request_data.get("lid", "1")
        request_id = request_data.get("id", "1")

        if authtoken:
            # CNC3/RA3 path: validate using FESL pre-auth ticket
            result = validate_and_consume_preauth_ticket(self.db_session, authtoken)

            if not result:
                logger.debug("GameStats: Invalid or expired authtoken")
                response_data = {
                    "pauthr": "-1",
                    "lid": lid,
                    "errmsg": "Invalid authtoken",
                }
                return self._format_response(response_data)

            user_id, persona_id, _ticket = result

        elif pid_str:
            # Generals/ZH path: no authtoken, game sends pid + resp
            # resp is a challenge-response hash but is ignored (reference does the same)
            # game auth (\auth\) already verified the client is a legitimate game
            try:
                persona_id = int(pid_str)
            except ValueError:
                return self._format_error("Invalid pid", request_id)
            user_id = persona_id
            logger.debug("GameStats: Generals authp for pid=%s (resp ignored)", pid_str)

        else:
            return self._format_error("Missing authtoken or pid", request_id)

        self.user_id = user_id
        self.persona_id = persona_id
        self.authenticated_player = True

        response_data = {
            "pauthr": str(persona_id),
            "lid": lid,
        }

        logger.debug("GameStats: Player auth successful: user=%s, persona=%s", user_id, persona_id)
        return self._format_response(response_data)

    def _is_generals_game(self) -> bool:
        """Check if the current game is Generals or Zero Hour."""
        return self.gamename in ("ccgenerals", "ccgenzh")

    def _handle_getpd(self, request_data: dict[str, str]) -> str:
        r"""
        Handle \getpd\ command - Get profile data.

        Routes to game-specific handler based on gamename.
        """
        logger.debug("GameStats: Processing getpd")

        request_id = request_data.get("id", "1")

        # Require game authentication; player auth is only needed for writes (setpd).
        # The GameSpy SDK sends getpd right after \auth\ without \authp\ first.
        if not self.authenticated_game:
            logger.debug("GameStats: getpd rejected - game not authenticated")
            return self._format_error("Game not authenticated", request_id)

        pid_str = request_data.get("pid", "")
        lid = request_data.get("lid", "1")

        if not pid_str:
            return self._format_error("Missing pid", request_id)

        try:
            pid = int(pid_str)
        except ValueError:
            return self._format_error("Invalid pid", request_id)

        if self._is_generals_game():
            return self._handle_getpd_generals(pid, lid, request_id, request_data)
        return self._handle_getpd_json(pid, lid, request_id, request_data)

    def _handle_getpd_json(self, pid: int, lid: str, request_id: str, request_data: dict[str, str]) -> str:
        """Handle getpd for CNC3/RA3/KW (JSON format).

        Converts nested JSON stats → flat keys for the game client wire format.
        """
        from app.models.game_config import GAME_TYPES

        game_id = GAMENAME_TO_GAME_ID.get(self.gamename, DEFAULT_GAME_ID)
        stats = get_player_stats(self.db_session, pid, game_id=game_id)

        stats_data = {}
        if stats:
            s = stats.stats or {}
            # Flatten nested JSON → flat keys: stats["ranked_1v1"]["wins"] → "wins_ranked_1v1"
            flat_stat_keys = [
                "wins", "losses", "disconnects", "desyncs",
                "avg_game_length", "win_ratio",
            ]
            for game_type in GAME_TYPES:
                mode_stats = s.get(game_type, {})
                for key in flat_stat_keys:
                    stats_data[f"{key}_{game_type}"] = mode_stats.get(key, 0)

            stats_data["total_matches_online"] = stats.total_matches_online

        data_json = json.dumps(stats_data)
        data_len = len(data_json)

        response_data = {
            "getpdr": "1",
            "lid": lid,
            "pid": str(pid),
            "mod": "0",
            "length": str(data_len),
            "data": data_json,
        }

        logger.debug("GameStats: Returning JSON stats for pid=%s, length=%d", pid, data_len)
        return self._format_response(response_data)

    def _handle_getpd_generals(self, pid: int, lid: str, request_id: str, request_data: dict[str, str]) -> str:
        r"""
        Handle getpd for Generals/Zero Hour (raw KV format).

        Returns the raw_data from GeneralsPlayerStats as the data field,
        with correct length. The battle honors bitmask is injected into
        the data so the game can read it.
        """
        from app.util.generals_stats import calculate_rank, format_generals_kv, parse_generals_kv

        stats = get_generals_player_stats(self.db_session, pid)

        if stats and stats.raw_data:
            # Inject computed battle honors and rank into the response data
            parsed = parse_generals_kv(stats.raw_data)
            rank = calculate_rank(parsed)
            parsed["battle"] = str(stats.battle_honors)
            parsed["rank"] = str(rank)
            data_str = format_generals_kv(parsed)
        else:
            data_str = ""

        data_len = len(data_str)

        # Build the response manually to handle the data field correctly
        # The data field contains backslashes, so we can't use _format_response
        response = (
            f"\\getpdr\\1"
            f"\\lid\\{lid}"
            f"\\pid\\{pid}"
            f"\\mod\\{int(stats.updated_at.timestamp()) if stats else 0}"
            f"\\length\\{data_len}"
            f"\\data\\{data_str}"
            f"\\final\\"
        )

        logger.debug("GameStats: Returning Generals stats for pid=%s, length=%d", pid, data_len)
        return response

    def _handle_setpd(self, request_data: dict[str, str]) -> str:
        r"""
        Handle \setpd\ command - Set profile data.

        Routes to game-specific handler based on gamename.
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
        data_str = request_data.get("data", "")
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

        if self._is_generals_game():
            return self._handle_setpd_generals(pid, data_str, lid, request_id)
        return self._handle_setpd_json(pid, data_str, lid, request_id)

    def _handle_setpd_json(self, pid: int, data_str: str, lid: str, request_id: str) -> str:
        """Handle setpd for CNC3/RA3 (JSON format)."""
        if not data_str:
            data_str = "{}"

        try:
            stats_data = json.loads(data_str)
        except json.JSONDecodeError:
            stats_data = {}

        if stats_data:
            game_id = GAMENAME_TO_GAME_ID.get(self.gamename, DEFAULT_GAME_ID)
            create_or_update_player_stats(self.db_session, pid, stats_data, game_id=game_id)

        response_data = {
            "setpdr": "1",
            "lid": lid,
            "pid": str(pid),
            "mod": "1",
        }

        logger.debug("GameStats: JSON stats saved for pid=%s", pid)
        return self._format_response(response_data)

    def _handle_setpd_generals(self, pid: int, data_str: str, lid: str, request_id: str) -> str:
        r"""
        Handle setpd for Generals/Zero Hour (raw KV format).

        Stores raw KV data, merging with existing stats. Recalculates
        battle honors on each update.
        """
        if data_str:
            create_or_update_generals_stats(self.db_session, pid, data_str)

        response_data = {
            "setpdr": "1",
            "lid": lid,
            "pid": str(pid),
            "mod": "1",
        }

        logger.debug("GameStats: Generals stats saved for pid=%s", pid)
        return self._format_response(response_data)

    def _handle_newgame(self, request_data: dict[str, str]) -> str:
        r"""
        Handle \newgame\ command - Game snapshot start.

        Sent by the gstats SDK when a game starts (SendGameSnapShot).
        We acknowledge it so the client doesn't error out.
        """
        request_id = request_data.get("id", "1")
        logger.debug("GameStats: Received newgame snapshot")

        # Acknowledge with a session ID
        response_data = {
            "newgame": "",
            "id": request_id,
        }
        return self._format_response(response_data)

    def _handle_updgame(self, request_data: dict[str, str]) -> str:
        r"""
        Handle \updgame\ command - Game snapshot update.

        Sent by the gstats SDK to update game snapshot data (player results, etc.).
        We acknowledge it so the client doesn't error out.
        """
        request_id = request_data.get("id", "1")
        logger.debug("GameStats: Received updgame snapshot")

        # Acknowledge
        response_data = {
            "updgame": "",
            "id": request_id,
        }
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
