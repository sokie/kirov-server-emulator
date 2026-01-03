r"""
GameSpy Protocol Server (GPServer) - Handles GameSpy protocol communications.

This server receives connections from clients after they've authenticated
through FESL and obtained a pre-auth ticket via GameSpyPreAuth.

The cross-service handshake flow:
1. Client authenticates with FESL (NuLogin -> NuLoginPersona -> GameSpyPreAuth)
2. FESL returns a ticket: base64(userId|profileId|secretToken)
3. Client connects to GPServer with the ticket as 'authtoken'
4. GPServer validates the ticket against the database
5. GPServer creates a session and returns session info

Protocol format:
- Request:  \command\key1\value1\key2\value2\...\final\
- Response: \key1\value1\key2\value2\...\final\
"""

import asyncio
import base64
import hashlib
import secrets
import string
from typing import TYPE_CHECKING

from app.util.logging_helper import format_hex, get_logger

logger = get_logger(__name__)

import contextlib

from app.db.crud import (
    accept_buddy_request,
    create_buddy_request,
    create_game_invite,
    create_gamespy_session,
    delete_buddy_one_way,
    get_gamespy_session_by_sesskey,
    get_persona_by_id,
    get_persona_friends,
    get_user_by_id,
    invalidate_gamespy_session,
    update_gamespy_session_status,
    validate_and_consume_preauth_ticket,
)
from app.db.database import create_session

if TYPE_CHECKING:
    from app.servers.sessions import SessionManager


class GpServer(asyncio.Protocol):
    r"""
    GameSpy Protocol Server.

    Handles GameSpy protocol commands:
    - \login\: Authenticate using FESL pre-auth ticket
    - \getprofile\: Get player profile information
    - \status\: Update player status
    - \logout\: End session
    """

    def __init__(self, session_manager: "SessionManager"):
        logger.debug("Initializing")
        self.transport = None
        self.peername = None
        self.session_manager = session_manager

        # Database session (reused across all operations for this connection)
        self._db_session = None

        # Session state
        self.user_id: int | None = None
        self.persona_id: int | None = None
        self.sesskey: str | None = None
        self.uniquenick: str | None = None

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
        logger.debug("New connection from %s", self.peername)

        # Create database session for this connection
        self.db_session = create_session()

        # Generate and send initial challenge
        self.server_challenge = self._generate_challenge()
        challenge_response = self.format_response({"lc": "1", "challenge": self.server_challenge, "id": "1"})
        response_bytes = challenge_response.encode()
        logger.debug("Sending challenge: %s", challenge_response)
        logger.debug("TX hex: %s", format_hex(response_bytes))
        self.transport.write(response_bytes)

    def _generate_challenge(self) -> str:
        """Generate a random challenge string - 10 uppercase letters like real server."""
        return "".join(secrets.choice(string.ascii_uppercase) for _ in range(10))

    def data_received(self, data):
        try:
            logger.debug("Received %d bytes from %s", len(data), self.peername)
            logger.debug("RX hex: %s", format_hex(data))
            message = data.decode().strip()
            logger.debug("RX decoded: %s", message)

            # Parse the command from the message
            parts = message.strip().split("\\")
            if len(parts) < 2:
                self.send_error("Invalid request format")
                return

            command = parts[1]
            request_data = self.parse_request(message)

            response = ""
            if command == "login":
                response = self.handle_login(request_data)
            elif command == "getprofile":
                response = self.handle_getprofile(request_data)
            elif command == "status":
                response = self.handle_status(request_data)
            elif command == "addbuddy":
                response = self.handle_addbuddy(request_data)
            elif command == "authadd":
                response = self.handle_authadd(request_data)
            elif command == "pinvite":
                response = self.handle_pinvite(request_data)
            elif command == "delbuddy":
                response = self.handle_delbuddy(request_data)
            elif command == "ka":
                # Keepalive - respond with keepalive
                response = "\\ka\\\\final\\"
            elif command == "logout":
                response = self.handle_logout(request_data)
            else:
                response = self.format_error("Unknown command", request_data.get("id", "1"))

            logger.debug("Response from handler: %r", response)
            if response:
                response_bytes = response.encode()
                logger.debug("Sending: %s", response)
                logger.debug("TX hex: %s", format_hex(response_bytes))
                self.transport.write(response_bytes)
            else:
                logger.debug("No response to send")

        except Exception as e:
            logger.exception("Error processing request: %s", e)
            self.send_error(str(e))

    def parse_request(self, data: str) -> dict[str, str]:
        """
        Parses the GameSpy request string into a dictionary.

        Format: \\command\\key1\\value1\\key2\\value2\\...\\final\\
        The command (first element after leading backslash) often has an empty value.
        """
        parts = data.strip().split("\\")

        # Remove empty strings from the beginning and end
        while parts and parts[0] == "":
            parts.pop(0)
        while parts and parts[-1] == "":
            parts.pop()
        # Remove 'final' from the end if present
        if parts and parts[-1] == "final":
            parts.pop()

        # Parse key-value pairs (values can be empty)
        result = {}
        i = 0
        while i < len(parts):
            key = parts[i]
            if key:  # Only add if key is not empty
                value = parts[i + 1] if i + 1 < len(parts) else ""
                result[key] = value
            i += 2

        return result

    def format_response(self, data: dict[str, str]) -> str:
        """Formats a dictionary as a GameSpy response string."""
        return "".join([f"\\{k}\\{v}" for k, v in data.items()]) + "\\final\\"

    def format_error(self, message: str, request_id: str = "1") -> str:
        """Formats an error response."""
        return f"\\error\\\\errmsg\\{message}\\id\\{request_id}\\final\\"

    def send_error(self, message: str):
        """Sends an error response to the client."""
        response = self.format_error(message)
        if self.transport:
            self.transport.write(response.encode())

    def handle_login(self, request_data: dict[str, str]) -> str:
        r"""
        Handle \login\ command - Authenticate using FESL pre-auth ticket.

        Request fields:
        - authtoken: Base64-encoded ticket from FESL GameSpyPreAuth
        - challenge: Client-generated challenge string
        - response: MD5 hash for verification
        - partnerid: Partner ID (usually 0)
        - port: Client port
        - productid: Game product ID (11419 for RA3)
        - gamename: Game name (redalert3pc)
        - namespaceid: Namespace ID
        - sdkrevision: SDK revision
        - firewall: Firewall status
        - quiet: Quiet mode flag
        - id: Request ID

        Response fields:
        - lc: Login code (2 = success)
        - sesskey: Session key for subsequent requests
        - proof: MD5 proof of authentication
        - userid: User's database ID
        - profileid: Persona's database ID
        - uniquenick: Persona's unique nickname
        - lt: Login ticket (base64 encoded)
        - id: Request ID from request
        """
        logger.debug("Processing login")

        authtoken = request_data.get("authtoken", "")
        client_challenge = request_data.get("challenge", "")
        client_response = request_data.get("response", "")
        request_id = request_data.get("id", "1")

        if not authtoken:
            return self.format_error("Missing authtoken", request_id)

        # Validate and consume the pre-auth ticket
        result = validate_and_consume_preauth_ticket(self.db_session, authtoken)

        if not result:
            logger.debug("Invalid or expired authtoken: %s...", authtoken[:20])
            return self.format_error("Invalid or expired authtoken", request_id)

        user_id, persona_id, preauth_ticket = result

        # Validate client response before proceeding
        # The client's response proves they also know the FESL challenge
        if client_response:
            expected_response = self.calculate_client_response(
                password=preauth_ticket.challenge,
                authtoken=authtoken,
                client_challenge=client_challenge,
                server_challenge=self.server_challenge,
            )
            if client_response != expected_response:
                logger.debug("Client response validation failed!")
                logger.debug("Expected: %s, Got: %s", expected_response, client_response)
                return self.format_error("Invalid client response", request_id)
            logger.debug("Client response validated successfully")

        # Get persona for uniquenick
        persona = get_persona_by_id(self.db_session, persona_id)
        if not persona:
            return self.format_error("Persona not found", request_id)

        uniquenick = persona.name

        # Create GameSpy session
        gp_session = create_gamespy_session(
            session=self.db_session,
            user_id=user_id,
            persona_id=persona_id,
            preauth_ticket_id=preauth_ticket.id,
            client_ip=self.peername[0] if self.peername else None,
            port=int(request_data.get("port", 0)) or None,
            product_id=int(request_data.get("productid", 0)) or None,
            gamename=request_data.get("gamename"),
        )

        # Store session info
        self.user_id = user_id
        self.persona_id = persona_id
        self.sesskey = gp_session.sesskey
        self.uniquenick = uniquenick

        # Register with session manager
        logger.debug("Registering session: %s", gp_session.sesskey)
        self.session_manager.register_user(gp_session.sesskey, self)
        logger.debug("Session registered, calculating proof...")

        # Calculate proof
        # Formula: MD5( MD5(fesl_challenge) + 48_spaces + authtoken + server_challenge + client_challenge + MD5(fesl_challenge) )
        # The password is the FESL challenge from GameSpyPreAuth, NOT the secret_token
        proof = self.calculate_proof(
            password=preauth_ticket.challenge,
            authtoken=authtoken,
            client_challenge=client_challenge,
            server_challenge=self.server_challenge,
        )

        # Generate lt (login ticket) for subsequent authentication
        # Format: base64(userid|profileid|secret)
        logger.debug("Generating lt with secret_token: %s", preauth_ticket.secret_token)
        lt_payload = f"{user_id}|{persona_id}|{preauth_ticket.secret_token}"
        lt = base64.b64encode(lt_payload.encode()).decode()

        # Response field order matters - must match real server exactly
        # Real: \lc\2\sesskey\...\proof\...\userid\...\profileid\...\uniquenick\...\lt\...\id\1\final\
        response_data = {
            "lc": "2",  # Login code 2 = success
            "sesskey": gp_session.sesskey,
            "proof": proof,
            "userid": str(user_id),
            "profileid": str(persona_id),
            "uniquenick": uniquenick,
            "lt": lt,
            "id": request_id,
        }

        logger.debug("Login successful: user=%s, persona=%s, uniquenick=%s", user_id, persona_id, uniquenick)
        result = self.format_response(response_data)
        logger.debug("Formatted response: %s", result)
        return result

    def calculate_proof(self, password: str, authtoken: str, client_challenge: str, server_challenge: str) -> str:
        """
        Calculate the server proof hash for GameSpy authentication.

        The proof is an MD5 hash that proves the server knows the shared secret.
        Formula: MD5( MD5(password) + 48_spaces + authtoken + server_challenge + client_challenge + MD5(password) )

        The password is the FESL challenge from GameSpyPreAuth response.
        """

        def md5hex(x):
            return hashlib.md5(x.encode()).hexdigest()

        spaces = " " * 48
        pwd_hash = md5hex(password)
        proof_string = pwd_hash + spaces + authtoken + server_challenge + client_challenge + pwd_hash
        proof = hashlib.md5(proof_string.encode()).hexdigest()
        logger.debug("Proof calculation: password=%s, authtoken=%s...", password, authtoken[:20])
        logger.debug(
            "Proof string components: md5(password)=%s, server_chal=%s, client_chal=%s",
            pwd_hash,
            server_challenge,
            client_challenge,
        )
        logger.debug("Proof result: %s", proof)
        return proof

    def calculate_client_response(
        self, password: str, authtoken: str, client_challenge: str, server_challenge: str
    ) -> str:
        """
        Calculate the expected client response hash for validation.

        The client calculates with challenges in OPPOSITE order:
        Formula: MD5( MD5(password) + 48_spaces + authtoken + client_challenge + server_challenge + MD5(password) )

        This is used to verify the client's 'response' field before proceeding.
        """

        def md5hex(x):
            return hashlib.md5(x.encode()).hexdigest()

        spaces = " " * 48
        pwd_hash = md5hex(password)
        # Note: client_challenge comes BEFORE server_challenge (opposite of server proof)
        response_string = pwd_hash + spaces + authtoken + client_challenge + server_challenge + pwd_hash
        return hashlib.md5(response_string.encode()).hexdigest()

    def handle_getprofile(self, request_data: dict[str, str]) -> str:
        r"""
        Handle \getprofile\ command - Get player profile information.

        Request fields:
        - profileid: Profile ID to look up
        - sesskey: Session key for authentication
        - id: Request ID

        Response fields (prefixed with \pi\):
        - profileid: Profile ID
        - nick: Display name
        - userid: User ID
        - uniquenick: Unique nickname
        - sig: Signature (empty or hash)
        - lon/lat: Location coordinates
        - loc: Location string
        - id: Request ID
        """
        logger.debug("Processing getprofile")

        request_id = request_data.get("id", "1")
        profileid_str = request_data.get("profileid", "")
        request_data.get("sesskey", "")

        if not profileid_str:
            return self.format_error("Missing profileid", request_id)

        try:
            profileid = int(profileid_str)
        except ValueError:
            return self.format_error("Invalid profileid", request_id)

        # Get the persona
        persona = get_persona_by_id(self.db_session, profileid)
        if not persona:
            return self.format_error("Profile not found", request_id)

        # Get the user
        user = get_user_by_id(self.db_session, persona.user_id)
        if not user:
            return self.format_error("User not found", request_id)

        response_data = {
            "profileid": str(persona.id),
            "nick": persona.name,
            "userid": str(user.id),
            "sig": "00000000000000000000000000000000",
            "uniquenick": persona.name,
            "pid": str(persona.id),
            "lon": "0.000000",
            "lat": "0.000000",
            "loc": "",
            "id": request_id,
        }

        # Profile responses are prefixed with \pi\
        return "\\pi\\" + self.format_response(response_data)

    def handle_status(self, request_data: dict[str, str]) -> str:
        r"""
        Handle \status\ command - Update player status.

        Request fields:
        - status: Status code (1-4)
        - sesskey: Session key
        - statstring: Human-readable status (Online, Playing, Loading, Staging, Chatting)
        - locstring: Location context (empty, channel ID, or host name)

        Status codes:
        - 1 = Online (idle, in menus)
        - 2 = In-game (Playing, Loading)
        - 3 = Staging (in game lobby)
        - 4 = Chatting (in chat channel)

        Response:
        - No response needed, server updates status and notifies friends
        """
        logger.debug("Processing status update")

        # Status code is provided directly as the value of 'status' key
        status_code = request_data.get("status", "1")
        sesskey = request_data.get("sesskey", self.sesskey)
        statstring = request_data.get("statstring", "Online")
        locstring = request_data.get("locstring", "")

        logger.debug("Status update: code=%s, statstring=%s, locstring=%s", status_code, statstring, locstring)

        # Update status in database
        if sesskey:
            try:
                update_gamespy_session_status(self.db_session, sesskey, status_code, statstring, locstring)
            except Exception as e:
                logger.warning("Error updating status: %s", e)

        # Notify buddies of status change
        self._notify_buddies_status(status_code, statstring, locstring)

        return ""  # No response needed

    def _notify_buddies_status(self, status_code: str, statstring: str, locstring: str):
        """Send buddy status notification to all online buddies."""
        if not self.persona_id:
            return

        try:
            friends = get_persona_friends(self.db_session, self.persona_id)

            # Build buddy message: |s|<code>|ss|<status>|ls|<location>|ip|<ip>|p|<port>|qm|0
            ip_int = self._ip_to_int(self.peername[0]) if self.peername else 0
            bm_msg = f"|s|{status_code}|ss|{statstring}|ls|{locstring}|ip|{ip_int}|p|0|qm|0"

            for friend in friends:
                # Find if friend is online via session manager
                friend_client = self.session_manager.get_user_by_persona_id(friend.id)
                if friend_client:
                    bm_response = f"\\bm\\100\\f\\{self.persona_id}\\msg\\{bm_msg}\\final\\"
                    with contextlib.suppress(Exception):
                        friend_client.transport.write(bm_response.encode())
        except Exception as e:
            logger.warning("Error notifying buddies: %s", e)

    def _ip_to_int(self, ip_str: str) -> int:
        """Convert IP address string to integer."""
        try:
            parts = ip_str.split(".")
            return (int(parts[0]) << 24) + (int(parts[1]) << 16) + (int(parts[2]) << 8) + int(parts[3])
        except Exception:
            return 0

    def handle_logout(self, request_data: dict[str, str]) -> str:
        r"""
        Handle \logout\ command - End the session.

        This invalidates the session and cleans up.
        """
        logger.debug("Processing logout")

        if self.sesskey:
            # Unregister from session manager
            self.session_manager.unregister_user(self.sesskey)

            # Invalidate the session in the database
            try:
                invalidate_gamespy_session(self.db_session, self.sesskey)
            except Exception as e:
                logger.warning("Error invalidating session: %s", e)

            # Notify buddies that we went offline
            self._notify_buddies_status("0", "Offline", "")

        # Clear local state
        self.user_id = None
        self.persona_id = None
        self.sesskey = None
        self.uniquenick = None

        return ""  # No response needed for logout

    def handle_addbuddy(self, request_data: dict[str, str]) -> str:
        r"""
        Handle \addbuddy\ command - Send a buddy request.

        Request fields:
        - sesskey: Session key
        - newprofileid: Profile ID of the person to add
        - reason: Optional reason message

        Response:
        - \bm\4\f\<profileid>\msg\\final\ (acknowledgment)
        - Server also sends \bm\2\ to the target player
        """
        logger.debug("Processing addbuddy")

        request_data.get("sesskey", self.sesskey)
        new_profile_id_str = request_data.get("newprofileid", "")
        reason = request_data.get("reason", "")

        if not new_profile_id_str or not self.persona_id:
            return ""

        try:
            new_profile_id = int(new_profile_id_str)
        except ValueError:
            return ""

        # Create buddy request in database
        try:
            create_buddy_request(self.db_session, self.persona_id, new_profile_id, reason)

            # Get the target persona
            target_persona = get_persona_by_id(self.db_session, new_profile_id)

            # Send buddy request notification to target if online
            if target_persona:
                target_client = self.session_manager.get_user_by_persona_id(new_profile_id)
                if target_client:
                    # Send \bm\2\ (buddy request) to target
                    # Format: message text + |signed| + 32 zeros
                    bm_msg = "Red Alert 3 user wants to add a buddy|signed|00000000000000000000000000000000"
                    bm_response = f"\\bm\\2\\f\\{self.persona_id}\\msg\\{bm_msg}\\final\\"
                    with contextlib.suppress(Exception):
                        target_client.transport.write(bm_response.encode())

            # Send acknowledgment to sender with status update
            # Real server sends \bm\4\ followed by \bm\100\ combined
            self._ip_to_int(self.peername[0]) if self.peername else 0
            # Get target's current status if online
            target_client = self.session_manager.get_user_by_persona_id(new_profile_id)
            if target_client and target_client.peername:
                target_ip_int = self._ip_to_int(target_client.peername[0])
                # Get target's status from their session
                target_status = "1"
                target_statstring = "Online"
                target_locstring = ""
                try:
                    gp_session = get_gamespy_session_by_sesskey(self.db_session, target_client.sesskey)
                    if gp_session:
                        target_status = gp_session.status or "1"
                        target_statstring = gp_session.stat_string or "Online"
                        target_locstring = gp_session.loc_string or ""
                except Exception:
                    pass
                status_msg = (
                    f"|s|{target_status}|ss|{target_statstring}|ls|{target_locstring}|ip|{target_ip_int}|p|0|qm|0"
                )
                return f"\\bm\\4\\f\\{new_profile_id}\\msg\\\\final\\\\bm\\100\\f\\{new_profile_id}\\msg\\{status_msg}\\final\\"

            # Target not online, just send ack
            return f"\\bm\\4\\f\\{new_profile_id}\\msg\\\\final\\"

        except Exception as e:
            logger.warning("Error creating buddy request: %s", e)
            return ""

    def handle_authadd(self, request_data: dict[str, str]) -> str:
        r"""
        Handle \authadd\ command - Authorize/accept a buddy request.

        Request fields:
        - sesskey: Session key
        - fromprofileid: Profile ID of the person who sent the request
        - sig: Signature (usually zeros)

        Response:
        - Sends \bm\100\ status notification to the original requester
        """
        logger.debug("Processing authadd")

        request_data.get("sesskey", self.sesskey)
        from_profile_id_str = request_data.get("fromprofileid", "")

        if not from_profile_id_str or not self.persona_id:
            return ""

        try:
            from_profile_id = int(from_profile_id_str)
        except ValueError:
            return ""

        # Accept buddy request in database
        try:
            success = accept_buddy_request(self.db_session, from_profile_id, self.persona_id)

            if success:
                # Notify the original sender that request was accepted
                sender_client = self.session_manager.get_user_by_persona_id(from_profile_id)
                if sender_client:
                    # Send status update with our actual current status
                    ip_int = self._ip_to_int(self.peername[0]) if self.peername else 0
                    # Get our current status from session
                    my_status = "1"
                    my_statstring = "Online"
                    my_locstring = ""
                    try:
                        my_session = get_gamespy_session_by_sesskey(self.db_session, self.sesskey)
                        if my_session:
                            my_status = my_session.status or "1"
                            my_statstring = my_session.stat_string or "Online"
                            my_locstring = my_session.loc_string or ""
                    except Exception:
                        pass
                    bm_msg = f"|s|{my_status}|ss|{my_statstring}|ls|{my_locstring}|ip|{ip_int}|p|0|qm|0"
                    bm_response = f"\\bm\\100\\f\\{self.persona_id}\\msg\\{bm_msg}\\final\\"
                    with contextlib.suppress(Exception):
                        sender_client.transport.write(bm_response.encode())

            return ""  # No direct response needed

        except Exception as e:
            logger.warning("Error accepting buddy request: %s", e)
            return ""

    def handle_pinvite(self, request_data: dict[str, str]) -> str:
        r"""
        Handle \pinvite\ command - Send a game invite to a buddy.

        Request fields:
        - sesskey: Session key
        - profileid: Profile ID to invite
        - productid: Game product ID (11419 for RA3)
        - location: Lobby info string

        The location format is:
        "<channel_id> <unknown> <flags> PW: #HOST:<host> <topic> #FROM:<inviter> #CHAN:<channel>"

        Response:
        - No direct response, but server forwards invite to target
        """
        logger.debug("Processing pinvite")

        request_data.get("sesskey", self.sesskey)
        profile_id_str = request_data.get("profileid", "")
        product_id_str = request_data.get("productid", "11419")
        location = request_data.get("location", "")

        if not profile_id_str or not self.persona_id:
            return ""

        try:
            profile_id = int(profile_id_str)
            product_id = int(product_id_str)
        except ValueError:
            return ""

        # Create game invite in database
        try:
            create_game_invite(self.db_session, self.persona_id, profile_id, product_id, location)

            # Forward invite to target if online
            target_client = self.session_manager.get_user_by_persona_id(profile_id)
            if target_client:
                # Send \bm\101\ (game invite) to the target
                # Format: \bm\101\f\<from_profileid>\msg\|p|<productid>|l|<location>\final\
                bm_msg = f"|p|{product_id}|l|{location}"
                invite_response = f"\\bm\\101\\f\\{self.persona_id}\\msg\\{bm_msg}\\final\\"
                with contextlib.suppress(Exception):
                    target_client.transport.write(invite_response.encode())

            return ""  # No direct response to sender

        except Exception as e:
            logger.warning("Error creating game invite: %s", e)
            return ""

    def handle_delbuddy(self, request_data: dict[str, str]) -> str:
        r"""
        Handle \delbuddy\ command - Delete a buddy from friend list.

        Request fields:
        - sesskey: Session key
        - delprofileid: Profile ID of the buddy to delete

        This performs a one-way deletion - only removes the buddy from
        this user's list. If the buddy has this user in their list,
        it remains there.

        Response:
        - No response needed (silent operation)
        """
        logger.debug("Processing delbuddy")

        request_data.get("sesskey", self.sesskey)
        del_profile_id_str = request_data.get("delprofileid", "")

        if not del_profile_id_str or not self.persona_id:
            return ""

        try:
            del_profile_id = int(del_profile_id_str)
        except ValueError:
            return ""

        # Delete buddy from database (one-way)
        try:
            success = delete_buddy_one_way(self.db_session, self.persona_id, del_profile_id)

            if success:
                logger.debug("Deleted buddy %s from persona %s's friend list", del_profile_id, self.persona_id)
            else:
                logger.debug("Buddy %s was not in persona %s's friend list", del_profile_id, self.persona_id)

            return ""  # No response needed

        except Exception as e:
            logger.warning("Error deleting buddy: %s", e)
            return ""

    def connection_lost(self, exc):
        logger.debug("Connection closed for %s", self.peername)

        # Clean up session
        if self.sesskey:
            self.session_manager.unregister_user(self.sesskey)

        # Close the database session
        if self._db_session is not None:
            try:
                self._db_session.close()
            except Exception as e:
                logger.warning("Error closing database session: %s", e)
            self._db_session = None


# =============================================================================
# Server Startup
# =============================================================================


async def start_gp_server(host: str, port: int, session_manager: "SessionManager") -> asyncio.Server:
    """
    Start the GameSpy Protocol server.

    Args:
        host: Host address to bind to
        port: Port to listen on
        session_manager: SessionManager instance for tracking sessions

    Returns:
        The asyncio server instance
    """
    loop = asyncio.get_running_loop()
    server = await loop.create_server(lambda: GpServer(session_manager), host, port)
    logger.info("GP server listening on %s:%d", host, port)
    return server


# Legacy methods for backwards compatibility (used in tests)
# Test constants - dummy data for testing (not real user data)
TEST_USER_ID = "100001"
TEST_PROFILE_ID = "200001"
TEST_UNIQUENICK = "testplayer"
TEST_SESSKEY = "123456789"
TEST_SECRET = "Te5tS3cr3t"
TEST_LT_TOKEN = "TestSecretToken123"


def generate_login_response(request_data: dict[str, str]) -> str:
    """
    Legacy function for generating login response.
    Used for testing without full server context.
    """
    userid = request_data.get("userid", TEST_USER_ID)
    profileid = request_data.get("profileid", TEST_PROFILE_ID)
    uniquenick = request_data.get("uniquenick", TEST_UNIQUENICK)
    challenge = request_data.get("challenge", "")
    request_id = request_data.get("id", "1")

    sesskey = TEST_SESSKEY
    secret = TEST_SECRET

    proof_string = f"{userid}{uniquenick}{challenge}{secret}"
    proof = hashlib.md5(proof_string.encode()).hexdigest()

    lt_payload = f"{userid}|{profileid}|{TEST_LT_TOKEN}"
    lt = base64.b64encode(lt_payload.encode()).decode()

    response_parts = {
        "lc": "2",
        "sesskey": sesskey,
        "proof": proof,
        "userid": userid,
        "profileid": profileid,
        "uniquenick": uniquenick,
        "lt": lt,
        "id": request_id,
    }

    return "".join([f"\\{k}\\{v}" for k, v in response_parts.items()]) + "\\final\\"
