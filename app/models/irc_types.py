"""
IRC/Peerchat protocol message types and data structures.
Implements standard IRC commands with GameSpy extensions.
"""

from contextvars import ContextVar
from dataclasses import dataclass, field

# Context variable for per-client IRC data (similar to FESL client_data_var)
irc_client_data_var = ContextVar("irc_client_data", default={})


@dataclass
class IRCMessage:
    """
    Represents a standard IRC protocol message.
    Format: [:<prefix>] <command> <params> [:<trailing>]
    """

    command: str
    params: list[str] = field(default_factory=list)
    prefix: str | None = None

    def serialize(self) -> str:
        """
        Convert to IRC wire format.

        Returns:
            IRC message string (without CRLF terminator)
        """
        parts = []

        if self.prefix:
            parts.append(f":{self.prefix}")

        parts.append(self.command)

        if self.params:
            # Last parameter may contain spaces, prefix with ':'
            if len(self.params) > 1:
                parts.extend(self.params[:-1])
                parts.append(f":{self.params[-1]}")
            elif " " in self.params[0] or self.params[0].startswith(":"):
                parts.append(f":{self.params[0]}")
            else:
                parts.append(self.params[0])

        return " ".join(parts)

    @staticmethod
    def parse(line: str) -> "IRCMessage":
        """
        Parse an IRC message from wire format.

        Args:
            line: IRC message string (without CRLF)

        Returns:
            Parsed IRCMessage object
        """
        prefix = None
        trailing = None

        if line.startswith(":"):
            prefix, line = line[1:].split(" ", 1)

        if " :" in line:
            line, trailing = line.split(" :", 1)

        parts = line.split()
        command = parts[0] if parts else ""
        params = parts[1:] if len(parts) > 1 else []

        if trailing is not None:
            params.append(trailing)

        return IRCMessage(command=command, params=params, prefix=prefix)


@dataclass
class IRCChannel:
    """Represents an IRC channel."""

    name: str
    topic: str | None = None
    modes: str = ""
    users: set[str] = field(default_factory=set)  # Set of nicknames
    operators: set[str] = field(default_factory=set)  # Set of operator nicknames
    user_stats: dict[str, dict[str, str]] = field(default_factory=dict)  # GameSpy user stats

    def is_private(self) -> bool:
        """Check if this is a private channel (GameSpy game lobby)."""
        return self.name.startswith("#GSP!")

    def is_operator(self, nickname: str) -> bool:
        """Check if user is channel operator."""
        return nickname in self.operators


@dataclass
class IRCUser:
    """Represents an IRC user/client."""

    nickname: str | None = None
    username: str | None = None
    realname: str | None = None
    hostname: str | None = None
    authenticated: bool = False
    channels: set[str] = field(default_factory=set)  # Set of channel names
    stats: dict[str, str] = field(default_factory=dict)  # GameSpy user attributes

    # GameSpy-specific fields
    profile_id: int | None = None
    user_id: int | None = None
    session_token: str | None = None
    cdkey_hash: str | None = None

    def get_prefix(self) -> str:
        """
        Get the IRC user prefix (nickname!username@hostname).
        GameSpy uses * as the hostname in messages.

        Returns:
            User prefix string
        """
        nick = self.nickname or "*"
        user = self.username or "unknown"
        # GameSpy uses * as the hostname in JOIN/PART/PRIVMSG etc.
        return f"{nick}!{user}@*"

    def is_registered(self) -> bool:
        """Check if user has completed registration (has both NICK and USER)."""
        return self.nickname is not None and self.username is not None


# IRC numeric reply codes (RFC 1459 and GameSpy extensions)
class IRCNumeric:
    """IRC numeric reply codes."""

    # Welcome messages (001-004)
    RPL_WELCOME = "001"
    RPL_YOURHOST = "002"
    RPL_CREATED = "003"
    RPL_MYINFO = "004"

    # MOTD (375-376)
    RPL_MOTDSTART = "375"
    RPL_MOTD = "372"
    RPL_ENDOFMOTD = "376"

    # User/channel information
    RPL_USERHOST = "302"  # USRIP response
    RPL_WHOREPLY = "352"  # WHO response
    RPL_NAMREPLY = "353"  # Channel user list
    RPL_ENDOFWHO = "315"  # End of WHO list
    RPL_ENDOFNAMES = "366"  # End of NAMES list
    RPL_TOPIC = "332"  # Channel topic
    RPL_NOTOPIC = "331"  # No topic set
    RPL_CHANNELMODEIS = "324"  # Channel mode

    # GameSpy extensions (700-709)
    RPL_CRYPT_CHALLENGE = "705"  # Server encryption challenge
    RPL_CDKEY_OK = "706"  # CD key authenticated
    RPL_GETCKEY_RESPONSE = "702"  # User stats response
    RPL_GETCKEY_END = "703"  # End of GETCKEY

    # Error codes (400-599)
    ERR_NOSUCHNICK = "401"  # No such nick/channel
    ERR_NOSUCHCHANNEL = "403"  # No such channel
    ERR_CANNOTSENDTOCHAN = "404"  # Cannot send to channel
    ERR_TOOMANYCHANNELS = "405"  # Too many channels
    ERR_NOTEXTTOSEND = "412"  # No text to send
    ERR_NOTONCHANNEL = "442"  # Not on channel
    ERR_UNKNOWNCOMMAND = "421"  # Unknown command
    ERR_NONICKNAMEGIVEN = "431"  # No nickname given
    ERR_ERRONEUSNICKNAME = "432"  # Erroneous nickname
    ERR_NICKNAMEINUSE = "433"  # Nickname already in use
    ERR_NEEDMOREPARAMS = "461"  # Need more params
    ERR_ALREADYREGISTRED = "462"  # Already registered
    ERR_PASSWDMISMATCH = "464"  # Password incorrect
    ERR_BADCHANMASK = "476"  # Bad channel mask
    ERR_CHANOPRIVSNEEDED = "482"  # Channel operator required


# GameSpy-specific commands
class GameSpyCommand:
    """GameSpy IRC extensions."""

    CRYPT = "CRYPT"  # Initialize encryption
    CDKEY = "CDKEY"  # Authenticate with CD key hash
    GETCKEY = "GETCKEY"  # Get channel user stats
    SETCKEY = "SETCKEY"  # Set channel user stats
    UTM = "UTM"  # Update game-specific data
    USRIP = "USRIP"  # Get user's IP address


# Standard IRC commands
class IRCCommand:
    """Standard IRC commands."""

    NICK = "NICK"
    USER = "USER"
    PASS = "PASS"
    JOIN = "JOIN"
    PART = "PART"
    QUIT = "QUIT"
    PRIVMSG = "PRIVMSG"
    NOTICE = "NOTICE"
    PING = "PING"
    PONG = "PONG"
    MODE = "MODE"
    TOPIC = "TOPIC"
    NAMES = "NAMES"
    LIST = "LIST"
    WHO = "WHO"
    WHOIS = "WHOIS"
    KICK = "KICK"
