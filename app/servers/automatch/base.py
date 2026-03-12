"""Base classes for the automatch game factory architecture."""

import random
from abc import ABC, abstractmethod
from dataclasses import dataclass, field


@dataclass
class BasePlayer:
    """Shared fields every game's player must have."""

    nickname: str
    profile_id: int
    ip: int = 0
    side: int = -1
    color: int = -1
    nat: int = 0
    num_players: int = 2
    map_bitset: str = ""
    ladder_id: int = 0
    queued_at: float = 0.0
    points: int = 1000
    infos: dict[str, str] = field(default_factory=dict)


class GameFactory(ABC):
    """Abstract factory that encapsulates all game-specific automatch logic."""

    @property
    @abstractmethod
    def game_id(self) -> str: ...

    @property
    @abstractmethod
    def nickname(self) -> str: ...

    @property
    @abstractmethod
    def username(self) -> str: ...

    @property
    @abstractmethod
    def channels(self) -> list[str]: ...

    @property
    @abstractmethod
    def match_interval(self) -> float: ...

    @property
    @abstractmethod
    def valid_num_players(self) -> list[int]: ...

    @abstractmethod
    def build_player(self, nickname: str, profile_id: int, infos: dict[str, str]) -> BasePlayer:
        """Build a game-specific player from parsed CINFO values."""
        ...

    @abstractmethod
    def try_match(self, players: dict[str, BasePlayer]) -> list[tuple[list[BasePlayer], str]] | None:
        """
        Attempt to match players from the queue.

        Returns a list of (matched_players, formatted_message) tuples,
        or None if no matches were found.
        """
        ...

    def handle_extra_command(self, command: str, player: BasePlayer) -> str | None:
        """Handle a game-specific command. Returns a response message or None."""
        return None

    def get_supported_commands(self) -> set[str]:
        """Return the set of extra commands this game supports."""
        return set()

    def on_match_loop_tick(self, players: dict[str, BasePlayer], now: float) -> list[tuple[str, str]]:
        """
        Called each match loop tick. Returns list of (nickname, message) to send.

        Use for timers, periodic checks, etc.
        """
        return []

    def create_bot(self):
        """Create the bot instance for this game. Override for custom bot types."""
        from app.servers.automatch.bot import AutoMatchBot

        return AutoMatchBot(self)


def find_common_maps(bitset1: str, bitset2: str) -> str:
    """
    AND two map bitsets. Returns empty string if no common maps.

    Each character is '1' (available) or '0' (unavailable).
    Bitsets must be the same length.
    """
    if not bitset1 or not bitset2 or len(bitset1) != len(bitset2):
        return ""

    result = ""
    has_common = False
    for c1, c2 in zip(bitset1, bitset2):
        if c1 == "1" and c2 == "1":
            result += "1"
            has_common = True
        else:
            result += "0"

    return result if has_common else ""


def pick_random_map_index(common_bitset: str) -> int:
    """Pick a random map index from a common bitset. Returns -1 if none available."""
    indices = [i for i, c in enumerate(common_bitset) if c == "1"]
    return random.choice(indices) if indices else -1


# GameSpy peerchat username encoding (piMangleIP / piDemangleUser)
# Format: X<8 encoded chars>X|<profileID>
# The game decodes the bot's username to validate the sender before accepting
# any MBOT: messages. An invalid username causes all messages to be silently dropped.

_GAMESPY_XOR_KEY = 0xC3801DC7
_GAMESPY_ALPHABET = "aFl4uOD9sfWq1vGp"
_HEX_CHARS = "0123456789abcdef"


def encode_gamespy_username(ip: int, profile_id: int) -> str:
    """Encode an IP + profile ID into GameSpy peerchat username format."""
    xored = ip ^ _GAMESPY_XOR_KEY
    hex_str = f"{xored:08x}"
    encoded = "".join(_GAMESPY_ALPHABET[_HEX_CHARS.index(c)] for c in hex_str)
    return f"X{encoded}X|{profile_id}"
