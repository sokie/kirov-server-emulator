"""
Match Report parser for RA3 competition service.

This module parses the binary match report data sent by the game
after a match ends.
"""

import struct
import uuid
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any

from app.models.game_config import GAME_ID_KW, GAME_ID_RA, GAME_ID_TW


class Faction:
    """Faction constants."""

    UNKNOWN = "Unknown"
    ALLIED = "Allied"
    SOVIET = "Soviet"
    EMPIRE = "Empire"
    AI = "AI"
    OBSERVER = "Observer"
    COMMENTATOR = "Commentator"
    RANDOM = "Random"


class GameType:
    """Game type constants."""

    UNKNOWN = "Unknown"
    VALID_1V1 = "Valid1v1"
    VALID_2V2 = "Valid2v2"
    VALID_3V3 = "Valid3v3"
    AUTO_MATCH_1V1 = "AutoMatch1v1"
    AUTO_MATCH_2V2 = "AutoMatch2v2"
    VALID_OTHER = "ValidOther"
    DISCONNECT = "Disconnect"
    DSYNC = "Dsync"
    AUTO_MATCH_DISCONNECT = "AutoMatchDisconnect"
    AUTO_MATCH_DSYNC = "AutoMatchDsync"
    INCOMPLETE = "Incomplete"
    CLAN_1V1 = "Clan1v1"
    CLAN_2V2 = "Clan2v2"


class ValueType(IntEnum):
    """Data value types in the report."""

    INT32 = 0
    INT16 = 1
    BYTE = 2
    STRING = 3


# Faction enum values for formula: faction_key = faction_enum * 5 + game_type
FACTION_ENUM_MAP: dict[int, str] = {
    0: Faction.ALLIED,
    1: Faction.SOVIET,
    2: Faction.EMPIRE,
}

# KW faction enum (developer_version=100)
# 12 entries: 3 groups of 3 playable factions separated by Observer/Commentator
# Confirmed from match reports: GDI=1, ZOCOM=2, SteelTalons=3, MoK=7, Scrin=9, Reaper17=10
KW_FACTION_ENUM_MAP: dict[int, str] = {
    0: "Random",
    # GDI group
    1: "GDI",
    2: "ZOCOM",
    3: "Steel Talons",
    4: "Observer",
    # Nod group
    5: "Nod",
    6: "Black Hand",
    7: "Marked of Kane",
    8: "Commentator",
    # Scrin group
    9: "Scrin",
    10: "Reaper-17",
    11: "Traveler-59",
}

TW_FACTION_ENUM_MAP: dict[int, str] = {
    0: "GDI",
    1: "Nod",
    2: "Scrin",
}

KW_FACTION_KEY_MAX = 59  # 12 factions * 5 game_types - 1

# KW game section keys (from disassembled binary format)
KW_GAME_KEY_NAMES: dict[int, str] = {
    106: "map_name",  # 0x6A - string, matchData+0x38
    107: "game_duration",  # 0x6B - int32, matchData+0x3C
    108: "game_version",  # 0x6C - string, matchData+0x40 (e.g. "1.3")
    109: "is_ranked",  # 0x6D - byte, matchData+0x44
    110: "teams_enabled",  # 0x6E - byte, matchData+0x4C
    111: "host_name",  # 0x6F - string, matchData+0x48
    112: "clan_name",  # 0x70 - string, matchData+0x50
    113: "clan_tag",  # 0x71 - string, matchData+0x54
    114: "clan_value",  # 0x72 - int32, matchData+0x58
    115: "extra_data_1",  # 0x73 - int32, matchData+0x60
    116: "extra_data_2",  # 0x74 - int32, matchData+0x64
    # Keys 117-122 are game_type_flag keys (117 + game_type)
}

# KW per-player stat base IDs (from disassembled binary format)
# Key = stat_base + game_type (0=unknown, 1=custom, 2=ranked_1v1, etc.)
KW_PLAYER_STAT_BASE_NAMES: dict[int, str] = {
    60: "duration_seconds",  # base+0x3C — only written for the local (submitting) player
    65: "career_wins",  # base+0x41
    70: "career_losses",  # base+0x46
    75: "current_win_streak",  # base+0x4B
    80: "current_loss_streak",  # base+0x50
    85: "longest_win_streak",  # base+0x55
    90: "longest_loss_streak",  # base+0x5A
    95: "disconnects",  # base+0x5F
}

# Map subfactions to parent faction for stats storage
KW_PARENT_FACTION: dict[str, str] = {
    "GDI": "GDI",
    "Steel Talons": "GDI",
    "ZOCOM": "GDI",
    "Nod": "Nod",
    "Black Hand": "Nod",
    "Marked of Kane": "Nod",
    "Scrin": "Scrin",
    "Reaper-17": "Scrin",
    "Traveler-59": "Scrin",
}

# Game type names by offset (key = base + game_type_offset)
# Offset = lobby_game_type_id - 2 (lobby IDs: 3=custom, 4=ranked_1v1, 5=ranked_2v2, 6=clan_1v1, 7=clan_2v2)
GAME_TYPE_NAMES: dict[int, str] = {
    0: "unknown",
    1: "custom",
    2: "ranked_1v1",
    3: "ranked_2v2",
    4: "clan_1v1",
    5: "clan_2v2",
}

# Player section: stat base ID → name (key = base + game_type_offset)
# Confirmed from real match reports; keys 0-14 use the faction formula instead.
PLAYER_STAT_BASE_NAMES: dict[int, str] = {
    15: "duration_seconds",  # only written for the local (submitting) player
    20: "career_wins",
    25: "career_losses",
    30: "current_win_streak",
    35: "current_loss_streak",
    40: "longest_win_streak",
    45: "longest_loss_streak",
    50: "disconnects",
    55: "desyncs",
    # Bases 60-70: gap (not seen in reports yet)
    # Bases 75+: seen as all-zero for clan_1v1, unmapped pending non-zero data
}

# Game section: key → name
GAME_KEY_NAMES: dict[int, str] = {
    61: "map_path",
    62: "duration_seconds",
    63: "version",
    64: "unknown_64",
    65: "unknown_65",
    # Keys 72-77: game_type flag (key = 72 + game_type_offset, value is flag byte)
}


def get_faction_from_key(key: int, game_id: int = GAME_ID_RA) -> tuple[str, int]:
    """
    Extract faction and game_type from player section key.

    Formula: key = faction_enum * 5 + game_type
    Where:
        - faction_enum varies by game (RA3: Allied/Soviet/Empire, TW: GDI/Nod/Scrin, KW: 12 subfactions)
        - game_type: 0=unknown, 1=custom, 2=ranked_1v1, 3=ranked_2v2, 4=clan_1v1

    Args:
        key: The player section key containing faction info.
        game_id: Game ID to select the correct faction map.

    Returns:
        Tuple of (faction_name, game_type_int).
    """
    if game_id == GAME_ID_KW:
        faction_map = KW_FACTION_ENUM_MAP
    elif game_id == GAME_ID_RA:
        faction_map = FACTION_ENUM_MAP
    elif game_id == GAME_ID_TW:
        faction_map = TW_FACTION_ENUM_MAP
    else:
        raise ValueError(f"Unsupported game_id: {game_id}")
    game_type = key % 5
    faction_enum = key // 5
    faction = faction_map.get(faction_enum, Faction.UNKNOWN)
    return faction, game_type


def get_player_key_name(key: int, game_id: int = GAME_ID_RA) -> str:
    """
    Get a human-readable name for a player section key.

    Keys 0-14 (RA3/TW) or 0-59 (KW) are faction indicators (faction_enum * 5 + game_type).
    Keys after that are stats using formula: key = stat_base + game_type_offset.
    """
    game_type = key % 5
    gt_name = GAME_TYPE_NAMES.get(game_type, f"gt{game_type}")

    if game_id == GAME_ID_KW:
        faction_key_max = KW_FACTION_KEY_MAX
        faction_map = KW_FACTION_ENUM_MAP
        stat_base_names = KW_PLAYER_STAT_BASE_NAMES
    elif game_id == GAME_ID_RA:
        faction_key_max = 14
        faction_map = FACTION_ENUM_MAP
        stat_base_names = PLAYER_STAT_BASE_NAMES
    elif game_id == GAME_ID_TW:
        faction_key_max = 14
        faction_map = TW_FACTION_ENUM_MAP
        stat_base_names = PLAYER_STAT_BASE_NAMES
    else:
        raise ValueError(f"Unsupported game_id: {game_id}")

    if 0 <= key <= faction_key_max:
        faction_enum = key // 5
        faction = faction_map.get(faction_enum, f"faction{faction_enum}")
        return f"faction_indicator.{faction}.{gt_name}"

    # KW team_id key
    if game_id == GAME_ID_KW and key == 117:
        return "team_id"

    base = key - game_type
    stat_name = stat_base_names.get(base, f"unknown_{base}")
    return f"{stat_name}.{gt_name}"


def get_game_key_name(key: int, game_id: int = GAME_ID_RA) -> str:
    """Get a human-readable name for a game section key."""
    if game_id == GAME_ID_KW:
        # KW game_type keys: 117-122
        if 117 <= key <= 122:
            gt = key - 117
            gt_name = GAME_TYPE_NAMES.get(gt, f"gt{gt}")
            return f"game_type_flag.{gt_name}"
        return KW_GAME_KEY_NAMES.get(key, f"unknown_{key}")
    elif game_id in (GAME_ID_RA, GAME_ID_TW):
        # RA3/TW game_type keys: 72-77
        if 72 <= key <= 77:
            gt = key - 72
            gt_name = GAME_TYPE_NAMES.get(gt, f"gt{gt}")
            return f"game_type_flag.{gt_name}"
        return GAME_KEY_NAMES.get(key, f"unknown_{key}")
    else:
        raise ValueError(f"Unsupported game_id: {game_id}")


@dataclass
class MatchPlayer:
    """Represents a player in a match."""

    full_id: str
    faction: str
    is_winner: bool
    team_id: int = 0


@dataclass
class Roster:
    """Roster entry with player ID and team ID."""

    player_id: uuid.UUID
    team_id: int


@dataclass
class DataValue:
    """A typed data value from the report."""

    value_type: ValueType
    value: Any


@dataclass
class ParsedPlayer:
    """Parsed player information."""

    full_id: str
    faction: str
    result: int  # 0=win, 1=loss, 3=disconnect, 4=dsync
    team_id: int = 0


class BinaryReader:
    """Helper class to read binary data with a cursor."""

    def __init__(self, data: bytes):
        self.data = data
        self.pos = 0

    def read_bytes(self, length: int) -> bytes:
        """Read a specific number of bytes."""
        result = self.data[self.pos : self.pos + length]
        self.pos += length
        return result

    def read_uint32_be(self) -> int:
        """Read a big-endian unsigned 32-bit integer."""
        return struct.unpack(">I", self.read_bytes(4))[0]

    def read_int32_be(self) -> int:
        """Read a big-endian signed 32-bit integer."""
        return struct.unpack(">i", self.read_bytes(4))[0]

    def read_uint16_be(self) -> int:
        """Read a big-endian unsigned 16-bit integer."""
        return struct.unpack(">H", self.read_bytes(2))[0]

    def read_int16_be(self) -> int:
        """Read a big-endian signed 16-bit integer."""
        return struct.unpack(">h", self.read_bytes(2))[0]

    def read_byte(self) -> int:
        """Read a single byte."""
        return self.read_bytes(1)[0]

    def read_string(self) -> str:
        """Read a length-prefixed UTF-8 string."""
        length = self.read_byte()
        return self.read_bytes(length).decode("utf-8", errors="replace")

    def read_guid(self) -> uuid.UUID:
        """Read a 16-byte UUID."""
        return uuid.UUID(bytes=self.read_bytes(16))

    def read_data_value(self) -> DataValue:
        """Read a typed data value."""
        value_type = ValueType(self.read_uint16_be())
        if value_type == ValueType.INT32:
            value = self.read_int32_be()
        elif value_type == ValueType.INT16:
            value = self.read_int16_be()
        elif value_type == ValueType.BYTE:
            value = self.read_byte()
        elif value_type == ValueType.STRING:
            value = self.read_string()
        else:
            raise ValueError(f"Unknown value type: {value_type}")
        return DataValue(value_type=value_type, value=value)

    def remaining(self) -> int:
        """Return the number of bytes remaining."""
        return len(self.data) - self.pos

    def is_empty(self) -> bool:
        """Check if there's no more data to read."""
        return self.pos >= len(self.data)


@dataclass
class MatchReport:
    """
    Parsed match report from binary data.

    The report contains information about the match result,
    players, factions, and game settings.
    """

    protocol_version: int = 0
    developer_version: int = 0
    checksum: bytes = b""
    game_status: int = 0
    flags: int = 0
    player_count: int = 0
    team_count: int = 0
    game_key_count: int = 0
    player_key_count: int = 0
    team_key_count: int = 0
    roster_section: list[Roster] = field(default_factory=list)
    auth_section: bytes = b""
    result_section: bytes = b""
    game_section: dict[int, DataValue] = field(default_factory=dict)
    player_section: list[dict[int, DataValue]] = field(default_factory=list)
    team_section: list[dict[int, DataValue]] = field(default_factory=list)
    parsed_players: list[ParsedPlayer] = field(default_factory=list)
    is_auto_match: bool = False
    game_id: int = 0

    @property
    def is_kw(self) -> bool:
        """Check if this is a Kane's Wrath report (developer_version=100)."""
        return self.developer_version == 100

    @property
    def is_tw(self) -> bool:
        """Check if this is a Tiberium Wars report."""
        return self.game_id == GAME_ID_TW

    @property
    def is_ra3(self) -> bool:
        """Check if this is a Red Alert 3 report."""
        return not self.is_kw and not self.is_tw

    @classmethod
    def from_bytes(cls, data: bytes, game_id: int = 0) -> "MatchReport":
        """Parse a match report from binary data."""
        reader = BinaryReader(data)

        report = cls()
        report.game_id = game_id
        report.protocol_version = reader.read_uint32_be()
        report.developer_version = reader.read_uint32_be()
        report.checksum = reader.read_bytes(16)
        report.game_status = reader.read_uint32_be()
        report.flags = reader.read_uint32_be()
        report.player_count = reader.read_uint16_be()
        report.team_count = reader.read_uint16_be()
        report.game_key_count = reader.read_uint16_be()
        report.player_key_count = reader.read_uint16_be()
        report.team_key_count = reader.read_uint16_be()
        reader.read_bytes(2)  # padding

        roster_section_length = reader.read_int32_be()
        auth_section_length = reader.read_int32_be()
        result_section_length = reader.read_int32_be()
        game_section_length = reader.read_int32_be()
        player_section_length = reader.read_int32_be()
        team_section_length = reader.read_int32_be()

        # Roster section
        roster_data = BinaryReader(reader.read_bytes(roster_section_length))
        while not roster_data.is_empty():
            player_id = roster_data.read_guid()
            team_id = roster_data.read_int32_be()
            report.roster_section.append(Roster(player_id=player_id, team_id=team_id))

        # Auth section
        report.auth_section = reader.read_bytes(auth_section_length)

        # Result section
        report.result_section = reader.read_bytes(result_section_length)

        # Game section
        game_data = BinaryReader(reader.read_bytes(game_section_length))
        while not game_data.is_empty():
            key = game_data.read_uint16_be()
            value = game_data.read_data_value()
            report.game_section[key] = value

        # Player section
        player_data = BinaryReader(reader.read_bytes(player_section_length))
        while not player_data.is_empty():
            player_dict: dict[int, DataValue] = {}
            key_count = player_data.read_uint16_be()
            for _ in range(key_count):
                key = player_data.read_uint16_be()
                value = player_data.read_data_value()
                player_dict[key] = value
            report.player_section.append(player_dict)

        # Team section
        team_data = BinaryReader(reader.read_bytes(team_section_length))
        while not team_data.is_empty():
            team_dict: dict[int, DataValue] = {}
            key_count = team_data.read_uint16_be()
            for _ in range(key_count):
                key = team_data.read_uint16_be()
                value = team_data.read_data_value()
                team_dict[key] = value
            report.team_section.append(team_dict)

        # Parse player list
        report._process_player_list()

        return report

    def _process_player_list(self) -> None:
        """Process the roster and player sections to extract player information."""
        for i in range(self.player_count):
            if i >= len(self.roster_section):
                break

            roster_entry = self.roster_section[i]

            # Player GUID (connectionId) structure: 000aaaaa-XXXX-XXXX-fe00-{MAC_ADDRESS}
            # The GUID is constructed locally from the player's network adapter MAC address.
            # It is NOT a server persona ID — do not try to extract one from it.
            full_id = str(roster_entry.player_id)
            team_id = roster_entry.team_id

            faction = Faction.UNKNOWN
            player_data = self.player_section[i] if i < len(self.player_section) else {}

            # Detect faction from player section keys using formula:
            # key = faction_enum * 5 + game_type
            # RA3/TW: keys 0-14 (3 factions * 5 game_types)
            # KW: keys 0-59 (12 factions * 5 game_types)
            if self.is_kw:
                faction_key_max = KW_FACTION_KEY_MAX
                faction_map = KW_FACTION_ENUM_MAP
            elif self.is_ra3:
                faction_key_max = 14
                faction_map = FACTION_ENUM_MAP
            elif self.is_tw:
                faction_key_max = 14
                faction_map = TW_FACTION_ENUM_MAP
            else:
                raise ValueError(f"Unsupported game_id: {self.game_id}")
            for key, value in player_data.items():
                if value.value_type == ValueType.INT16 and 0 <= key <= faction_key_max:
                    faction_enum = key // 5
                    detected_faction = faction_map.get(faction_enum, Faction.UNKNOWN)
                    faction = detected_faction
                    break

            # Result: 0=win, 1=loss, 3=disconnect, 4=dsync
            result = 0
            result_idx = i * 4 + 3
            if result_idx < len(self.result_section):
                result = self.result_section[result_idx]

            self.parsed_players.append(
                ParsedPlayer(
                    full_id=full_id,
                    faction=faction,
                    result=result,
                    team_id=team_id,
                )
            )

    def get_player_list(self) -> list[MatchPlayer]:
        """Get the list of players with their match results."""
        return [
            MatchPlayer(
                full_id=p.full_id,
                faction=p.faction,
                is_winner=(p.result == 0),
                team_id=p.team_id,
            )
            for p in self.parsed_players
        ]

    def get_local_player_index(self) -> int | None:
        """
        Identify the local (submitting) player by checking for duration_seconds.

        The game only writes duration_seconds for the local player's stats.
        KW base=60, RA3/TW base=15, key = base + game_type (0-4).
        """
        if self.is_kw:
            duration_keys = range(60, 65)
        elif self.is_ra3 or self.is_tw:
            duration_keys = range(15, 20)
        else:
            raise ValueError(f"Unsupported game_id: {self.game_id}")
        for i, section in enumerate(self.player_section):
            if section.keys() & set(duration_keys):
                return i
        return None

    def get_map_path(self) -> str:
        """Get the map path from the report."""
        if self.is_kw:
            key = 106
        elif self.is_ra3 or self.is_tw:
            key = 61
        else:
            raise ValueError(f"Unsupported game_id: {self.game_id}")
        return str(self.game_section[key].value) if key in self.game_section else ""

    def get_replay_guid(self) -> str:
        """Get the replay GUID from the report."""
        if 67 in self.game_section:
            return str(self.game_section[67].value)
        return ""

    def get_duration(self) -> int:
        """
        Get the game duration in seconds from the report.

        Returns:
            Duration in seconds, or 0 if not available (partial reports).
        """
        if self.is_kw:
            key = 107
        elif self.is_ra3 or self.is_tw:
            key = 62
        else:
            raise ValueError(f"Unsupported game_id: {self.game_id}")
        return int(self.game_section[key].value) if key in self.game_section else 0

    def get_game_type_from_key(self) -> int:
        """
        Extract game_type from Game Section key.

        The game section contains a key in range 72-77 (RA3/TW) or 117-122 (KW):
        key = base + game_type, where base is 72 (RA3/TW) or 117 (KW).

        Game type offsets (= lobby_game_type_id - 2):
            0 = unknown
            1 = custom/unranked (lobby ID 3)
            2 = ranked_1v1 (lobby ID 4)
            3 = ranked_2v2 (lobby ID 5)
            4 = clan_1v1 (lobby ID 6)
            5 = clan_2v2 (lobby ID 7)

        Returns:
            The game_type integer (0-5), defaults to 0 if not found.
        """
        if self.is_kw:
            base, end = 117, 122
        elif self.is_ra3 or self.is_tw:
            base, end = 72, 77
        else:
            raise ValueError(f"Unsupported game_id: {self.game_id}")
        for key in self.game_section:
            if base <= key <= end:
                return key - base
        return 0  # Default to unranked

    def is_clan_game(self) -> bool:
        """Check if this is a clan game based on team_count."""
        return self.team_count > 0

    def get_game_type(self) -> str:
        """Determine the game type based on game section key and player results."""
        # First check for disconnect/dsync
        for player in self.parsed_players:
            if player.result == 3:
                return GameType.DISCONNECT
            elif player.result == 4:
                return GameType.DSYNC

        # Get game_type from game section key
        game_type_int = self.get_game_type_from_key()

        # Map game_type offset to GameType string
        # Offsets: 0=unknown, 1=custom, 2=ranked_1v1, 3=ranked_2v2, 4=clan_1v1, 5=clan_2v2
        game_type_map = {
            0: GameType.VALID_OTHER,
            1: GameType.VALID_OTHER,  # custom/unranked
            2: GameType.VALID_1V1,  # ranked 1v1
            3: GameType.VALID_2V2,  # ranked 2v2
            4: GameType.CLAN_1V1,
            5: GameType.CLAN_2V2,
        }

        return game_type_map.get(game_type_int, GameType.VALID_OTHER)

    def get_faction_list(self) -> list[str]:
        """Get list of all player factions."""
        return [p.faction for p in self.parsed_players]
