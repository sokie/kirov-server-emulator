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


def get_faction_from_key(key: int) -> tuple[str, int]:
    """
    Extract faction and game_type from player section key.

    Formula: key = faction_enum * 5 + game_type
    Where:
        - faction_enum: 0=Allied, 1=Soviet, 2=Empire
        - game_type: 0=unranked, 1=ranked_1v1, 2=ranked_2v2, 3=???, 4=clan_1v1, 5=clan_2v2

    Args:
        key: The player section key containing faction info.

    Returns:
        Tuple of (faction_name, game_type_int).
    """
    game_type = key % 5
    faction_enum = key // 5
    faction = FACTION_ENUM_MAP.get(faction_enum, Faction.UNKNOWN)
    return faction, game_type


@dataclass
class MatchPlayer:
    """Represents a player in a match."""

    full_id: str
    persona_id: int
    faction: str
    is_winner: bool
    team_id: int = 0
    persona_id_valid: bool = True  # False if persona_id looks corrupted


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
    player_id: int
    faction: str
    result: int  # 0=win, 1=loss, 3=disconnect, 4=dsync
    team_id: int = 0
    player_id_valid: bool = True  # False if persona_id looks corrupted


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

    @classmethod
    def from_bytes(cls, data: bytes) -> "MatchReport":
        """Parse a match report from binary data."""
        reader = BinaryReader(data)

        report = cls()
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
        auto_match_count = 0

        for i in range(self.player_count):
            if i >= len(self.roster_section):
                break

            roster_entry = self.roster_section[i]

            # Player GUID contains the persona ID in the last 8 hex chars
            full_id = str(roster_entry.player_id)
            try:
                player_id = int(full_id[24:32], 16)
            except (ValueError, IndexError):
                player_id = 0

            # Get team_id from roster entry
            team_id = roster_entry.team_id

            faction = Faction.UNKNOWN
            player_data = self.player_section[i] if i < len(self.player_section) else {}

            # Detect faction from player section keys using formula:
            # key = faction_enum * 5 + game_type
            # Find INT16 keys in range 0-14 (covers all faction/game_type combos)
            for key, value in player_data.items():
                if value.value_type == ValueType.INT16 and 0 <= key <= 14:
                    detected_faction, detected_game_type = get_faction_from_key(key)
                    faction = detected_faction
                    # game_type 1 or 2 indicates auto-match (ranked)
                    if detected_game_type in (1, 2):
                        auto_match_count += 1
                    break

            # Result: 0=win, 1=loss, 3=disconnect, 4=dsync
            result = 0
            result_idx = i * 4 + 3
            if result_idx < len(self.result_section):
                result = self.result_section[result_idx]

            # Validate persona_id - valid IDs are typically < 50,000,000 and follow 0x00A8xxxx pattern
            # Invalid IDs often come from opponent data in final reports where the game client
            # doesn't know the actual persona_id
            player_id_valid = 0 < player_id < 50_000_000

            self.parsed_players.append(
                ParsedPlayer(
                    full_id=full_id,
                    player_id=player_id,
                    faction=faction,
                    result=result,
                    team_id=team_id,
                    player_id_valid=player_id_valid,
                )
            )

        self.is_auto_match = auto_match_count > 0

    def get_player_list(self) -> list[MatchPlayer]:
        """Get the list of players with their match results."""
        return [
            MatchPlayer(
                full_id=p.full_id,
                persona_id=p.player_id,
                faction=p.faction,
                is_winner=(p.result == 0),
                team_id=p.team_id,
                persona_id_valid=p.player_id_valid,
            )
            for p in self.parsed_players
        ]

    def get_map_path(self) -> str:
        """Get the map path from the report."""
        if 61 in self.game_section:
            return str(self.game_section[61].value)
        return ""

    def get_replay_guid(self) -> str:
        """Get the replay GUID from the report."""
        if 67 in self.game_section:
            return str(self.game_section[67].value)
        return ""

    def get_duration(self) -> int:
        """
        Get the game duration in seconds from the report.

        Key 62 contains the duration as INT32, only present in final reports.

        Returns:
            Duration in seconds, or 0 if not available (partial reports).
        """
        if 62 in self.game_section:
            return int(self.game_section[62].value)
        return 0

    def get_game_type_from_key(self) -> int:
        """
        Extract game_type from Game Section key.

        The game section contains a key in range 72-77 where:
        key = 72 + game_type

        Game types:
            0 = unranked
            1 = ranked_1v1
            2 = ranked_2v2
            3 = ???
            4 = clan_1v1
            5 = clan_2v2

        Returns:
            The game_type integer (0-5), defaults to 0 (unranked) if not found.
        """
        for key in self.game_section:
            if 72 <= key <= 77:
                return key - 72
        return 0  # Default to unranked

    def is_clan_game(self) -> bool:
        """Check if this is a clan game based on team_count."""
        return self.team_count > 0

    def get_game_type(self) -> str:
        """Determine the game type based on game section key and player results."""
        # First check for disconnect/dsync
        for player in self.parsed_players:
            if player.result == 3:
                return GameType.AUTO_MATCH_DISCONNECT if self.is_auto_match else GameType.DISCONNECT
            elif player.result == 4:
                return GameType.AUTO_MATCH_DSYNC if self.is_auto_match else GameType.DSYNC

        # Get game_type from game section key
        game_type_int = self.get_game_type_from_key()

        # Count winners for 1v1 vs 2v2 distinction
        winner_count = sum(1 for p in self.parsed_players if p.result == 0)

        # Map game_type_int to GameType string
        # Values are (auto_match_type, non_auto_match_type) or single type
        game_type_map = {
            0: GameType.VALID_OTHER,  # unranked
            1: (GameType.AUTO_MATCH_1V1, GameType.VALID_1V1),
            2: (GameType.AUTO_MATCH_2V2, GameType.VALID_2V2),
            4: GameType.CLAN_1V1,
            5: GameType.CLAN_2V2,
        }

        if game_type_int in game_type_map:
            result = game_type_map[game_type_int]
            if isinstance(result, tuple):
                return result[0] if self.is_auto_match else result[1]
            return result

        # Fallback: use winner/loser count method
        winner_count = 0
        loser_count = 0
        for player in self.parsed_players:
            if player.result == 0:
                winner_count += 1
            elif player.result == 1:
                loser_count += 1

        if winner_count == loser_count:
            game_type_map = {
                1: GameType.AUTO_MATCH_1V1 if self.is_auto_match else GameType.VALID_1V1,
                2: GameType.AUTO_MATCH_2V2 if self.is_auto_match else GameType.VALID_2V2,
                3: GameType.VALID_3V3,
            }
            return game_type_map.get(winner_count, GameType.VALID_OTHER)

        return GameType.VALID_OTHER

    def get_player_id_list(self) -> list[int]:
        """Get list of all player IDs."""
        return [p.player_id for p in self.parsed_players]

    def get_winner_id_list(self) -> list[int]:
        """Get list of winner player IDs."""
        return [p.player_id for p in self.parsed_players if p.result == 0]

    def get_loser_id_list(self) -> list[int]:
        """Get list of loser player IDs."""
        return [p.player_id for p in self.parsed_players if p.result == 1]

    def get_faction_list(self) -> list[str]:
        """Get list of all player factions."""
        return [p.faction for p in self.parsed_players]
