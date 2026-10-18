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

from app.models import cnc3_stats, ra3_stats
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


# RA3 report side -> faction
FACTION_ENUM_MAP: dict[int, str] = {
    0: Faction.ALLIED,
    1: Faction.SOVIET,
    2: Faction.EMPIRE,
}

# Kane's Wrath faction by side number. Reports never carry side 0, 4 or 8.
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

SIDE_FACTION_MAPS: dict[int, dict[int, str]] = {
    GAME_ID_RA: FACTION_ENUM_MAP,
    GAME_ID_KW: KW_FACTION_ENUM_MAP,
    GAME_ID_TW: TW_FACTION_ENUM_MAP,
}

# Report game type -> stored game type (the GAME_TYPES index in game_config). Every other report game type,
# such as 0 (unknown) and 1 (custom), is stored as unranked (0).
GAME_TYPE_KEY_TO_DB: dict[int, int] = {
    2: 1,  # ranked_1v1
    3: 2,  # ranked_2v2
    4: 3,  # clan_1v1
    5: 4,  # clan_2v2
}


def persona_from_roster_guid(full_id: str) -> int | None:
    """Recover a player's persona id from their SC roster connection GUID.

    The backend mints each player's connection GUID as PPPPPPPP-BEEF-CAFE-... with the persona id in the
    leading dword, and the game round-trips that GUID verbatim into the report roster, so the leading dword
    is the persona. Returns None for a GUID without the BEEF-CAFE marker (a genuine MAC-derived id: a player
    that did not go through our backend, whose persona cannot be recovered).
    """
    try:
        parts = full_id.split("-")
        if len(parts) >= 3 and parts[1].lower() == "beef" and parts[2].lower() == "cafe":
            return int(parts[0], 16)
    except (ValueError, AttributeError):
        pass
    return None


def _cnc3_game(game_id: int) -> cnc3_stats.Cnc3Game:
    game = cnc3_stats.GAMES.get(game_id)
    if game is None:
        raise ValueError(f"Unsupported game_id: {game_id}")
    return game


def get_faction_from_key(key: int, game_id: int = GAME_ID_RA) -> tuple[str, int]:
    """Returns the faction and the game type of a player side key, or (Unknown, 0) for any other key."""
    if game_id == GAME_ID_RA:
        side_gt = ra3_stats.side_from_key(key)
    else:
        side_gt = cnc3_stats.side_from_key(_cnc3_game(game_id), key)
    if side_gt is None:
        return Faction.UNKNOWN, 0
    return SIDE_FACTION_MAPS[game_id].get(side_gt[0], Faction.UNKNOWN), side_gt[1]


def get_player_key_name(key: int, game_id: int = GAME_ID_RA, gt: int = 0) -> str:
    """Returns the name of a player section key."""
    if game_id == GAME_ID_RA:
        return ra3_stats.player_key_name(key, gt)
    return cnc3_stats.player_key_name(_cnc3_game(game_id), key, gt)


def get_game_key_name(key: int, game_id: int = GAME_ID_RA) -> str:
    """Returns the name of a game section key."""
    if game_id == GAME_ID_RA:
        return ra3_stats.game_key_name(key)
    return cnc3_stats.game_key_name(_cnc3_game(game_id), key)


@dataclass
class MatchPlayer:
    """Represents a player in a match."""

    full_id: str
    faction: str
    is_winner: bool
    team_id: int = 0
    result: int = 0
    persona_id: int | None = None


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

    @property
    def is_authoritative(self) -> bool:
        return bool(self.flags & 1)

    @property
    def report_game_id(self) -> int:
        """The report's game id. A report that is not Kane's Wrath or Tiberium Wars is RA3."""
        if self.is_kw:
            return GAME_ID_KW
        return GAME_ID_TW if self.is_tw else GAME_ID_RA

    @property
    def key_offset(self) -> int:
        """Kane's Wrath keys are 45 higher than Tiberium Wars and RA3 keys."""
        return cnc3_stats.KW.key_offset if self.is_kw else 0

    @property
    def cnc3_game(self) -> cnc3_stats.Cnc3Game | None:
        return cnc3_stats.GAMES.get(self.report_game_id)

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

            # Player GUID = the SC connection GUID. The game round-trips it verbatim from the ccid the
            # backend returned, so a backend-minted PPPPPPPP-BEEF-CAFE-... GUID carries the player's persona
            # in its leading dword (see persona_from_roster_guid). A MAC-derived GUID means the player did
            # not go through our backend and has no recoverable persona.
            full_id = str(roster_entry.player_id)
            team_id = roster_entry.team_id

            faction = Faction.UNKNOWN
            player_data = self.player_section[i] if i < len(self.player_section) else {}
            for key, value in player_data.items():
                if value.value_type == ValueType.INT16:
                    side_faction, side_gt = get_faction_from_key(key, self.report_game_id)
                    if side_gt:
                        faction = side_faction
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
                result=p.result,
                persona_id=persona_from_roster_guid(p.full_id),
            )
            for p in self.parsed_players
        ]

    def get_map_path(self) -> str:
        """Get the map path from the report."""
        key = 61 + self.key_offset
        return str(self.game_section[key].value) if key in self.game_section else ""

    def get_match_id(self) -> str:
        """Returns the lobby MatchID (game key 67). The game sends it only when key 65 is set."""
        value = self.game_section.get(67 + self.key_offset)
        return str(value.value) if value is not None else ""

    def get_ra3_mode(self) -> str:
        """Returns the career mode of an RA3 report."""
        return ra3_stats.GT_TO_MODE.get(self.get_game_type_from_key(), "unranked")

    def get_ra3_counts(self, index: int) -> dict[str, int]:
        """Returns one player's counts of an RA3 report, by career key."""
        gt = self.get_game_type_from_key()
        section = self.player_section[index] if index < len(self.player_section) else {}
        counts: dict[str, int] = {}
        for stat in ra3_stats.REPORT_STATS:
            value = section.get(stat.report_base + gt)
            if value is not None and value.value_type in (ValueType.INT32, ValueType.INT16, ValueType.BYTE):
                counts[stat.key] = int(value.value)
        return counts

    def get_cnc3_mode(self) -> str:
        """Returns the career mode of a Tiberium Wars or Kane's Wrath report."""
        return cnc3_stats.GT_TO_MODE.get(self.get_game_type_from_key(), "unranked")

    def get_cnc3_counts(self, index: int) -> dict[str, int]:
        """Returns one player's counts of a Tiberium Wars or Kane's Wrath report, by career key."""
        game = self.cnc3_game
        if game is None:
            return {}
        gt = self.get_game_type_from_key()
        section = self.player_section[index] if index < len(self.player_section) else {}
        counts: dict[str, int] = {}
        for stat in game.report_stats:
            value = section.get(stat.report_base + game.key_offset + gt)
            if value is not None and value.value_type in (ValueType.INT32, ValueType.INT16, ValueType.BYTE):
                counts[stat.key] = int(value.value)
        return counts

    def get_duration(self) -> int:
        """Returns the match length in seconds, or 0 for a partial report, which does not carry it."""
        key = 62 + self.key_offset
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
        base = ra3_stats.GAME_KEY_MODE_BASE + self.key_offset
        for key in self.game_section:
            if base <= key <= base + 5:
                return key - base
        return 0  # Default to unranked

    def get_db_game_type(self) -> int:
        """The mode this match was played in, as a GAME_TYPES index (0=unranked ... 4=clan_2v2).

        Reads the game section key, so it is independent of how the match ended - unlike get_game_type(),
        which reports "Disconnect"/"Dsync" as soon as any player drops and would lose the ranked mode.
        """
        return GAME_TYPE_KEY_TO_DB.get(self.get_game_type_from_key(), 0)

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
