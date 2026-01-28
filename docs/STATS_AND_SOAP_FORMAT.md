# Match Report Binary Format and SOAP Endpoints

This document describes the binary match report format used by Red Alert 3 and the SOAP endpoints for the Competition service.

## Competition Service SOAP Endpoints

The Competition service handles match session tracking and report submission.

**Endpoint:** `/competitionservice/competitionservice.asmx`

### CreateSession

Creates a new match session. Called by the match host when starting a ranked game.

**Request:**
```xml
<CreateSession xmlns="http://gamespy.net/competition/">
  <certificate>
    <profileid>12345</profileid>
    <userid>67890</userid>
    ...
  </certificate>
</CreateSession>
```

**Response:**
```xml
<CreateSessionResponse xmlns="http://gamespy.net/competition/">
  <csid>abc123...</csid>
  <ccid>xyz789...</ccid>
</CreateSessionResponse>
```

- `csid`: Competition Session ID - unique identifier for the match
- `ccid`: Competition Channel ID - identifier for the host player

### SetReportIntention

Signals that a player intends to submit a match report. Called by each player at the end of a match.

**Request:**
```xml
<SetReportIntention xmlns="http://gamespy.net/competition/">
  <csid>abc123...</csid>
  <ccid>xyz789...</ccid>
  <certificate>
    <profileid>12345</profileid>
    ...
  </certificate>
</SetReportIntention>
```

**Response:**
```xml
<SetReportIntentionResponse xmlns="http://gamespy.net/competition/">
  <csid>abc123...</csid>
  <ccid>player_ccid...</ccid>
</SetReportIntentionResponse>
```

The server generates a unique `ccid` for each player who sets their report intention.

### SubmitReport

Submits the match report binary data.

**Request:** Mixed XML + Binary
- XML SOAP envelope with `csid`, `ccid`, and `certificate`
- Marker: `application/bin\0`
- Raw binary report data

**Response:**
```xml
<SubmitReportResponse xmlns="http://gamespy.net/competition/">
  <SubmitReportResult>1</SubmitReportResult>
</SubmitReportResponse>
```

## Binary Match Report Format

The match report is a binary structure sent by each player after a match ends.

### Header Structure (44 bytes)

| Offset | Size | Field | Description |
|--------|------|-------|-------------|
| 0x00 | 4 | protocol_version | Protocol version (big-endian uint32) |
| 0x04 | 4 | developer_version | Developer version (big-endian uint32) |
| 0x08 | 16 | checksum | MD5 checksum of report data |
| 0x18 | 4 | game_status | Game status flags (big-endian uint32) |
| 0x1C | 4 | flags | Additional flags (big-endian uint32) |
| 0x20 | 2 | player_count | Number of players (big-endian uint16) |
| 0x22 | 2 | team_count | Number of teams (big-endian uint16) |
| 0x24 | 2 | game_key_count | Number of game section keys (big-endian uint16) |
| 0x26 | 2 | player_key_count | Number of player section keys (big-endian uint16) |
| 0x28 | 2 | team_key_count | Number of team section keys (big-endian uint16) |
| 0x2A | 2 | padding | Padding bytes |

### Section Length Table (24 bytes)

Following the header, six 4-byte section lengths (big-endian int32):

| Section | Description |
|---------|-------------|
| roster_section_length | Length of roster data |
| auth_section_length | Length of auth data |
| result_section_length | Length of result data |
| game_section_length | Length of game section |
| player_section_length | Length of player section |
| team_section_length | Length of team section |

### Roster Section

Contains player GUIDs and team assignments. Each entry is 20 bytes:

| Size | Field | Description |
|------|-------|-------------|
| 16 | player_id | Player UUID/GUID |
| 4 | team_id | Team ID (big-endian int32) |

**Player ID Format:**
The player's persona ID is encoded in the last 8 hex characters of the UUID.
Example: `xxxxxxxx-xxxx-xxxx-xxxx-xxxx00001234` -> persona_id = `0x1234` = 4660

### Auth Section

Raw authentication data (currently not parsed).

### Result Section

Contains match results for each player. Each player has 4 bytes, with the result code at offset 3.

**Result Codes:**
| Code | Meaning |
|------|---------|
| 0 | Win |
| 1 | Loss |
| 3 | Disconnect |
| 4 | Desync |

### Game Section

Key-value pairs with game metadata.

**Data Value Format:**
| Size | Field | Description |
|------|-------|-------------|
| 2 | key | Key ID (big-endian uint16) |
| 2 | value_type | Type (0=INT32, 1=INT16, 2=BYTE, 3=STRING) |
| varies | value | Value based on type |

**Known Game Section Keys:**
| Key | Type | Description |
|-----|------|-------------|
| 61 | STRING | Map path (e.g., "data/maps/official/...") |
| 67 | STRING | Replay GUID |

### Player Section

Contains per-player data as key-value pairs. Each player entry starts with a key count (uint16).

**Faction Detection (FACTION_KEY_MAP):**

The game uses specific keys to indicate faction selection:

| Key | Faction |
|-----|---------|
| 1 | Allied |
| 6 | Soviet |
| 11 | Empire |

Additional keys (+1, +2 from base) indicate AutoMatch games.

### Team Section

Contains per-team data as key-value pairs (similar format to player section).

## Report Types

**Partial Report:** Contains only the submitting player's data (player_count = 1).

**Final Report:** Contains all players' data (player_count > 1). Used for match finalization and ELO calculation.

## Duration Calculation

Match duration is not stored in the binary report. It is calculated server-side as:
```
duration = report_submission_time - competition_session.created_at
```
