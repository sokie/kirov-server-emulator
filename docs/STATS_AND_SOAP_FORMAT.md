# Match Reports, Careers and Sake (Red Alert 3)

This document describes how Red Alert 3 reports a match, how the server turns reports into careers,
and the Sake tables the game reads. Every value here was read from `RA3_1.13.game`; the addresses are
for that build. Kane's Wrath and Tiberium Wars keep their own handling and are not covered.

## When the game sends a report

- Only in an online game (game mode 4). LAN, skirmish, single-player campaign and co-op campaign
  (game modes 1, 2, 5-8) send no report.
- Only when at least two humans are in the game, and the game ran for a minimum time.
- Every human client that is still in the game sends its own report, with its own player first. AI
  players are not in the roster.
- A report is authoritative unless its own player left before the end. Only an authoritative report
  lists the other players. A report that is not authoritative lists only its own player.
- The server settles the match from the first authoritative report and ignores the others (one
  settlement per `csid`).
- The game creates one kind of report only (`scCreateReport` has one caller, developer version 5).

## Competition service

Endpoint: `/competitionservice/competitionservice.asmx`, namespace `http://gamespy.net/competition/`.

| Call | Sent by | Request | Reply |
|---|---|---|---|
| `CreateSession` | the host, at match start | certificate, proof, `gameid` 2128 | `result` 0, `csid`, `ccid` |
| `SetReportIntention` | every player, twice | certificate, `csid`, `ccid`, `gameid`, `authoritative` | `result` 0, `csid`, `ccid` |
| `SubmitReport` | every player still in the game | certificate, `csid`, `ccid`, `gameid`, `authoritative`, report | `result` 0 |

`SetReportIntention`:

- The game clears its connection id, then calls `SetReportIntention` with `authoritative` 1 and an
  empty `ccid`, then again with `authoritative` 0 and the `ccid` from the first reply.
- The SDK keeps the `ccid` of each reply and sends the last one with `SubmitReport`. The game keeps
  the first one and gives it to the other players, so it is the player's roster GUID in every report.
- So the server returns the same `ccid` when a player sends a `ccid` it already holds for that `csid`.
- The server mints each `ccid` as `PPPPPPPP-BEEF-CAFE-XXXX-XXXXXXXXXXXX` with the persona id in the first
  group, so each roster GUID names its player.

`SubmitReport` is a DIME message (`Content-Type: application/dime`): a record with the SOAP envelope,
then a record with ID `report` and type `application/bin` that holds the report bytes.

## Report layout

All numbers are big-endian.

| Offset | Size | Field |
|---|---|---|
| 0x00 | 4 | protocol version (2) |
| 0x04 | 4 | developer version (5) |
| 0x08 | 16 | MD5 of the whole report, computed with these 16 bytes set to zero |
| 0x18 | 4 | game status, always 0 (complete) |
| 0x1C | 4 | flags, bit 0 = authoritative |
| 0x20 | 2 | player count |
| 0x22 | 2 | team count |
| 0x24 | 2 | game key count |
| 0x26 | 2 | player key count, all players together |
| 0x28 | 2 | team key count |
| 0x2A | 2 | reserved |
| 0x2C | 24 | section lengths: roster, auth, results, game, player, team |

| Section | Content |
|---|---|
| roster | per player: connection GUID (16), team (4) |
| auth | per player: 16 bytes, all zero in RA3 |
| results | per player, then per team: result (4) |
| game | key/value pairs |
| player | per player: key count (2), then key/value pairs |
| team | not used by RA3 (team results are in the results section) |

A key/value pair is key (2), type (2), value. Types: 0 int32, 1 int16, 2 byte, 3 string (1-byte
length, then UTF-8, no terminator).

Results: 0 win, 1 loss, 3 disconnect, 4 desync. The game never sends 2 (draw).

- The local player: 4 on a desync; 3 if it left the game; 1 if the game did not end normally or it
  was not victorious; 0 if it won.
- Another human: 4 on a desync; 1 or 3 if it left, by the time it left; 0 if victorious, else 1.
- Teams (clan modes only, authoritative reports only): a team gets 0 if any member won, else the first
  of 1, 3, 4 that a member has.

### Mode index

The game writes a mode index `gt` = lobby type - 2.

| Lobby type | gt | Mode | Sake suffix |
|---|---|---|---|
| 3 | 1 | unranked (custom) | `UNRANKED` |
| 4 | 2 | ranked 1v1 | `RANKED1V1` |
| 5 | 3 | ranked 2v2 | `RANKED2V2` |
| 6 | 4 | clan 1v1 | `CLAN1V1` |
| 7 | 5 | clan 2v2 | `CLAN2V2` |

Because `gt` runs from 1 to 5, `key % 5` does not give the mode: for clan 2v2 it gives 0, and the
bases from 77 up are not multiples of 5. Read `gt` from the game section, then subtract it.

### Game keys

Written in this order: mode flag, 61, 63, 64, 65, 62, 67, 68, 69, 70, 71, 66.

| Key | Type | Value | Sent |
|---|---|---|---|
| 72 + gt | byte | 1, the mode flag | always |
| 61 | string | map name | always |
| 62 | int32 | match length in seconds | when the game ended normally |
| 63 | string | game version, "1.13" | always |
| 64 | byte | 1 when the map is in the map cache and its record byte +0x37 is 0 | always |
| 65 | byte | 1 when the lobby has a MatchID | always |
| 66 | string | map display name | when not empty |
| 67 | string | the lobby MatchID, the same value the NewsTicker search filters on | with 65 |
| 68 | string | a second lobby string (game-info vtable +0x68) | with 65 |
| 69 | int32 | value +0x5C of an AI slot | with 65, when above 0 |
| 70 | int32 | MultiplayerSettings +0x84 | when above 0 |
| 71 | int32 | MultiplayerSettings +0x88 | with 70 |

### Player keys

The local player comes first, then the other humans. Values are this match's score keeper counts.
The game runs in lockstep, so every client sends the same counts.

| Key | Type | Value | Career key |
|---|---|---|---|
| side * 5 + gt (1-15) | int16 | 1; side 0 Allied, 1 Soviet, 2 Japan | faction |
| 15 + gt | int32 | match length, local player only | - |
| 72 | int32 | a value of the local player, clan modes only | - |
| 20 + gt | int32 | structures built | `structures_built` |
| 25 + gt | int32 | structures lost | `structures_lost` |
| 30 + gt | int32 | structures destroyed | `structures_destroyed` |
| 35 + gt | int32 | structures captured | `structures_captured` |
| 40 + gt | int32 | units built | `units_built` |
| 45 + gt | int32 | units lost | `units_lost` |
| 50 + gt | int32 | units killed | `units_killed` |
| 55 + gt | int32 | seconds of a timed score keeper state (not read from Sake) | `timed_state_seconds` |
| 77 + gt | int32 | value of units lost | `units_lost_value` |
| 82 + gt | int32 | value of units killed | `units_killed_value` |
| 87 + gt | int32 | units lost to friendly fire | `units_killed_allied` |
| 92 + gt | int32 | special abilities used | `units_activated` |
| 97 + gt | int32 | powers activated | `powers_activated` |
| 102 + gt | int32 | structures infiltrated | `structures_infiltrated` |

The report carries no career totals. Wins, losses and streaks come from the results.

## Careers

- Each settled match is stored in `ra3_match` (csid, mode, map, MatchID, length, players with their
  result, faction and counts) and then folded onto each player's career.
- The fold is the one the client applies to its own `Stats_<mode>.ini` files
  (`Stats_UpdateLocalCareer`, 0x00636D40):
  - `total_matches` +1, `total_time_played` + match length.
  - A win: `wins` +1, `current_loss_streak` = 0, `current_win_streak` +1, `longest_win_streak` = max.
  - Any other result: `losses` +1, `current_win_streak` = 0, `current_loss_streak` +1,
    `longest_loss_streak` = max.
  - Result 3 adds `disconnects`, result 4 adds `desyncs`.
  - The report counts add up.
  - Matches, wins, losses, time and streaks are also kept per faction.
- Derived columns are computed when read: `WinLossRatio` = wins / max(losses, 1),
  `UnitKillDeathRatio` = units killed / max(units lost, 1), `AverageGameLength` = time played / matches.
- Score and rank: after a win or a loss, Score grows by a `ScoringMultipliers` value. The column is
  picked by (won, ranked), and every mode but unranked counts as ranked. Rank is the highest level
  whose `Levels` score the player has. The client predicts the same after each match. A player who
  left or desynced gets no score.
- `scripts/ra3_stats_tool.py rebuild` clears every RA3 career, score and rank and folds `ra3_match`
  again. ELO is not touched.
- The full stat list, with the stats the client keeps only for itself, is in
  [`ra3_stat_catalog.csv`](ra3_stat_catalog.csv).

## Sake tables

Endpoint: `/SakeStorageServer/StorageServer.asmx`. The game calls `GetMyRecords`, `SearchForRecords`,
`GetSpecificRecords` and `CreateRecord` (custom maps only). It never writes stats to Sake.

| Table | Call | Request | Reply |
|---|---|---|---|
| `PlayerStats_v5` | GetMyRecords | 190 career columns | one value per column, in order |
| `PlayerStats_v5` | GetMyRecords | `Score`, `Rank` | the player's score and rank |
| `PlayerStats_v5` | SearchForRecords | `ownerid=N`, sort `recordid`, `Rank`, `ownerid` | another player's rank |
| `Levels` | SearchForRecords | `Level>0`, sort `Level`, max 1000, `Score` | the first score of each rank |
| `ScoringMultipliers` | GetSpecificRecords | record 1: `UnrankedLosses`, `UnrankedWins`, `RankedLosses`, `RankedWins` | shorts 1, 2, 2, 5 |
| `NewsTicker` | SearchForRecords | `MatchID = '<id>' or MatchID = '-1'`, sort `TickerType desc` | ticker lines |
| `custom_maps` | SearchForRecords, CreateRecord | `mapCRC=<crc>` | map sharing |

- The 190 columns are `<Stat>_<MODE>` for 26 stats and, for `TotalMatches`, `CareerLosses`,
  `CareerWins` and `WinLossRatio`, also `<Stat>_<ALLIED|SOVIET|JAPAN>_<MODE>`. The game maps each
  column to {lobby type, faction, stat id} with the table at 0x00C1D4D0 and stores only int (type 2)
  and float (type 3) values; the ratios are floats.
- `PlayerStats_v5` has one record per persona; a player without matches reads zeroes and rank 1.
- Searches follow the SDK: `filter` and `targetRecordFilter` (comparisons, `and`, `or`, `not`, `in`,
  `like`, `is null`), a multi-column `sort` with `desc`, `offset` and `max`, `surrounding` around the
  target, `ownerids`, and `row` as the position.
- The game has reply handlers for `RatingMatch` and `RatingPlayer`, but no build from 1.0 to 1.13
  sends those searches.
