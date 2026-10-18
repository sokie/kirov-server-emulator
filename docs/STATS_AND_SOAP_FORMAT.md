# Match Reports, Careers and Sake (Red Alert 3, Tiberium Wars, Kane's Wrath)

This document describes how Red Alert 3 (RA3), Tiberium Wars (TW) and Kane's Wrath (KW) report a match, how
the server turns reports into careers, and the Sake tables the games read. Every value here was read from
`RA3_1.13.game`, `cnc3game.dat` 1.10 and `cnc3ep1.dat` 1.3. The three games share the report code, so a
rule applies to all three unless a game is named.

## When a game sends a report

- Only in an online game. LAN, skirmish and every campaign mode send no report.
- Only when at least two humans are in the game, and the game ran for a minimum time.
- Every human client that is still in the game sends its own report, with its own player first. AI
  players are not in the roster.
- RA3 and TW: a report is authoritative unless its own player left before the end. Only an authoritative
  report lists the other players. A report that is not authoritative lists only its own player.
- KW: every report is authoritative. A report lists every human only when the match ended normally;
  otherwise it lists only its own player.
- The server settles the match from the first authoritative report that names at least two players, and
  ignores the others (one settlement per `csid`).
- Each game creates one kind of report only: developer version 5 for RA3 and TW, 100 for KW.

## Competition service

Endpoint: `/competitionservice/competitionservice.asmx`, namespace `http://gamespy.net/competition/`.
The three games send the same calls; `gameid` is 2128 (RA3), 1422 (TW) or 1814 (KW).

| Call | Sent by | Request | Reply |
|---|---|---|---|
| `CreateSession` | the host, at match start | certificate, proof, `gameid` | `result` 0, `csid`, `ccid` |
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
then a record with ID `report` and type `application/bin` that holds the report bytes. The second record
header is `0A 10 00 00 00 06 00 0F` followed by the 4-byte report length.

## Report layout

All numbers are big-endian.

| Offset | Size | Field |
|---|---|---|
| 0x00 | 4 | protocol version (RA3 2, TW and KW 1) |
| 0x04 | 4 | developer version (RA3 and TW 5, KW 100) |
| 0x08 | 16 | MD5 of the whole report, computed with these 16 bytes set to zero (zero in TW) |
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
| auth | per player: 16 bytes, all zero |
| results | per player, then per team: result (4) |
| game | key/value pairs |
| player | per player: key count (2), then key/value pairs |
| team | not used (team results are in the results section) |

A key/value pair is key (2), type (2), value. Types: 0 int32, 1 int16, 2 byte, 3 string (1-byte
length, then UTF-8, no terminator).

Results: 0 win, 1 loss, 3 disconnect, 4 desync. No game sends 2 (draw).

- RA3 and TW, the local player: 4 on a desync; 3 if it left the game; 1 if the game did not end normally
  or it was not victorious; 0 if it won.
- RA3 and TW, another human: 4 on a desync; 1 or 3 if it left, by the time it left; 0 if victorious,
  else 1.
- KW, every player: 4 on a desync; 3 if it left; 0 if victorious, else 1.
- Teams (clan modes only, authoritative reports only): a team gets 0 if any member won, else the first
  of 1, 3, 4 that a member has.

### Mode index

Every game writes a mode index `gt` = lobby type - 2.

| Lobby type | gt | Mode | Sake suffix |
|---|---|---|---|
| 3 | 1 | unranked (custom) | `UNRANKED` |
| 4 | 2 | ranked 1v1 | `RANKED1V1` |
| 5 | 3 | ranked 2v2 | `RANKED2V2` |
| 6 | 4 | clan 1v1 | `CLAN1V1` |
| 7 | 5 | clan 2v2 | `CLAN2V2` |

Because `gt` runs from 1 to 5, `key % 5` does not give the mode: for clan 2v2 it gives 0, and the RA3
bases from 77 up are not multiples of 5. Read `gt` from the game section, then subtract it. Side keys
are `side * 5 + gt`, so the side is `(key - 1) // 5`.

### Game keys

KW numbers every key 45 above RA3 and TW. Written in this order: mode flag, 61, 63, 64, 65, 62, 67, 68,
69, 70, 71, 66.

| RA3, TW | KW | Type | Value | Sent |
|---|---|---|---|---|
| 72 + gt | 117 + gt | byte | 1, the mode flag | always |
| 61 | 106 | string | map name | always |
| 62 | 107 | int32 | match length in seconds | when the game ended normally |
| 63 | 108 | string | game version, such as "1.13" or "1.10" | always |
| 64 | 109 | byte | 1 when the map is in the map cache and its record byte +0x37 is 0 | always |
| 65 | 110 | byte | 1 when the lobby has a MatchID | always |
| 66 | 111 | string | map display name | when not empty |
| 67 | 112 | string | the lobby MatchID, the same value the NewsTicker search filters on | with 65 |
| 68 | 113 | string | a second lobby string (game-info vtable +0x68) | with 65 |
| 69 | 114 | int32 | profile id of the commentator slot | with 65, when above 0 |
| 70 | 115 | int32 | a multiplayer setting (RA3 MultiplayerSettings +0x84) | when above 0 |
| 71 | 116 | int32 | a second multiplayer setting (RA3 +0x88) | with 70 |

### Player keys

The local player comes first, then the other humans. Values are this match's score keeper counts. The
games run in lockstep, so every client sends the same counts. The report carries no career totals: wins,
losses and streaks come from the results.

Side keys (`side * 5 + gt`, int16, value 1):

| Game | Sides |
|---|---|
| RA3 | 0 Allied, 1 Soviet, 2 Japan |
| TW | 0 GDI, 1 Nod, 2 Scrin |
| KW | 1 GDI, 2 ZOCOM, 3 Steel Talons, 5 Nod, 6 Black Hand, 7 Marked of Kane, 9 Scrin, 10 Reaper-17, 11 Traveler-59 |

RA3:

| Key | Type | Value | Career key |
|---|---|---|---|
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

TW and KW (these seven counts only):

| TW | KW | Type | Value | Career key |
|---|---|---|---|---|
| 15 + gt | 60 + gt | int32 | match length, local player only | - |
| 72 | 117 | int32 | a value of the local player, clan modes only | - |
| 20 + gt | 65 + gt | int32 | structures built | `structures_built` |
| 25 + gt | 70 + gt | int32 | structures lost | `structures_lost` |
| 30 + gt | 75 + gt | int32 | structures destroyed | `structures_destroyed` |
| 35 + gt | 80 + gt | int32 | structures captured | `structures_captured` |
| 40 + gt | 85 + gt | int32 | units built | `units_built` |
| 45 + gt | 90 + gt | int32 | units lost | `units_lost` |
| 50 + gt | 95 + gt | int32 | units killed | `units_killed` |

## Careers

- Each settled match is stored in `match_history`: game, csid, mode, map, MatchID, length, and the players
  with their result, faction and counts. Then it is folded onto each player's career in
  `player_stats.stats`, in the same transaction as the ELO changes.
- The fold, for the match's mode and for `all_online` (every match together):
  - `total_matches` +1, `total_time_played` + match length.
  - A win: `wins` +1, `current_loss_streak` = 0, `current_win_streak` +1, `longest_win_streak` = max.
  - Any other result: `losses` +1, `current_win_streak` = 0, `current_loss_streak` +1,
    `longest_loss_streak` = max.
  - Result 3 adds `disconnects`, result 4 adds `desyncs`.
  - The report counts add up.
  - Matches, wins, losses, time and streaks are also kept per faction (`factions`), and in KW per parent
    faction (`parents`: gdi, nod, scrin, each with its three subfactions).
- Derived values are computed when read: `WinLossRatio` = wins / max(losses, 1),
  `UnitKillDeathRatio` = units killed / max(units lost, 1), `AverageGameLength` = time played / matches.
- `all_online` follows the matches in order, so its streaks are real streaks across modes. KW reads it as
  its `ALLONLINE` columns; the web profile shows it as "All online" for every game.
- The KW 1.3 client resets the wrong streak after a loss in its own career files. The client reloads its
  career from Sake at login, so the server's values replace it.
- Score and rank: after a win or a loss, Score grows by a `ScoringMultipliers` value. The column is
  picked by (won, ranked), and every mode but unranked counts as ranked. Rank is the highest level
  whose `Levels` score the player has. The client predicts the same after each match. A player who
  left or desynced gets no score.
- `scripts/ra3_stats_tool.py rebuild` and `scripts/cnc3_stats_tool.py <tw|kw> rebuild` clear every career,
  score and rank of the game and fold its match history again. ELO is not touched. Run a rebuild after an
  upgrade, so older careers get their `all_online` bucket.
- The full stat lists, with the stats the clients keep only for themselves, are in
  [`ra3_stat_catalog.csv`](ra3_stat_catalog.csv), [`tw_stat_catalog.csv`](tw_stat_catalog.csv) and
  [`kw_stat_catalog.csv`](kw_stat_catalog.csv).

## Sake tables

Endpoint: `/SakeStorageServer/StorageServer.asmx`. The games call `GetMyRecords`, `SearchForRecords`,
`GetSpecificRecords` and `CreateRecord`. They never write stats to Sake. Every table is answered by field
name. Any other operation gets a SOAP fault.

| Table | Game | Call | Request | Reply |
|---|---|---|---|---|
| `PlayerStats_v5` | RA3 | GetMyRecords | 190 career columns | one value per column |
| `PlayerStats_v5` | TW | GetMyRecords | 160 career columns | one value per column |
| `PlayerStats_v100` | KW | GetMyRecords | 420 career columns | one value per column |
| the stats table | all | GetMyRecords | `Score`, `Rank` | the player's score and rank |
| the stats table | all | SearchForRecords | `ownerid=N`, sort `recordid`, `Rank`, `ownerid` | another player's rank |
| `Levels` | all | SearchForRecords | `Level>0`, sort `Level`, max 1000, `Score` | the first score of each rank |
| `ScoringMultipliers` | all | GetSpecificRecords | record 1: `UnrankedLosses`, `UnrankedWins`, `RankedLosses`, `RankedWins` | shorts 1, 2, 2, 5 |
| `TickerMgmt` | all | GetSpecificRecords | record 1: `DisplayRateInSec`, `MaxItemsToDownload`, `AdPercentage`, `CMPercentage`, `BGPercentage` | 30.0, 10, 50.0, 25.0, 25.0 |
| `NewsTicker` | all | SearchForRecords | `MatchID = '<id>' or MatchID = '-1'` (and `ImageFileID = 0`), sort `TickerType desc` | ticker lines |
| `custom_maps` | all | SearchForRecords, CreateRecord | `mapCRC=<crc>`, sort `recordid` | map sharing |
| `RatingMatch` | TW, KW | CreateRecord, SearchForRecords | `matchguid`, `compid`, `mrating`, `comrating`; search `matchguid='<guid>' and ownerid=<me>`, sort `rate_datetime desc` | the player's last rating of a match and its commentator |
| `RatingPlayer` | TW, KW | CreateRecord, SearchForRecords | `matchguid`, `pid`, `skrating`, `ssrating`; search `pid=<pid> and ownerid=<me>`, sort `rate_datetime desc` | the player's last skill and sportsmanship rating of another player |

- Column names are `<Stat>_<MODE>`, and for `TotalMatches`, `CareerLosses`, `CareerWins` and
  `WinLossRatio` also `<Stat>_<FACTION>_<MODE>`:
  - RA3: factions `ALLIED`, `SOVIET`, `JAPAN`.
  - TW: factions `GDI`, `NOD`, `ALIEN` (Scrin).
  - KW: parents `GDI`, `NOD`, `ALIEN` and subfactions `GDI_GDI`, `GDI_ZOCOM`, `GDI_TALONS`, `NOD_NOD`,
    `NOD_BLACKHAND`, `NOD_MARKED`, `ALIEN_SCRIN`, `ALIEN_REAPER`, `ALIEN_TRAVELER`; every stat also has an
    `ALLONLINE` mode. `CareerInputCommands` and `AverageCareerInputCommands` read 0: no report carries
    them and no client code writes them.
- Each game maps every column to {lobby type, faction, stat id} and stores only int (type 2) and float
  (type 3) values. The ratios are floats, and in TW and KW the average game length too.
- The stats table has one record per persona; a player without matches reads zeroes and rank 1.
- `CreateRecord` keeps the record in `sake_record` (game, table, owner, values) and returns its
  `recordid`. Searches on these tables also give `recordid`, `ownerid` and `rate_datetime` (the time the
  record was created).
- Searches follow the SDK: `filter` and `targetRecordFilter` (comparisons, `and`, `or`, `not`, `in`,
  `like`, `is null`), a multi-column `sort` with `desc`, `offset` and `max`, `surrounding` around the
  target, `ownerids`, and `row` as the position.
- RA3 has reply handlers for `RatingMatch` and `RatingPlayer`, but no build from 1.0 to 1.13 sends those
  requests.
