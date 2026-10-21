# Automatch Protocol

Automatch is the automated matchmaking system used by Red Alert 3, Command & Conquer Generals / Zero Hour and The Battle for Middle-earth. It works via virtual IRC bots that sit in game channels on the Peerchat server. Players send search requests to the bot via `PRIVMSG`, and the bot responds with match results when compatible opponents are found.

Kane's Wrath and Tiberium Wars use no bot; see [Kane's Wrath and Tiberium Wars QuickMatch](#kanes-wrath-and-tiberium-wars-quickmatch).

## Bot Identities

Each game has a dedicated bot with a fixed IRC identity:

| Game | Bot Nickname | Bot Username | Channel(s) | Match Interval |
|------|-------------|-------------|------------|----------------|
| Red Alert 3 | `anpwcjnybr2008` | `XDqGfsuOsX\|167408418` | `#GSP!redalert3pc` | 10s |
| Generals / ZH | `qmbot` | `X1fsaFv1DX\|17461195` | `#GPG!597`, `#GPG!392` | 2s |
| Battle for Middle-earth | `bfmeqmbot` | `X1fsaFv1DX\|17461196` | `#GPG!662` | 2s |

The bot registers in IRC state as a virtual client (no real socket) and joins its channels on server startup. It appears in NAMES lists and responds to WHO/GETCKEY like any other user.

### Username Encoding (piMangleIP)

The bot username **must** be in GameSpy encoded format: `X<8 encoded chars>X|<profileID>`. The game client calls `piDemangleUser` on the bot's username (from the WHO response) before accepting any `MBOT:` messages. If decoding fails, all messages from the bot are **silently dropped**.

**Encoding algorithm** (from the binary at `0x0080da50`):

1. XOR the IP with key `0xC3801DC7`
2. Format as 8-digit lowercase hex
3. Substitute each hex char using the alphabet `aFl4uOD9sfWq1vGp`:
   ```
   0→a  1→F  2→l  3→4  4→u  5→O  6→D  7→9
   8→s  9→f  a→W  b→q  c→1  d→v  e→G  f→p
   ```
4. Wrap with `X...X`, append `|<profileID>`

**Decoding validation** (from `0x0080d930`):

1. String length must be ≥ 12 characters
2. `str[0]` must be `'X'` and `str[9]` must be `'X'`
3. Reverse-substitute chars 1–8 back to hex, parse as integer
4. XOR with `0xC3801DC7` to recover the IP
5. IP must be non-zero (0.0.0.0 is rejected)
6. Profile ID is parsed from `str[11:]` via `atoi()`

The encoded IP can be any valid non-zero address (the bot is virtual, so the actual IP doesn't matter). The profile ID should match the original bot's ID from the game's `config.txt` (served via servserv). Use `encode_gamespy_username()` from `base.py` to generate values.

## Message Flow

```
┌────────┐                                         ┌──────────┐
│ Player │                                         │ Matchbot │
└───┬────┘                                         └────┬─────┘
    │                                                   │
    │  JOIN #GSP!redalert3pc                            │
    │  (bot is already in channel)                      │
    │                                                   │
    │── PRIVMSG anpwcjnybr2008 :\CINFO\...\  ────────►│
    │                                                   │  Parse CINFO,
    │                                                   │  validate, queue
    │◄──────────── PRIVMSG player :MBOT:WORKING 3 ─────│
    │                                                   │
    │              [match loop runs every N seconds]     │
    │                                                   │
    │◄──────────── PRIVMSG player :MBOT:POOLSIZE 3 ────│  (every 30s)
    │                                                   │
    │              [match found]                         │
    │                                                   │
    │◄──────────── PRIVMSG player :MBOT:MATCHED ... ───│
    │                                                   │
    │  PART / QUIT                                      │
    │  (player removed from queue on disconnect)        │
```

## CINFO Format

Players send their search parameters as a `CINFO` message — a backslash-delimited key-value payload sent as a `PRIVMSG` to the bot's nickname.

**Wire format:**
```
PRIVMSG botname :\CINFO\key1\value1\key2\value2...
```

The parser strips the `\CINFO` prefix, splits on `\`, and pairs up remaining tokens as keys and values.

### RA3 CINFO Fields

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `NumPlayers` | int | `2` | Players per match (2 or 4) |
| `Points` | int | — | Not used: the bot reads the player's ELO for the ladder from the server |
| `PointsStddev` | int | — | Not used |
| `PointRange` | int | `400` | The rating difference the player accepts (100, 250, 400, or 1000) |
| `IP` | int | `0` | Player's encoded IP address |
| `Side` | int | `-1` | Faction selection (-1 = random) |
| `Color` | int | `-1` | Color selection (-1 = random) |
| `NAT` | int | `0` | NAT type |
| `Maps` | string | — | Map availability bitset |
| `LadID` | int | `1` | Ladder ID (1=1v1, 2=2v2 random, 3=2v2 team) |
| `teammate1` | string | — | Nickname of teammate (LadID=3 only) |

### Generals / ZH CINFO Fields

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `NumPlayers` | int | `2` | Players per match (2, 4, 6, or 8) |
| `Points` | int | `1` | Player's skill points (minimum 1) |
| `IP` | int | `0` | Player's encoded IP address |
| `Side` | int | `-1` | Faction selection (-1 = random) |
| `Color` | int | `-1` | Color selection (-1 = random) |
| `NAT` | int | `0` | NAT type |
| `Maps` | string | — | Map availability bitset |
| `LadID` | int | `0` | Ladder ID |
| `PointsMin` | int | `0` | Minimum acceptable opponent skill % |
| `PointsMax` | int | `100` | Maximum acceptable opponent skill % |
| `DisconMax` | int | `100` | Maximum acceptable opponent disconnects |
| `Discons` | int | `0` | Player's own disconnect count |
| `PingMax` | int | `1000` | Maximum acceptable ping |
| `Pings` | string | — | Hex-encoded pseudo-ping values (2 hex chars each) |
| `Widen` | int | `0` | Seconds until automatic search widening (0 = disabled) |

## Bot Response Messages

### Common Messages (Both Games)

| Message | When Sent |
|---------|-----------|
| `MBOT:WORKING {pool_size}` | Player queued successfully; sent to the new player and all others in the pool |
| `MBOT:POOLSIZE {ladderId} {pool_size}` | Periodic pool size update, every 30 seconds. Includes the player's ladder ID so the client can match it to the correct pool. |
| `MBOT:BADCINFO` | `NumPlayers` value not in the game's valid set |
| `MBOT:BADMAPS` | `Maps` field is empty or missing |

### RA3 MATCHED Format

Sent to all matched players when a match is found:

```
MBOT:MATCHED {mapIdx} {matchId} 1 {nick} {ip} {side} {color} {nat} -1 {points} {teamId} {nick2} {ip2} {side2} {color2} {nat2} -1 {points2} {teamId2} ...
```

| Field | Description |
|-------|-------------|
| `mapIdx` | Index into the map bitset |
| `matchId` | Random match identifier (2000–20000) |
| `1` | Literal constant |
| `nick` | Player nickname |
| `ip` | Encoded IP address |
| `side` | Faction |
| `color` | Color |
| `nat` | NAT type |
| `-1` | Literal constant |
| `points` | Player's ELO rating for the ladder |
| `teamId` | Team identifier (0 or 1) |

Player blocks repeat for each participant. In 1v1, team IDs are 0 and 1. In 2v2, team IDs are 0, 0, 1, 1.

### Generals MATCHED Format

Used for all game sizes (1v1 through 4v4):

```
MBOT:MATCHED {mapIdx} {seed} {nick} {ip} {side} {color} {nat} {nick2} {ip2} {side2} {color2} {nat2} ...
```

| Field | Description |
|-------|-------------|
| `mapIdx` | Index into the map bitset |
| `seed` | Random game seed (0–2³¹-1) |
| `nick` | Player nickname |
| `ip` | Unsigned 32-bit IP address |
| `side` | Faction |
| `color` | Color |
| `nat` | NAT type |

Player blocks repeat for each participant (2 for 1v1, 4 for 2v2, etc.).

### Generals-Only Messages

| Message | When Sent |
|---------|-----------|
| `MBOT:WIDENINGSEARCH` | Player's search criteria have been relaxed (manual or auto-widen) |
| `MBOT:CANTSENDWIDENNOW` | `WIDEN` command received before the player has sent CINFO |

## Matchmaking Modes

### RA3 Ladders

| LadID | Mode | Description |
|-------|------|-------------|
| 1 | 1v1 | The closest ratings within reach (see below) |
| 2 | 2v2 Random | The four neighbours in rating order with the smallest spread, split into the most even teams |
| 3 | 2v2 Team | Both players in a team must reference each other via `teammate1`; the two teams with the closest average ratings |

### Generals Modes

| NumPlayers | Mode | Description |
|------------|------|-------------|
| 2 | 1v1 | Fitness score matching — skill ratio + disconnect + map checks |
| 4, 6, 8 | Team | Greedy fitness-based team formation — first valid team of `N/2` + `N/2` |

## Map Selection

The `Maps` field is a bitset string where each character position represents one map:
- `1` = player has this map available
- `0` = player does not have this map available

**Example:** `"10101100"` means maps at indices 0, 2, 4, 5 are available.

When a match is found, the server ANDs all matched players' bitsets together and picks a random index where the result is `1`.

- **RA3**: Clients typically send all `1`s (no user map restriction).
- **Generals**: Clients can restrict maps via the bitset. The `WIDEN` command overrides the bitset to all `1`s.

## RA3 ELO Matching

The bot reads each player's ELO from the server when the CINFO arrives: `ranked_1v1` for LadID 1,
`ranked_2v2` for LadID 2 and 3. Two players are within reach when each rating lies inside the other's
`PointRange`: `|elo1 - elo2| <= min(range1, range2)`. Kane's Wrath and Tiberium Wars apply the same rule
with a fixed window of 400.

- **1v1**: of the pairs within reach that share a map, the closest ratings meet; on a tie, the player who
  waited longest.
- **2v2 random**: the four neighbours in rating order with the smallest spread, all within reach of each
  other, split into weakest + strongest against the middle two (the most even team averages).
- **2v2 team**: the two complete teams whose average ratings are closest, within the smallest
  `PointRange` of the four players.

## Generals Fitness Matching

Generals uses a fitness function that checks multiple criteria.

### Fitness Checks (in order)

For each candidate pair (p1, p2):

1. **Skill percentage check** (skipped if player has widened):
   - `opponent_points × 100 / my_points` must be within `[PointsMin, PointsMax]`
   - Checked symmetrically for both players
2. **Disconnect filter** (skipped if player has widened, or if `DisconMax` is 0):
   - Opponent's `Discons` must be ≤ my `DisconMax`
   - Checked symmetrically
3. **Map compatibility**:
   - AND of both players' map bitsets must have at least one `1`
4. **Fitness score**:
   ```
   fitness = min(points1, points2) / max(points1, points2)
   ```

If any check fails, fitness returns 0 and the pair is skipped. The pair with the highest fitness score is matched.

### WIDEN

The `WIDEN` command relaxes search criteria:
- Sets the player's map bitset to all `1`s
- Bypasses skill percentage and disconnect checks in fitness evaluation

**Manual widen**: Player sends `\WIDEN\` as a PRIVMSG to the bot.

**Auto-widen**: If the `Widen` CINFO field is > 0, the bot automatically widens after that many seconds. The match loop checks the widen timer on each tick.

### Team Matching

For team games (NumPlayers 4, 6, or 8), the algorithm uses greedy team formation:

1. Pick a seed player for team A
2. Add compatible players (fitness > 0 with the seed) until team A has `N/2` members
3. Find `N/2` players for team B where each has fitness > 0 with every member of team A
4. Check map compatibility across all players
5. If successful, send `MBOT:MATCHED`; otherwise try the next seed

## Battle for Middle-earth QuickMatch

The Battle for Middle-earth (`lotrbfme.exe` 1.03) uses the Generals matchbot protocol with these differences:

- The game finds the bot by profile ID, not by nickname. It joins the group room named `QuickMatch`
  (`#GPG!662`), lists the players in it, and takes the player whose profile ID is the `<QMBot>` ID in
  `static/servserv/lotrbfme/config.txt`.
- CINFO also carries `PingMax` and `CMD`.
- `Points` is the player's ladder rank, and `PointsMin`/`PointsMax` are the ranks the player accepts: the rank
  plus or minus an eighth of the ladder, as in Kane's Wrath. They are not point percentages. Without ladder data
  the game sends `-1`, `2147483647` and `2147483647`. A rank below 1 counts as the top of the player's own
  window, and two players meet when each rank lies in the other's window, or after a widen.
- The bot matches only players with the same `EXE` and `INI` checksums, so players on different patches do not
  meet.
- `MBOT:MATCHED` has six fields per player: `{nick} {ip} {side} {color} {nat} {rank}`. The game reads six
  tokens per player, so with five it reads the next player's nickname as the sixth field. `rank` is the
  player's ladder rank on the loading screen; a value below 1 shows "Ladder rank unavailable". The bot sends
  the player's `Points`.
- The QuickMatch screen has no map choice. The pool is `<QMMaps>` in `config.txt`: the 40 official
  `map mp ...` maps in `maps.big`. The game keeps the maps that it has and that hold exactly `NumPlayers`
  players, and sets one `Maps` bit for each. `mapIdx` counts the same maps in `config.txt` order, so the pool
  must only hold maps that every install has. The official maps give 9 maps for 1v1, 18 for 2v2, 6 for 3v3
  and 4 for 4v4.
- The game puts each player in a team by slot order: the first `NumPlayers / 2` players against the rest.
- After the match the players negotiate NAT with each other through peerchat `NAT/` UTMs, as in Generals.
- The game reads `MBOT:POOLSIZE` only from room messages, as `<ladder> <size>` pairs. The bot sends it in
  private, so the game does not show the pool size. Generals reads it the same way.

## Kane's Wrath and Tiberium Wars QuickMatch

Kane's Wrath (`cnc3ep1.dat` 1.3) and Tiberium Wars (`cnc3game.dat` 1.10) have no matchbot. QuickMatch is the
GameSpy Peer SDK automatch: the clients find each other through the master server and agree on the game
with UTM messages between themselves. The server provides the parts the SDK expects: the automatch server
list, the staging rooms, and the ladder ratings.

KW reads `<QMBot>` from `config.txt`, but nothing uses the value, and the game never joins the
`QuickMatch` group room: the room is only hidden from the lobby lists. A player searches from the lobby
they are in.

### Automatch states

| Status | Meaning | What the client does |
|--------|---------|----------------------|
| 1 Searching | looking for a host | lists `<title>am` (`cc3xp1am`, `cc3tibwarsam`) with push updates |
| 2 Waiting | hosting | creates its staging room, reports it with QR2 on `<title>am`, keeps listing |
| 3 Staging | another player is in the room | the joiner stops listing and reporting; the host keeps reporting |
| 4 Ready | the room is full | the host may start the game |
| 5 Complete | the game launched | everything stops |

- A search that finds no host becomes a host (Waiting).
- A client rates every listed host with the game's rate callback, then joins the best one. A host in
  Waiting that sees a better-rated host leaves its own room and joins that one.
- The joiner builds the host's room name from the host's server list entry:
  `#GSP!<title>!M<mangled public IP, private IP and port>M`. The host used its own public IP, private IP
  and QR2 port, so the entry must carry those (private IP flag set, private port = the QR2 port).
- A host also finds its own entry in the pushes by its public IP, private IP and QR2 port. If the entry does
  not match, the host takes its own entry for a better host, leaves its room and joins a room nobody hosts.
- The host's public IP is the address peerchat gives it (USRIP). The master uses the heartbeat's source
  address, which is the same address when chat and heartbeat reach the server the same way (localhost,
  LAN, Radmin VPN or the internet).
- The host's private IP is its first `10/8`, `172.16/12` or `192.168/16` address, or 0.0.0.0 when it has
  none. The heartbeat lists up to five local addresses as `localip0`..`localip4`, and the master takes the
  first private one: `localip0` can be a VPN address, such as a Radmin `26.x` address.
- The room name only identifies the room. The games connect to the addresses that NAT negotiation gives them.

### What a host rates

The rate callback uses only the host's keys, so the master sends them all (full rules):

| Key | Rule |
|-----|------|
| `maxRPlyr` | must equal the searcher's player count (2 or 4) |
| `vCRC`, `cCRC`, `iCRC` | must equal the searcher's version, INI and exe CRCs |
| `pings`, `maxPing` | pseudo ping against the ping servers; must be under both limits |
| `rank_0`, `minPntPrcnt`, `maxPntPrcnt` | the host's rank must be in the searcher's window, and the searcher's rank in the host's |
| `widen` | a widened search skips the ping and rank limits |
| `mapBit` | the two map sets must share a map |
| `numplayers`, `maxplayers` | a full host is skipped |

The rank comes from `GetPlayerLadderRatings`. The menu searches `rank ± ceil(size / 8)` inside `[1, size]`,
and the fitness of a host is `min(rank) / max(rank)`. The server returns each player's ELO in that mode as
the rank and a ladder size of 3200, so QuickMatch matches on ELO with a window of ±400
([`ELO_AND_RANKINGS.md`](ELO_AND_RANKINGS.md)).

### Game handshake

```
Host (Waiting)                                  Joiner
     │◄────────── JOIN #GSP!cc3xp1!M...M ──────────│
     │── UTM <joiner> :QMREQ/ ────────────────────►│
     │◄── UTM <host> :QMRES/ Faction=<n> ──────────│   one UTM per field:
     │◄── UTM <host> :QMRES/ Color=<n> ────────────│   Faction, Color, IP, NAT,
     │◄── ... IP, NAT, Rank, ProfileID ────────────│   Rank, ProfileID,
     │◄── UTM <host> :QMRES/ BroadcastEnabled=<n> ─│   BroadcastEnabled
     │◄── UTM <host> :QMRDY/ ──────────────────────│
     │                                             │
     │  every slot ready and the room full (Ready) │
     │── UTM #GSP!cc3xp1!M...M :QMGO/ <params> ───►│   both launch the game
```

`QMGO/` parameters: `<mapIndex> <seed> <1 if every player allows broadcast, else 0>`, then per player
`<nick> <IP> <faction> <color> <NAT> <rank> <profileID>`. The map is a random map that every player has.

### Server pieces

- **Master server**: lists `<title>am` hosts with full rules, pushes hosts that appear or change and
  deletes those that leave, and answers server info requests ([`MASTER_SERVER.md`](MASTER_SERVER.md)).
- **QR2**: a host that sends `statechanged=2`, or nothing for 180 seconds, is removed.
- **Peerchat**: the host sets `MODE +l 2` (or 4); a JOIN to a full room gets `471`, so a third searcher
  goes back to searching. UTMs go to the named player or to everyone in the room.
- **Ladder ratings**: `KWServices/KWGetPlayerLadderRatings.aspx` (ladders 52177 1v1, 52178 2v2) and
  `CC3Services/GetPlayerLadderRatings.aspx` (43738 1v1, 43783 2v2).

## Extra Commands

### WIDEN (Generals Only)

```
PRIVMSG qmbot :\WIDEN\
```

Relaxes all search criteria for the sending player. The bot responds with `MBOT:WIDENINGSEARCH`.

If the player has not yet sent a CINFO (is not in the queue), the bot responds with `MBOT:CANTSENDWIDENNOW`.
