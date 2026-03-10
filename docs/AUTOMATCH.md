# Automatch Protocol

Automatch is the automated matchmaking system used by Red Alert 3 and Command & Conquer Generals / Zero Hour. It works via virtual IRC bots that sit in game channels on the Peerchat server. Players send search requests to the bot via `PRIVMSG`, and the bot responds with match results when compatible opponents are found.

## Bot Identities

Each game has a dedicated bot with a fixed IRC identity:

| Game | Bot Nickname | Bot Username | Channel(s) | Match Interval |
|------|-------------|-------------|------------|----------------|
| Red Alert 3 | `anpwcjnybr2008` | `XDqGfsuOsX\|167408418` | `#GSP!redalert3pc` | 10s |
| Generals / ZH | `qmbot` | `X1fsaFv1DX\|17461195` | `#GPG!597`, `#GPG!392` | 2s |

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
| `Points` | int | `1000` | Player's ELO rating |
| `PointsStddev` | int | `50` | ELO standard deviation |
| `PointRange` | int | `1000` | Search range preference (100, 250, 400, or 1000) |
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
| `points` | Player's ELO rating |
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
| 1 | 1v1 | ELO-range interval overlap matching (see below) |
| 2 | 2v2 Random | First 4 queued players are matched; no ELO check |
| 3 | 2v2 Team | Both players in a team must reference each other via `teammate1`; two complete teams required |

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

## RA3 ELO-Range Matching

RA3 1v1 uses ELO-range interval overlap to find the best match.

### PointRange to Sigma Mapping

The `PointRange` CINFO field maps to a sigma coefficient that controls how wide the search interval is:

| PointRange | Sigma (σ) |
|------------|-----------|
| 100 | 1 |
| 250 | 2 |
| 400 | 4 |
| 1000 | 8 |

Any unrecognized `PointRange` value defaults to σ = 8 (widest search).

### Interval Calculation

Each player's search interval is:

```
interval = [points - σ × stddev, points + σ × stddev]
```

Where `stddev` is clamped to a minimum of 50 and `points` is clamped to a minimum of 1.

### Scoring

For every pair of queued players:

1. Compute the overlap region between their intervals
2. If no overlap exists, skip the pair
3. Calculate the overlap score:
   ```
   score = min(overlap_length / range1, overlap_length / range2) + random_noise
   ```
   Where `random_noise` is 0–0.03 (adds slight randomization)
4. Score is clamped to [0.0, 1.0]

The pair with the highest score is matched. Map compatibility is checked after scoring — if the best pair has no common maps, no match occurs.

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

## Extra Commands

### WIDEN (Generals Only)

```
PRIVMSG qmbot :\WIDEN\
```

Relaxes all search criteria for the sending player. The bot responds with `MBOT:WIDENINGSEARCH`.

If the player has not yet sent a CINFO (is not in the queue), the bot responds with `MBOT:CANTSENDWIDENNOW`.
