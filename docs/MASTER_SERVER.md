# GameSpy Master Server Implementation

The Master Server handles game session discovery and registration. It consists of two components:

- **TCP Query Server** (port 28910) - Handles room list and game list queries from clients
- **UDP Heartbeat Server** (port 27900) - Receives game session registrations from hosts

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              Game Clients                                    │
└─────────────────────────────────────────────────────────────────────────────┘
              │                                           │
              │ TCP 28910                                 │ UDP 27900
              │ (queries)                                 │ (heartbeats)
              ▼                                           ▼
    ┌──────────────────┐                        ┌──────────────────┐
    │ QueryMasterServer │                        │  HeartbeatMaster │
    │    (TCP)          │                        │     (UDP)        │
    └────────┬─────────┘                        └────────┬─────────┘
             │                                           │
             │                                           │
             └──────────────┬────────────────────────────┘
                            │
                            ▼
                 ┌───────────────────────┐
                 │  GameSessionRegistry  │
                 │     (singleton)       │
                 └───────────────────────┘
```

## Game Registration Flow

```
┌─────────────────┐     UDP 27900      ┌──────────────────┐
│   Game Host     │ ──────────────────►│  HeartbeatMaster │
│  (creates game) │    HEARTBEAT       │                  │
└─────────────────┘                    └────────┬─────────┘
                                                │
                                                │ register_game()
                                                ▼
                                    ┌───────────────────────┐
                                    │  GameSessionRegistry  │
                                    │     (singleton)       │
                                    └───────────┬───────────┘
                                                │
                                                │ get_games()
                                                ▼
┌─────────────────┐     TCP 28910      ┌──────────────────┐
│   Game Client   │ ◄──────────────────│ QueryMasterHandler│
│  (finds games)  │    Game List       │                  │
└─────────────────┘                    └──────────────────┘
```

**Flow:**

1. Game host sends UDP HEARTBEAT to port 27900 with session info
2. HeartbeatMaster parses the heartbeat and calls `GameSessionRegistry.register_game()`
3. GameSessionRegistry stores the GameEntry with all fields (hostname, gamemode, mapname, etc.)
4. Game client sends TCP query to port 28910 requesting game list
5. QueryMasterHandler calls `GameSessionRegistry.get_games()` and returns filtered results
6. When host closes lobby, sends HEARTBEAT with `statechanged=2` to unregister

---

## TCP Query Server (Port 28910)

### Request Format

All requests are length-prefixed binary packets:

```
┌─────────┬────────┬─────┬───────────┬───────────┬──────────┬────────┬────────┬──────┐
│ u16be   │ 6B     │ 0x00│ str0      │ str0      │ 8B       │ str0   │ str0   │ tail │
│ length  │ header │ sep │ gameName  │ gameName2 │ validate │ filter │ fields │      │
└─────────┴────────┴─────┴───────────┴───────────┴──────────┴────────┴────────┴──────┘
```

| Field | Size | Description |
|-------|------|-------------|
| `length` | 2 bytes | Total packet length (big-endian) |
| `header` | 6 bytes | Unknown header bytes |
| `separator` | 1 byte | 0x00 |
| `gameName` | null-terminated | Game identifier (e.g., `redalert3pc`) |
| `gameName2` | null-terminated | Usually same as gameName |
| `validate` | 8 bytes | Validate token for encryption |
| `filter` | null-terminated | Filter expression (e.g., `(groupid=2166)`) |
| `fields` | null-terminated | Backslash-delimited field list |
| `tail` | remaining | Trailing bytes |

### Filter Expression

Filters use SQL-like syntax:

```
(groupid=2166) AND (gamemode != 'closedplaying')
```

Supported operators: `=`, `!=`, `<`, `>`, `<=`, `>=`

### Request Types

**Room List Request** - Fields include: `hostname`, `numwaiting`, `maxwaiting`, `numservers`, `numplayers`, `roomType`

**Game List Request** - Fields include: `hostname`, `gamemode`, `mapname`, `vCRC`, `iCRC`, `cCRC`, `pw`, `obs`, `rules`, `pings`, `numRPlyr`, `maxRPlyr`, `numObs`, `mID`, `mod`, `modv`, `name_`

### Response Format (Classic)

Responses are encrypted using EncTypeX cipher with the game key and client's validate token.

**Plaintext structure:**

```
┌─────────┬─────────┬────────────┬──────┬──────────────┬──────┬────────────┐
│ ip4     │ u16be   │ fieldList  │ 0x00 │ entries...   │ 0x00 │ 0xFFFFFFFF │
│ masterIp│ port    │            │ sep  │              │ sep  │ end marker │
└─────────┴─────────┴────────────┴──────┴──────────────┴──────┴────────────┘
```

**Field List:**

```
┌──────┬────────────────────────────────────────┐
│ u8   │ repeat fieldCount times:              │
│ count│   u8 type + str0 fieldName            │
└──────┴────────────────────────────────────────┘
```

Field types: `0` = string, `1` = u8 immediate

### Room Entry Format

```
┌──────┬─────────┬──────────────────────────────────────┐
│ 0x40 │ u32be   │ repeat for each field:               │
│ '@'  │ roomId  │   0xFF + value bytes + 0x00          │
└──────┴─────────┴──────────────────────────────────────┘
```

### Game Entry Format

```
┌──────┬─────────┬─────────┬───────────┬───────────┬───────────┬───────────┬────────┬──────┐
│ 0x7E │ ip4     │ u16be   │ ip4       │ u16be     │ ip4       │ u16be     │ fields │ 0x00 │
│ '~'  │ pubIp   │ pubPort │ privIp    │ privPort  │ tracedIp  │ tracedPort│        │      │
└──────┴─────────┴─────────┴───────────┴───────────┴───────────┴───────────┴────────┴──────┘
```

| Field | Description |
|-------|-------------|
| `publicIp/Port` | NAT-translated external address |
| `privateIp/Port` | Local network address |
| `tracedIp/Port` | Address packet was received from |

### EncTypeX Encryption

Server responses are encrypted using the EncTypeX cipher. The encryption uses:

- **Game key**: Game-specific secret key (from `config.json`)
- **Validate token**: 8 bytes from client request

**Encoded format:**

```
┌──────────────────┬────────────────┬──────────────┬────────────────────┐
│ header_len^0xEC-2│ random padding │ iv_len^0xEA  │ salt + encrypted   │
│ (1 byte)         │ (variable)     │ (1 byte)     │ payload            │
└──────────────────┴────────────────┴──────────────┴────────────────────┘
```

---

## UDP Heartbeat Server (Port 27900)

### Packet Format

```
┌──────┬──────────┬───────────────┐
│ u8   │ u32be    │ body          │
│ msgId│ clientId │ (varies)      │
└──────┴──────────┴───────────────┘
```

### Message Types

| ID | Name | Description |
|----|------|-------------|
| `0x01` | CHALLENGE_RESPONSE | Server challenge to client |
| `0x03` | HEARTBEAT | Game session info from host |
| `0x08` | KEEPALIVE | Keepalive ping |
| `0x09` | AVAILABLE | Check if master is online |
| `0x0A` | RESPONSE_CORRECT | Challenge accepted |

### AVAILABLE (0x09)

Client checks if master server is online.

**Request:**
```
┌──────┬──────────┬─────────────────┐
│ 0x09 │ clientId │ gameName\0      │
└──────┴──────────┴─────────────────┘
```

**Response:**
```
┌───────────────────────┐
│ 0xFE 0xFD 0x09 0x00   │
│ 0x00 0x00 0x00        │
└───────────────────────┘
```

### HEARTBEAT (0x03)

Game host sends session information.

**Request:**
```
┌──────┬──────────┬─────────────────────────────────────────────┐
│ 0x03 │ clientId │ key\0value\0key\0value\0...\0\0             │
└──────┴──────────┴─────────────────────────────────────────────┘
```

**Common heartbeat fields:**

| Field | Description |
|-------|-------------|
| `hostname` | Game session name |
| `gamename` | Game identifier (`redalert3pc`) |
| `gamever` | Game version |
| `hostport` | Game host port |
| `mapname` | Current map |
| `gamemode` | Current mode (`openstaging`, `closedplaying`) |
| `numplayers` | Current player count |
| `maxplayers` | Maximum players |
| `localip0` | Host's local IP |
| `localport` | Host's local port |
| `natneg` | NAT negotiation enabled (`1`) |
| `publicip` | Public IP as signed integer (0 if unknown) |
| `publicport` | Public port |
| `statechanged` | State change reason |
| `groupid` | Room/lobby group ID |

**Response (if publicip=0):**

Server sends challenge with actual IP/port:

```
┌─────────┬──────┬──────────┬───────────┬──────────────────────┬──────┐
│ 0xFE    │ 0x01 │ clientId │ challenge │ hex(0x00+ip4+u16be)  │ 0x00 │
│ 0xFD    │      │ (4B)     │ bytes     │ port                 │      │
└─────────┴──────┴──────────┴───────────┴──────────────────────┴──────┘
```

### Heartbeat State Values

The `statechanged` field indicates why the heartbeat is being sent:

| Value | Name | Description |
|-------|------|-------------|
| `0` | NORMAL | Normal periodic heartbeat |
| `1` | STATECHANGED | Game state changed (mode, players, etc.) |
| `2` | EXITING | Server shutting down, remove from list |
| `3` | INITIAL | Initial registration heartbeat |

When `statechanged=2` is received, the game session is unregistered and will no longer appear in game list queries.

### KEEPALIVE (0x08)

Periodic keepalive to maintain session.

**Request:**
```
┌──────┬──────────┐
│ 0x08 │ clientId │
└──────┴──────────┘
```

No response required.

---

## Example Packets

### Room List Query

```
00 6d                         # length: 109 bytes
00 01 03 00 00 01             # header
00                            # separator
72 65 64 61 6c 65 72 74 33 70 63 00   # "redalert3pc\0"
72 65 64 61 6c 65 72 74 33 70 63 00   # "redalert3pc\0"
74 37 53 4c 61 26 53 50       # validate token: "t7SLa&SP"
00                            # empty filter
5c 68 6f 73 74 6e 61 6d 65   # "\hostname\numwaiting\maxwaiting..."
5c 6e 75 6d 77 61 69 74 69 6e 67
5c 6d 61 78 77 61 69 74 69 6e 67
5c 6e 75 6d 73 65 72 76 65 72 73
5c 6e 75 6d 70 6c 61 79 65 72 73
5c 72 6f 6f 6d 54 79 70 65 00
00 00 00 04                   # tail
```

### Game List Query

```
00 d9                         # length: 217 bytes
00 01 03 00 00 01             # header
00                            # separator
72 65 64 61 6c 65 72 74 33 70 63 00   # "redalert3pc\0"
72 65 64 61 6c 65 72 74 33 70 63 00   # "redalert3pc\0"
4b 62 64 69 44 7c 56 4d       # validate token
28 67 72 6f 75 70 69 64 3d 32 31 36 36 29   # "(groupid=2166) AND (gamemode != 'closedplaying')"
20 41 4e 44 20 28 67 61 6d 65 6d 6f 64 65
20 21 3d 20 27 63 6c 6f 73 65 64 70 6c 61
79 69 6e 67 27 29 00
5c 68 6f 73 74 6e 61 6d 65   # "\hostname\gamemode\mapname..."
...
00 00 00 04                   # tail
```

### UDP Heartbeat

```
03                            # HEARTBEAT (0x03)
f7 b3 f2 7e                   # clientId: 4153247358
6c 6f 63 61 6c 69 70 30 00    # "localip0\0"
31 39 32 2e 31 36 38 2e 36 38 2e 36 33 00   # "192.168.68.63\0"
6c 6f 63 61 6c 70 6f 72 74 00 # "localport\0"
36 35 36 33 00                # "6563\0"
6e 61 74 6e 65 67 00          # "natneg\0"
31 00                         # "1\0"
73 74 61 74 65 63 68 61 6e 67 65 64 00   # "statechanged\0"
32 00                         # "2\0" (EXITING)
67 61 6d 65 6e 61 6d 65 00    # "gamename\0"
72 65 64 61 6c 65 72 74 33 70 63 00   # "redalert3pc\0"
00                            # end of pairs
```

---

## Configuration

Add master server settings to `config.json`:

```json
{
  "master": {
    "host": "0.0.0.0",
    "port": 28910,
    "udp_port": 27900,
    "enabled": true
  },
  "game": {
    "gamekey": "YOUR_GAME_KEY"
  }
}
```

| Setting | Default | Description |
|---------|---------|-------------|
| `host` | `0.0.0.0` | Bind address |
| `port` | `28910` | TCP query port |
| `udp_port` | `27900` | UDP heartbeat port |
| `enabled` | `true` | Enable/disable master server |

---

## Implementation Notes

1. **Shared Registry**: `GameSessionRegistry` is a singleton that bridges the UDP heartbeat server (registrations) with the TCP query server (queries).

2. **Session Lifecycle**: Games register via HEARTBEAT, update via periodic HEARTBEATs, and unregister by sending `statechanged=2`.

3. **Encryption**: All TCP responses are encrypted with EncTypeX. The cipher uses the game key and the client's 8-byte validate token.

4. **IP Resolution**: When a game host sends `publicip=0`, the server responds with a challenge containing the actual source IP/port observed.

5. **Filter Matching**: Game list queries can filter results using SQL-like expressions on any field (groupid, gamemode, etc.).

6. **Default Rooms**: The server provides a default list of lobby rooms (LobbyRoom:1-21, LobbyCoop:1-5, LobbyClan:1-2, etc.) for room list queries.
