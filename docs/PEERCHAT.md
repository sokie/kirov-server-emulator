# Peerchat IRC Server Implementation

Peerchat is a GameSpy-extended IRC server used for Red Alert 3's lobby system, chat, messaging, and game coordination. It handles player matchmaking, game session creation, and NAT negotiation initiation.

## Protocol Overview

Peerchat is based on standard IRC (RFC 1459) with GameSpy-specific extensions:

- **Encryption**: All traffic after initial handshake is encrypted using a custom stream cipher
- **Authentication**: Uses CDKEY hash derived from FESL session
- **Channel Stats**: `GETCKEY`/`SETCKEY` commands for game-specific metadata
- **UTM Messages**: Unified text messages for game data exchange

## Connection Flow

```
┌────────┐                                    ┌─────────────────┐
│ Client │                                    │ Peerchat Server │
└───┬────┘                                    └────────┬────────┘
    │                                                  │
    │─────────── CRYPT des 1 redalertpc ──────────────►│
    │◄────────────────────────────────────── 705 challenges
    │                                                  │
    │           [Encryption enabled]                   │
    │                                                  │
    │─────────── NICK playername ─────────────────────►│
    │─────────── USER encodedip|profileid ... ────────►│
    │◄──────────────────────────────────── 001-004, MOTD
    │                                                  │
    │─────────── CDKEY <hash> ────────────────────────►│
    │◄──────────────────────────────────────── 706 OK
    │◄─────────────────────────────────────── PING s
    │                                                  │
    │           [Ready for channels]                   │
```

## Message Format

### Standard IRC Format

```
[:<prefix>] <command> <params...> [:<trailing>]\r\n
```

**Examples:**
```
NICK testplayer
:testplayer!random|123@* PRIVMSG #lobby :Hello everyone
:s 001 testplayer :Welcome to the Matrix testplayer
```

### Prefix Format

| Context | Format | Example |
|---------|--------|---------|
| Server message | `s` | `:s 001 nick :Welcome` |
| User message | `nick!user@host` | `:player!encoded@* PRIVMSG` |
| GameSpy host | `*` (asterisk) | `:nick!user@*` |

## Encryption System

GameSpy uses a custom stream cipher based on RC4-like key scheduling.

### Initialization (CRYPT command)

```
Client: CRYPT des 1 redalertpc
Server: :s 705 <client_challenge> <server_challenge>
```

| Field | Description |
|-------|-------------|
| `des` | Cipher type (ignored, always uses GameSpy cipher) |
| `1` | Version |
| `redalertpc` | Game identifier |

### Cipher Setup

1. Server generates two 16-character random challenges (printable ASCII `;` to `~`)
2. Both client and server derive encryption keys from: `challenge XOR gamekey`
3. Two separate cipher instances: one for send, one for receive
4. All subsequent traffic is encrypted

**Gamekey**: Retrieved from `app_config.game.gamekey` (secret, not hardcoded)

### Challenge Generation

```python
# Characters from ';' (0x3B) to '~' (0x7E)
alphabet = ''.join(chr(i) for i in range(ord(';'), ord('~')))
challenge = ''.join(random.choice(alphabet) for _ in range(16))
```

## Authentication Commands

### NICK

Set client nickname (player name).

```
Client: NICK playername
```

- Max 30 characters
- Returns `433` if nickname in use

### USER

Register user details. GameSpy format differs from standard IRC.

```
Client: USER <encoded_ip>|<profile_id> <local_ip> <server> :<auth_token>
```

| Field | Description |
|-------|-------------|
| `encoded_ip` | GameSpy-encoded IP address |
| `profile_id` | Persona ID from FESL login |
| `local_ip` | Client's local IP (for LAN detection) |
| `server` | Server hostname |
| `auth_token` | Session token hash |

**Example:**
```
USER random|123 192.168.1.5 peerchat.gamespy.com :ff70dbb93425a35226fd1fe8f052623c
```

### CDKEY

Authenticate with CD key hash (derived from FESL session token + challenge).

```
Client: CDKEY <hash>
Server: :s 706 1 :Authenticated
```

After successful CDKEY, server sends initial `PING s` to start keepalive cycle.

## Channel System

### Channel Types

| Prefix | Type | Description |
|--------|------|-------------|
| `#GPG!` | Public lobby | Global lobby (e.g., `#GPG!redalert3pc`) |
| `#GSP!` | Private game | Game session (e.g., `#GSP!redalert3pc!Mzhhzq1h0M`) |

### GSP Channel Naming

Private game channels follow the format:
```
#GSP!<gamename>!<session_id>
```

- `gamename`: Game identifier (e.g., `redalert3pc`)
- `session_id`: Random/unique session identifier

### JOIN

Join a channel. First user becomes operator.

```
Client: JOIN #channel
Server: :nick!user@* JOIN :#channel
Server: :s 353 nick = #channel :@nick
Server: :s 366 nick #channel :End of /NAMES list
```

### PART

Leave a channel.

```
Client: PART #channel :reason
Server: :nick!user@* PART #channel :reason
```

### TOPIC

Get or set channel topic.

```
Client: TOPIC #channel              (query)
Client: TOPIC #channel :New topic   (set, requires op)
```

### MODE

Channel modes used by RA3:

```
Client: MODE #channel +l 6          (set player limit)
Client: MODE #channel -i-p-s-m-n-t+l+e 6  (typical game lobby)
```

| Mode | Description |
|------|-------------|
| `+l N` | Player limit |
| `+i` | Invite only |
| `+p` | Private |
| `+s` | Secret |
| `+e` | External messages allowed |

## GameSpy Extension Commands

### GETCKEY

Query user metadata in a channel. Used to get player info like flags, team, ready status.

```
Client: GETCKEY #channel <target|*> <request_id> <flags> :\key1\key2...
Server: :s 702 nick #channel target request_id \value1\value2...
Server: :s 703 nick #channel request_id :End of GETCKEY
```

| Field | Description |
|-------|-------------|
| `target` | Nickname or `*` for all users |
| `request_id` | Client-provided ID echoed in response |
| `flags` | Usually `0` |
| `keys` | Backslash-separated key names to query |

**Special key `username`**: Returns the user's encoded username field.

**Example:**
```
Client: GETCKEY #GSP!redalert3pc!abc * 123 0 :\username\b_flags\b_team
Server: :s 702 me #GSP!redalert3pc!abc player1 123 \random|1234\0\1
Server: :s 702 me #GSP!redalert3pc!abc player2 123 \random|1235\0\2
Server: :s 703 me #GSP!redalert3pc!abc 123 :End of GETCKEY
```

### SETCKEY

Set your own metadata in a channel. Broadcasts update to all channel members.

```
Client: SETCKEY #channel nickname :\key\value\key\value...
Server: :s 702 #channel #channel nickname BCAST \key\value...  (to all)
```

**Common keys for RA3:**

| Key | Description |
|-----|-------------|
| `b_flags` | Player flags (ready status, etc.) |
| `b_team` | Team number |
| `b_clanTag` | Clan tag |
| `b_armorSet` | Selected faction/armor |

### UTM (Unified Text Message)

Game-specific data exchange. Used for map selection, game settings, NAT negotiation.

```
Client: UTM <target> :<message>
Server: :nick!user@* UTM <target> :<message>
```

**Target types:**
- `#channel` - Broadcast to channel (excludes sender)
- `nickname` - Direct to single user
- `nick1,nick2,nick3` - Direct to multiple users

**Example UTM messages:**

```
UTM #GSP!redalert3pc!abc :CYCLED,MAP,GAME,RANKED,\filename,0,0,0,0,0,0
UTM player2 :CYCLED,MAP,GAME,RANKED,\mapdata...
UTM player2,player3 :NAT negotiation data
```

### USRIP

Get client's public IP address (as seen by server).

```
Client: USRIP
Server: :s 302  :=+@192.168.1.100
```

### WHO

Query user information.

```
Client: WHO #channel
Server: :s 352 me #channel username hostname server nick H@ :0 realname
Server: :s 315 me #channel :End of /WHO list
```

Flags in response: `H` = Here, `@` = Operator

## Game Session Lifecycle

### 1. Player Enters Lobby

```
JOIN #GPG!redalert3pc
```

Player joins the main public lobby to see available games.

### 2. Host Creates Game

```
JOIN #GSP!redalert3pc!Mzhhzq1h0M
MODE #GSP!redalert3pc!Mzhhzq1h0M -i-p-s-m-n-t+l+e 6
TOPIC #GSP!redalert3pc!Mzhhzq1h0M :Game settings...
SETCKEY #GSP!redalert3pc!Mzhhzq1h0M hostname :\b_flags\0\b_team\1
```

Host creates private channel, sets player limit, topic (game settings), and initial stats.

### 3. Guest Joins Game

```
JOIN #GSP!redalert3pc!Mzhhzq1h0M
GETCKEY #GSP!redalert3pc!Mzhhzq1h0M * 1 0 :\username\b_flags\b_team
SETCKEY #GSP!redalert3pc!Mzhhzq1h0M guestname :\b_flags\0\b_team\2
```

Guest joins, queries all player stats, sets own stats.

### 4. Game Settings Exchange

```
UTM #GSP!redalert3pc!Mzhhzq1h0M :CYCLED,MAP,GAME,RANKED,...
```

Host broadcasts map selection, game rules via UTM.

### 5. Ready Status

```
SETCKEY #GSP!redalert3pc!Mzhhzq1h0M player :\b_flags\1
```

Players set `b_flags` to indicate ready.

### 6. Game Start Countdown

```
NOTICE #GSP!redalert3pc!Mzhhzq1h0M :Type,LAN:GameStartTimerSingular,5
NOTICE #GSP!redalert3pc!Mzhhzq1h0M :Type,LAN:GameStartTimerSingular,4
...
```

Host sends countdown via NOTICE.

### 7. NAT Negotiation

Before game starts, clients exchange NAT negotiation data via UTM (or via GPServer buddy messages). The session cookie is shared here, then clients connect to the NAT negotiation server (see `docs/NATNEG.md`).

### 8. Game Ends / Players Leave

```
PART #GSP!redalert3pc!Mzhhzq1h0M :Game over
```

Channel is automatically deleted when empty.

## Friends System Integration

Friends/buddy features are handled by **GPServer** (see `docs/GP_SERVER.md`), not Peerchat. However:

- Player's `profile_id` from USER command links to GPServer identity
- Game invites can be sent via GPServer's `\bm\101\` messages
- Online status is managed by GPServer's `\status\` command

## NAT Negotiation Integration

NAT negotiation is separate from Peerchat but coordinated through it:

1. **Session cookie exchange**: Host generates session cookie, shares via UTM
2. **Players connect to NATNEG server**: UDP port 27901 (see `docs/NATNEG.md`)
3. **INIT packets**: Both players send INIT with shared cookie
4. **CONNECT**: Server sends peer addresses to both players
5. **P2P connection**: Direct game traffic flows between players

## Numeric Reply Codes

### Standard IRC

| Code | Name | Description |
|------|------|-------------|
| 001 | RPL_WELCOME | Welcome message |
| 002 | RPL_YOURHOST | Server info |
| 003 | RPL_CREATED | Server creation |
| 004 | RPL_MYINFO | Server capabilities |
| 302 | RPL_USERHOST | USRIP response |
| 315 | RPL_ENDOFWHO | End of WHO list |
| 324 | RPL_CHANNELMODEIS | Channel mode |
| 331 | RPL_NOTOPIC | No topic set |
| 332 | RPL_TOPIC | Channel topic |
| 352 | RPL_WHOREPLY | WHO response |
| 353 | RPL_NAMREPLY | NAMES list |
| 366 | RPL_ENDOFNAMES | End of NAMES |
| 372 | RPL_MOTD | MOTD line |
| 375 | RPL_MOTDSTART | MOTD start |
| 376 | RPL_ENDOFMOTD | MOTD end |

### Error Codes

| Code | Name | Description |
|------|------|-------------|
| 401 | ERR_NOSUCHNICK | No such nick/channel |
| 403 | ERR_NOSUCHCHANNEL | No such channel |
| 404 | ERR_CANNOTSENDTOCHAN | Cannot send to channel |
| 421 | ERR_UNKNOWNCOMMAND | Unknown command |
| 431 | ERR_NONICKNAMEGIVEN | No nickname given |
| 432 | ERR_ERRONEUSNICKNAME | Erroneous nickname |
| 433 | ERR_NICKNAMEINUSE | Nickname in use |
| 442 | ERR_NOTONCHANNEL | Not on channel |
| 461 | ERR_NEEDMOREPARAMS | Need more parameters |
| 462 | ERR_ALREADYREGISTRED | Already registered |
| 482 | ERR_CHANOPRIVSNEEDED | Channel op required |

### GameSpy Extensions

| Code | Name | Description |
|------|------|-------------|
| 702 | RPL_GETCKEY_RESPONSE | GETCKEY result |
| 703 | RPL_GETCKEY_END | End of GETCKEY |
| 705 | RPL_CRYPT_CHALLENGE | Encryption challenges |
| 706 | RPL_CDKEY_OK | CDKEY authenticated |

## Implementation Notes

1. **Thread safety**: Global client/channel dictionaries use threading locks. Multiple async connections may modify state concurrently.

2. **Encryption timing**: Enable encryption immediately after sending 705. Both send and receive ciphers use separate state.

3. **First user is operator**: When creating a channel, the first joiner automatically becomes operator (`@` prefix).

4. **Private channel cleanup**: `#GSP!` channels are deleted when the last user leaves.

5. **PING/PONG keepalive**: Server sends `PING s` every 60 seconds. Clients timeout after 90 seconds without PONG.

6. **UTM multi-target**: UTM supports comma-separated nicknames for multi-target delivery. Each target receives the message with their own nick in the params.

7. **NOTICE vs PRIVMSG**: NOTICE doesn't generate error responses. Used for game countdown timers.

8. **SETCKEY permissions**: Users can only set their own keys, not others'.

9. **Context variables**: Per-connection state stored in `irc_client_data_var` context variable.

10. **Profile ID extraction**: Parsed from USER command's first param (`encoded|profile_id`).

## Testing

See test files:
- `app/test/test_peerchat_server.py` - Unit tests for server logic
- `app/test/test_peerchat_live.py` - Live connection tests
- `app/util/peerchat_crypt.py` - Cipher verification (run as `__main__`)

Run tests:
```bash
python -m pytest app/test/test_peerchat_server.py -v
python -m pytest app/test/test_peerchat_live.py -v
```
