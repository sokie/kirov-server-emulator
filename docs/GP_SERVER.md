# GameSpy Protocol (GP) Server Implementation

## Protocol Format

```
Request:  \command\\key1\value1\key2\value2\...\final\
Response: \key1\value1\key2\value2\...\final\
```

## Authentication Flow

```
┌────────┐                              ┌───────────┐
│ Client │                              │ GP Server │
└───┬────┘                              └─────┬─────┘
    │                                         │
    │◄───────── \lc\1\challenge\<SERVER_CHAL>\id\1\final\
    │                                         │
    │ \login\\challenge\<CLIENT_CHAL>\authtoken\<TICKET>\response\<CLIENT_RESP>\...
    │────────────────────────────────────────►│
    │                                         │
    │◄─── \lc\2\sesskey\<SESSKEY>\proof\<SERVER_PROOF>\userid\...\final\
    │                                         │
```

## 1. Server Challenge (lc\1)

Server sends immediately on connection.

| Field | Description |
|-------|-------------|
| `lc` | `1` |
| `challenge` | 10 random uppercase letters (A-Z) |
| `id` | `1` |

## 2. Client Login Request

| Field | Description |
|-------|-------------|
| `login` | Empty |
| `challenge` | 32-char client-generated challenge |
| `authtoken` | Base64 ticket from FESL GameSpyPreAuth |
| `response` | MD5 hash (see Client Response below) |
| `partnerid` | `0` |
| `port` | Client port |
| `productid` | Game ID (RA3: `11419`) |
| `gamename` | `redalert3pc` |
| `namespaceid` | `1` |
| `sdkrevision` | `11` |
| `firewall` | `1` or `0` |
| `quiet` | `0` |
| `id` | Request ID |

## 3. Server Login Response (lc\2)

| Field | Description |
|-------|-------------|
| `lc` | `2` (success) |
| `sesskey` | Random 9-digit session key |
| `proof` | MD5 hash (see Server Proof below) |
| `userid` | User database ID |
| `profileid` | Persona database ID |
| `uniquenick` | Player display name |
| `lt` | Base64(userid\|profileid\|secret) |
| `id` | Request ID from client |

## Proof Calculation

### Inputs

From FESL GameSpyPreAuth response:
- `challenge`: 8 lowercase letters (the **password**)
- `ticket`: Base64(userid|profileid|secret_token)

From GP handshake:
- `server_challenge`: Server's 10-char challenge
- `client_challenge`: Client's 32-char challenge
- `authtoken`: The ticket (same as above)

### Server Proof

```python
pwd_hash = MD5(fesl_challenge)  # The FESL challenge IS the password
proof = MD5(pwd_hash + "                                                " + authtoken + server_challenge + client_challenge + pwd_hash)
#           ^^^^^^^^   ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^   ^^^^^^^^^   ^^^^^^^^^^^^^^^^   ^^^^^^^^^^^^^^^^   ^^^^^^^^
#           32 chars              48 spaces                                ticket      server's chal      client's chal      32 chars
```

### Client Response (for validation)

Same formula but challenges are **swapped**:

```python
pwd_hash = MD5(fesl_challenge)
response = MD5(pwd_hash + "                                                " + authtoken + client_challenge + server_challenge + pwd_hash)
#                                                                                          ^^^^^^^^^^^^^^^^   ^^^^^^^^^^^^^^^^
#                                                                                          SWAPPED ORDER
```

### Example (with reproducible dummy values)

```
fesl_challenge   = "abcdefgh"
authtoken        = "MTAwMDAwMXwyMDAwMDAxfER1bW15U2VjcmV0VG9rZW4xMjM="
server_challenge = "ABCDEFGHIJ"
client_challenge = "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6"

MD5(fesl_challenge) = "e8dc4081b13434b45189a720b77b6818"

server_proof     = "b45781b2880edefccf21cb5a3b5b6c93"
client_response  = "98eca380e91ea22929e8d97c771bd5c1"
```

### Python verification code

```python
import hashlib, base64

fesl_challenge = "abcdefgh"
authtoken = "MTAwMDAwMXwyMDAwMDAxfER1bW15U2VjcmV0VG9rZW4xMjM="
server_challenge = "ABCDEFGHIJ"
client_challenge = "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6"

pwd_hash = hashlib.md5(fesl_challenge.encode()).hexdigest()
spaces = " " * 48

# Server proof
proof_str = pwd_hash + spaces + authtoken + server_challenge + client_challenge + pwd_hash
server_proof = hashlib.md5(proof_str.encode()).hexdigest()

# Client response (challenges swapped)
resp_str = pwd_hash + spaces + authtoken + client_challenge + server_challenge + pwd_hash
client_response = hashlib.md5(resp_str.encode()).hexdigest()
```

## Other Commands

### Status Update

Update your online status. Server notifies all online buddies via `\bm\100\`.

```
Request: \status\<CODE>\sesskey\<SESSKEY>\statstring\<STATUS>\locstring\<LOC>\final\
```

| Field | Description |
|-------|-------------|
| `status` (value after `\status\`) | Status code |
| `sesskey` | Session key |
| `statstring` | Human-readable status |
| `locstring` | Location context (channel, host, or empty) |

**Status codes:**

| Code | Name | Description |
|------|------|-------------|
| `0` | Offline | Disconnected |
| `1` | Online | Idle, in menus |
| `2` | Playing | In-game (Playing, Loading) |
| `3` | Staging | In game lobby |
| `4` | Chatting | In chat channel |

No response. Server broadcasts status to online buddies.

### Get Profile

```
Request:  \getprofile\\profileid\<ID>\sesskey\<SESSKEY>\id\<N>\final\
Response: \pi\\profileid\<ID>\nick\<NAME>\userid\<UID>\sig\<32zeros>\uniquenick\<NAME>\pid\<ID>\lon\0.000000\lat\0.000000\loc\\id\<N>\final\
```

### Buddy Messages (server-initiated)

```
\bm\<TYPE>\f\<FROM_PROFILE>\msg\<MESSAGE>\final\
```

| Type | Name | Description |
|------|------|-------------|
| `1` | Message | Direct text message |
| `2` | Buddy Request | Friend request notification |
| `4` | Ack | Acknowledgment (msg is empty) |
| `100` | Status Update | Player status change |
| `101` | Game Invite | Game/lobby invitation |

#### Status message format (type 100)

```
|s|<code>|ss|<status_string>|ls|<location>|ip|<ip_int>|p|<port>|qm|0
```

- `s`: Status code (0=Offline, 1=Online, 2=Playing, 3=Staging, 4=Chatting)
- `ss`: Human-readable status (e.g., "Online", "Playing", "Staging")
- `ls`: Location string (channel name, host info, or empty)
- `ip`: IP address as 32-bit integer
- `p`: Port number
- `qm`: Query mode (always 0)

#### Game invite format (type 101)

```
|p|<product_id>|l|<location>
```

- `p`: Product ID (11419 for RA3)
- `l`: Location/lobby info string

#### Buddy request format (type 2)

```
<message_text>|signed|<32_zeros>
```

### Keepalive

```
Request:  \ka\\final\
Response: \ka\\final\
```

### Logout

```
Request: \logout\\sesskey\<SESSKEY>\final\
```

No response. Server notifies buddies of offline status and cleans up session.

## Buddy Management Commands

### Add Buddy

Send a friend request to another player.

```
Request:  \addbuddy\\sesskey\<SESSKEY>\newprofileid\<PROFILE_ID>\reason\<MSG>\final\
Response: \bm\4\f\<PROFILE_ID>\msg\\final\
```

If target is online, server also sends their status:
```
\bm\4\f\<PROFILE_ID>\msg\\final\\bm\100\f\<PROFILE_ID>\msg\<STATUS_MSG>\final\
```

Server sends `\bm\2\` notification to the target player (see Buddy Messages).

### Authorize Add (Accept Request)

Accept a pending friend request.

```
Request: \authadd\\sesskey\<SESSKEY>\fromprofileid\<PROFILE_ID>\sig\<32zeros>\final\
```

No direct response. Server sends `\bm\100\` status update to the original requester if online.

### Delete Buddy

Remove a player from your friend list (one-way deletion).

```
Request: \delbuddy\\sesskey\<SESSKEY>\delprofileid\<PROFILE_ID>\final\
```

No response. Only removes the buddy from your list; if they have you as a friend, that relationship remains.

### Player Invite (Game Invite)

Invite a buddy to join your game lobby.

```
Request: \pinvite\\sesskey\<SESSKEY>\profileid\<PROFILE_ID>\productid\<PRODUCT_ID>\location\<LOCATION>\final\
```

| Field | Description |
|-------|-------------|
| `profileid` | Target player's profile ID |
| `productid` | Game product ID (11419 for RA3) |
| `location` | Lobby info string (see format below) |

**Location format:**
```
<channel_id> <unknown> <flags> PW: #HOST:<host_name> <topic> #FROM:<inviter_name> #CHAN:<channel_name>
```

No direct response. Server forwards `\bm\101\` to the target player (see Buddy Messages).

## Implementation Notes

1. **Session management**: Each connection gets a database session. The `sesskey` (9-digit random) is used to identify sessions across requests.

2. **Pre-auth flow**: Client must first authenticate via FESL `GameSpyPreAuth` to get a ticket before connecting to GP server. The ticket contains `userid|profileid|secret_token` and is validated/consumed on login.

3. **Challenge format**: Server challenge is 10 uppercase letters (A-Z). Client challenge is 32 characters (alphanumeric).

4. **Client response validation**: Server validates the client's `response` field before accepting login. If invalid, login fails.

5. **Buddy notifications**: Status changes trigger `\bm\100\` messages to all online friends. The session manager tracks which users are online.

6. **One-way buddy deletion**: `\delbuddy\` only removes the buddy from your list. The reverse relationship (if they have you as a friend) is unaffected.

7. **IP integer format**: IP addresses in status messages are 32-bit big-endian integers. Example: `192.168.1.1` = `(192<<24)+(168<<16)+(1<<8)+1` = `3232235777`.
