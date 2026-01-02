# FESL Protocol Server Implementation

FESL (EA Frontend Server Layer) handles authentication and session management for Red Alert 3. Clients connect via TCP and exchange binary packets with key-value payloads.

## Packet Structure

### Header Format (12 bytes)

| Offset | Size | Field | Description |
|--------|------|-------|-------------|
| 0 | 4 | Command | ASCII command type (`fsys`, `acct`) |
| 4 | 1 | Type | Packet type tag (see below) |
| 5 | 3 | PacketNum | 24-bit packet sequence number |
| 8 | 4 | Size | Total packet size (header + payload) |

**Packet Types:**

| Value | Name | Direction |
|-------|------|-----------|
| `0xC0` | TAG_SINGLE_CLIENT | Client → Server |
| `0x80` | TAG_SINGLE_SERVER | Server → Client |
| `0xF0` | TAG_MULTI_CLIENT | Client → Server (fragmented) |
| `0xB0` | TAG_MULTI_SERVER | Server → Client (fragmented) |

### Header Hex Example

```
66 73 79 73  c0 00 00 01  00 00 00 b0
│           │  │        │           │
│           │  │        │           └─ Size: 0xB0 (176 bytes)
│           │  │        └─ PacketNum: 0x000001 (1)
│           │  └─ Type: 0xC0 (TAG_SINGLE_CLIENT)
│           │
└───────────└─ Command: "fsys"
```

### Payload Format

Payload is a null-terminated UTF-8 string with newline-separated key-value pairs:

```
TXN=Hello
clientString=cncra3-pc
sku=15299
locale=en_US
\0
```

- First field must be `TXN=<TransactionType>`
- Arrays use indexed notation: `personas.[]=2`, `personas.0=name1`, `personas.1=name2`
- Nested objects use dot notation: `domainPartition.domain=eagames`

## Authentication Flow

```
┌────────┐                                    ┌─────────────┐
│ Client │                                    │ FESL Server │
└───┬────┘                                    └──────┬──────┘
    │                                                │
    │─────────── fsys Hello ────────────────────────►│
    │◄──────────────────────────── fsys Hello + MemCheck
    │                                                │
    │─────────── fsys MemCheck (response) ──────────►│
    │                                                │
    │─────────── acct NuLogin ──────────────────────►│
    │◄────────────────────────────────── acct NuLogin
    │                                                │
    │─────────── acct NuGetPersonas ────────────────►│
    │◄──────────────────────────── acct NuGetPersonas
    │                                                │
    │─────────── acct NuLoginPersona ───────────────►│
    │◄─────────────────────────── acct NuLoginPersona
    │                                                │
    │─────────── acct GameSpyPreAuth ───────────────►│
    │◄─────────────────────────── acct GameSpyPreAuth
    │                                                │
    │              [Client connects to GPServer]     │
```

## Command Reference

### fsys Commands

#### Hello

Initial handshake. Server responds with Hello + MemCheck (two packets).

**Client Request:**

| Field | Type | Description |
|-------|------|-------------|
| `TXN` | string | `Hello` |
| `clientString` | string | Game identifier (`cncra3-pc`) |
| `sku` | int | Game SKU (`15299`) |
| `locale` | string | Client locale (`en_US`) |
| `clientPlatform` | string | Platform (`PC`) |
| `clientVersion` | string | Version (`1.0`) |
| `SDKVersion` | string | SDK version (`4.3.4.0.0`) |
| `protocolVersion` | string | Protocol version (`2.0`) |
| `fragmentSize` | int | Max fragment size (`8096`) |
| `clientType` | string | Client type (usually empty) |

**Server Response:**

| Field | Type | Description |
|-------|------|-------------|
| `TXN` | string | `Hello` |
| `theaterIp` | string | Theater server IP |
| `theaterPort` | int | Theater server port |
| `messengerIp` | string | Messenger IP (unused) |
| `messengerPort` | int | Messenger port (unused) |
| `activityTimeoutSecs` | int | Activity timeout |
| `curTime` | string | Server time (quoted) |
| `domainPartition.domain` | string | Domain (`eagames`) |
| `domainPartition.subDomain` | string | Sub-domain (`CNCRA3`) |

**Example Request Packet (hex):**

```
66 73 79 73 c0 00 00 01 00 00 00 b0
54 58 4e 3d 48 65 6c 6c 6f 0a        TXN=Hello\n
63 6c 69 65 6e 74 53 74 72 69 6e 67  clientString
3d 63 6e 63 72 61 33 2d 70 63 0a     =cncra3-pc\n
73 6b 75 3d 31 35 32 39 39 0a        sku=15299\n
...
00                                   \0 (null terminator)
```

#### MemCheck

Anti-cheat/memory check. Server sends this with Hello, client must respond.

**Server Request (sent with Hello):**

| Field | Type | Description |
|-------|------|-------------|
| `TXN` | string | `MemCheck` |
| `type` | int | Check type (`0`) |
| `salt` | int | Random 32-bit salt |
| `memcheck.[]` | int | Array size (`0`) |

**Client Response:**

| Field | Type | Description |
|-------|------|-------------|
| `TXN` | string | `MemCheck` |
| `result` | string | Check result (empty string accepted) |

**Note:** MemCheck is server-initiated and uses packet number `0`.

---

### acct Commands

#### NuLogin

Initial user authentication with email and password.

**Client Request:**

| Field | Type | Description |
|-------|------|-------------|
| `TXN` | string | `NuLogin` |
| `returnEncryptedInfo` | int | Return encrypted info flag (`1`) |
| `nuid` | string | User's email address |
| `password` | string | User's password |
| `macAddr` | string | MAC address (`$aabbccddeeff`) |

**Server Response:**

| Field | Type | Description |
|-------|------|-------------|
| `TXN` | string | `NuLogin` |
| `nuid` | int | User ID |
| `profileId` | int | Profile ID (same as userId initially) |
| `userId` | int | User database ID |
| `displayName` | string | User's display name |
| `lkey` | string | Login key token for session |
| `entitledGameFeatureWrappers.[]` | int | Number of entitlements |
| `entitledGameFeatureWrappers.N.gameFeatureId` | int | Feature ID (e.g., `6014`) |
| `entitledGameFeatureWrappers.N.entitlementExpirationDays` | int | Days until expiry (`-1` = never) |
| `entitledGameFeatureWrappers.N.entitlementExpirationDate` | string | Expiry date (or empty) |
| `entitledGameFeatureWrappers.N.message` | string | Message (or empty) |
| `entitledGameFeatureWrappers.N.status` | int | Status (`0` = active) |

**Example Response Payload:**

```
TXN=NuLogin
nuid=1000001
profileId=1000001
userId=1000001
displayName=testplayer
lkey=T4QdgDQCFm83wYUMCn4qpAAAKDw.
entitledGameFeatureWrappers.[]=1
entitledGameFeatureWrappers.0.entitlementExpirationDate=
entitledGameFeatureWrappers.0.entitlementExpirationDays=-1
entitledGameFeatureWrappers.0.gameFeatureId=6014
entitledGameFeatureWrappers.0.message=
entitledGameFeatureWrappers.0.status=0
```

#### NuGetPersonas

Get list of personas (characters) for the logged-in user.

**Client Request:**

| Field | Type | Description |
|-------|------|-------------|
| `TXN` | string | `NuGetPersonas` |
| `namespace` | string | Namespace filter (usually empty) |

**Server Response:**

| Field | Type | Description |
|-------|------|-------------|
| `TXN` | string | `NuGetPersonas` |
| `personas.[]` | int | Number of personas |
| `personas.N` | string | Persona name at index N |

**Example Response:**

```
TXN=NuGetPersonas
personas.[]=2
personas.0=MainCharacter
personas.1=AltCharacter
```

#### NuAddPersona

Create a new persona for the logged-in user.

**Client Request:**

| Field | Type | Description |
|-------|------|-------------|
| `TXN` | string | `NuAddPersona` |
| `name` | string | Name for new persona |

**Server Response:**

| Field | Type | Description |
|-------|------|-------------|
| `TXN` | string | `NuAddPersona` |

(Empty response on success, just TXN)

#### NuLoginPersona

Select a persona to play as. This generates a new `lkey` and sets the `profileId`.

**Client Request:**

| Field | Type | Description |
|-------|------|-------------|
| `TXN` | string | `NuLoginPersona` |
| `name` | string | Persona name to login as |

**Server Response:**

| Field | Type | Description |
|-------|------|-------------|
| `TXN` | string | `NuLoginPersona` |
| `userId` | int | User's database ID |
| `profileId` | int | Selected persona's database ID |
| `lkey` | string | New login key for persona session |

**Important:** `profileId` differs from `userId` - it's the persona's ID, not the user's.

#### GameSpyPreAuth

Generate authentication ticket for GPServer handshake. Must call `NuLoginPersona` first.

**Client Request:**

| Field | Type | Description |
|-------|------|-------------|
| `TXN` | string | `GameSpyPreAuth` |

**Server Response:**

| Field | Type | Description |
|-------|------|-------------|
| `TXN` | string | `GameSpyPreAuth` |
| `challenge` | string | 8 lowercase letters (used as password for GP proof) |
| `ticket` | string | Base64-encoded ticket |

**Ticket Format:**

```
ticket = base64(userId|profileId|secretToken)
```

Example: `MTAwMDAwMXwyMDAwMDAxfER1bW15U2VjcmV0VG9rZW4xMjM=` decodes to `1000001|2000001|DummySecretToken123`

The `challenge` field is the **password** used in GPServer proof calculation (see `docs/GP_SERVER.md`).

---

## Implementation Notes

1. **Packet numbering**: Client packets increment from 1. Server responses echo the client's packet number. Exception: `MemCheck` is server-initiated and uses packet number `0`.

2. **Hello + MemCheck**: These must be sent together. The game expects both packets in response to Hello.

3. **Session context**: Use a context variable to store user/session data across requests within a connection. The flow is stateful:
   - `NuLogin` → stores user
   - `NuGetPersonas` → reads user from context
   - `NuLoginPersona` → stores persona
   - `GameSpyPreAuth` → requires both user and persona

4. **lkey regeneration**: A new `lkey` is generated after `NuLoginPersona`. This key is used for subsequent authenticated requests.

5. **Array serialization**: Arrays use `field.[]=count` followed by `field.0=value`, `field.1=value`, etc. Order of fields matters for some clients.

6. **Entitlements**: If user has no entitlements in DB, return default RA3 entitlement (`gameFeatureId=6014`).

7. **Error handling**: Currently returns `None` for errors. Production should return proper error packets with error codes.

8. **GameSpyPreAuth bridge**: The ticket from this response is consumed by GPServer's `\login\` command. Store it in DB with expiry and validate/consume on GP side.

## Testing

See `app/test/test_fesl_parsing.py` for:
- Header parsing tests
- Packet round-trip tests
- All TXN type serialization tests
- Authentication chain validation

Run tests:
```bash
python -m pytest app/test/test_fesl_parsing.py -v
```