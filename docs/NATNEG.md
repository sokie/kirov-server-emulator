# GameSpy NAT Negotiation Protocol

UDP server on port **27901** that facilitates P2P connections between game clients through NAT traversal.

## Protocol Constants

| Constant | Value |
|----------|-------|
| Magic Bytes | `FD FC 1E 66 6A B2` |
| Version | `0x03` |
| Default Port | `27901` |

## Packet Types

| Type | Value | Direction | Description |
|------|-------|-----------|-------------|
| INIT | `0x00` | Client → Server | Client registration |
| INIT_ACK | `0x01` | Server → Client | Registration acknowledgment |
| ERT_TEST | `0x02` | Server → Client | NAT type detection (STUN-like) |
| ERT_ACK | `0x03` | Client → Server | NAT test response |
| STATE_UPDATE | `0x04` | Bidirectional | State synchronization |
| CONNECT | `0x05` | Server → Client | Peer connection info |
| CONNECT_ACK | `0x06` | Client → Server | Connection acknowledged |
| CONNECT_PING | `0x07` | Client ↔ Client | P2P keep-alive |
| BACKUP_TEST | `0x08` | Client → Server | Backup connectivity test |
| BACKUP_ACK | `0x09` | Server → Client | Backup test response |
| ADDRESS_CHECK | `0x0A` | Client → Server | Public address request |
| ADDRESS_REPLY | `0x0B` | Server → Client | Public address response |
| NATIFY_REQUEST | `0x0C` | Client → Server | NAT detection request |
| REPORT | `0x0D` | Client → Server | Connection status report |
| REPORT_ACK | `0x0E` | Server → Client | Report acknowledgment |
| PREINIT | `0x0F` | Client → Server | Pre-initialization (v4) |
| PREINIT_ACK | `0x10` | Server → Client | Pre-init acknowledgment (v4) |

## Packet Structures

### Base Header (12 bytes)

All packets share this header:

| Offset | Size | Field | Description |
|--------|------|-------|-------------|
| 0 | 6 | magic | `FD FC 1E 66 6A B2` |
| 6 | 1 | version | Protocol version (`0x03`) |
| 7 | 1 | type | Packet type (see table above) |
| 8 | 4 | cookie | Session ID (big-endian) |

### INIT Packet (21 bytes)

Sent by client to register with server. Each client sends 4 INIT packets with port_type 0-3.

| Offset | Size | Field | Description |
|--------|------|-------|-------------|
| 0-11 | 12 | header | Base header |
| 12 | 1 | port_type | `0x00`-`0x03` (GP, NN1, NN2, NN3) |
| 13 | 1 | client_index | `0x00`=guest, `0x01`=host |
| 14 | 1 | use_game_port | Game port flag |
| 15 | 4 | local_ip | Client's local IP (4 bytes) |
| 19 | 2 | local_port | Client's local port (big-endian) |
| 21+ | var | game_name | Null-terminated ASCII string |

**Note:** port_type 0,1 have `local_port=0`. Port_type 2,3 contain the actual game port.

### INIT_ACK Packet (14 bytes)

Server response to INIT.

| Offset | Size | Field | Description |
|--------|------|-------|-------------|
| 0-11 | 12 | header | Base header (type=`0x01`) |
| 12 | 1 | port_type | Echo from INIT |
| 13 | 1 | client_index | Echo from INIT |

### CONNECT Packet (20 bytes)

Sent to both clients when session is ready. Contains peer's address for P2P connection.

| Offset | Size | Field | Description |
|--------|------|-------|-------------|
| 0-11 | 12 | header | Base header (type=`0x05`) |
| 12 | 4 | remote_ip | Peer's IP address (4 bytes) |
| 16 | 2 | remote_port | Peer's port (big-endian) |
| 18 | 1 | gotyourdata | `0x42` if peer data valid |
| 19 | 1 | finished | Error code (see below) |

**IMPORTANT:** The `finished` field is an error code, NOT a boolean:

| Value | Constant | Meaning |
|-------|----------|---------|
| `0x00` | FINISHED_NOERROR | Success |
| `0x01` | FINISHED_ERROR_DEADBEAT_PARTNER | Partner error |
| `0x02` | FINISHED_ERROR_INIT_PACKETS_TIMEDOUT | Timeout |

**Always send `0x00` for successful peer connections.**

### REPORT Packet (variable)

Client reports NAT negotiation result.

| Offset | Size | Field | Description |
|--------|------|-------|-------------|
| 0-11 | 12 | header | Base header (type=`0x0D`) |
| 12 | 1 | port_type | Port type |
| 13 | 1 | client_index | Client index |
| 14 | 1 | result | Negotiation result |
| 15 | 1 | nat_type | Detected NAT type |
| 16 | 1 | mapping_scheme | NAT mapping scheme |
| 17+ | var | game_name | Null-terminated ASCII |

### REPORT_ACK Packet (14 bytes)

| Offset | Size | Field | Description |
|--------|------|-------|-------------|
| 0-11 | 12 | header | Base header (type=`0x0E`) |
| 12 | 1 | port_type | Echo from REPORT |
| 13 | 1 | client_index | Echo from REPORT |

## Session Flow

```
Host                    Server                  Guest
  |                        |                       |
  |------- INIT x4 ------->|                       |
  |<----- INIT_ACK x4 -----|                       |
  |                        |<------ INIT x4 -------|
  |                        |------ INIT_ACK x4 --->|
  |                        |                       |
  |    [Session Ready - both clients registered]   |
  |                        |                       |
  |<----- CONNECT ---------|------- CONNECT ------>|
  |                        |                       |
  |<=================== P2P Connection ==========>|
  |                        |                       |
  |------ REPORT --------->|<------- REPORT -------|
  |<---- REPORT_ACK -------|------ REPORT_ACK ---->|
```

### Step 1: Client Registration (INIT)

Each client sends **4 INIT packets** with `port_type` 0-3, each from a different source UDP port. This creates multiple NAT mappings ("hole punching") to increase connection success probability.

- **port_type 0-1**: Sent with `local_port=0` (probe packets)
- **port_type 2-3**: Sent with actual game port (where game listens for P2P traffic)

The server tracks all 4 connections per client. Session matching uses the `session_id` (cookie), which both host and guest receive from the game lobby/matchmaking system before starting NAT negotiation.

### Step 2: Registration Acknowledgment (INIT_ACK)

Server immediately responds with INIT_ACK for each INIT received. This confirms the client's NAT mapping is working and the server can reach them.

### Step 3: Session Ready Check

Session becomes "ready" when **both** host and guest have registered with valid connections (at least one with `port_type` 2 or 3 containing the game port).

A **100ms delay** is applied before sending CONNECT packets to ensure any in-flight INIT packets are processed first.

### Step 4: Peer Exchange (CONNECT)

Server sends CONNECT packets to **all connections** of both clients (all 4 port_types). Each CONNECT contains the peer's address:
- **LAN mode**: Local IP:port from INIT packet (direct connection)
- **WAN mode**: Public IP:port as seen by server (NAT-punched address)

### Step 5: P2P Connection

Clients use the peer address from CONNECT to establish direct UDP communication. The game sends CONNECT_PING packets to maintain the connection.

### Step 6: Result Reporting (REPORT)

Clients report the negotiation outcome (success/failure, detected NAT type). Server responds with REPORT_ACK. When both clients acknowledge CONNECT, the session is marked completed.

## Configuration

The NAT negotiation server is configured via `config.json`:

```json
{
  "natneg": {
    "host": "0.0.0.0",
    "port": 27901,
    "enabled": true,
    "force_lan_mode": true
  }
}
```

| Option | Default | Description |
|--------|---------|-------------|
| `host` | `0.0.0.0` | Bind address |
| `port` | `27901` | UDP port |
| `enabled` | `true` | Enable/disable server |
| `session_timeout` | `30` | Seconds to wait for both clients |
| `force_lan_mode` | `true` | Always use LAN mode (local IPs) |

### LAN vs WAN Mode

**LAN mode** (`force_lan_mode: true`, default): CONNECT packets contain clients' local IP addresses from INIT packets. This enables direct P2P communication on the same network without NAT traversal.

**WAN mode** (`force_lan_mode: false`): Server auto-detects whether clients are on the same LAN (by comparing public IPs). If not, it uses public IP addresses in CONNECT packets. **Note: WAN mode is experimental** - full NAT punchthrough is not implemented and connections may fail for clients behind restrictive NATs.

## LAN Detection (when force_lan_mode=false)

When `force_lan_mode` is disabled, the server auto-detects LAN clients by comparing the first 3 octets of their public IPs:
- `192.168.1.10` and `192.168.1.20` → Same LAN → use local addresses
- `192.168.1.10` and `192.168.2.10` → Different networks → use public addresses

When LAN mode is active, CONNECT packets contain the `local_ip` and `local_port` from INIT packets (where the game actually listens), rather than the NAT-mapped public addresses.

## Implementation Notes

1. **Session readiness**: Don't send CONNECT until both clients have registered with at least one valid connection (port_type 2 or 3 with game port). A 100ms delay ensures late INIT packets are processed.

2. **Use local_port from port_type 2 or 3**: Earlier port_types (0-1) send `local_port=0` and are only for NAT probing.

3. **Session matching**: Host and guest share the same cookie (session_id) exchanged via game lobby before NAT negotiation starts. The server uses this to pair clients.

4. **CONNECT to all connections**: Send CONNECT packets to all 4 port_type connections per client, not just one. The game may receive on any of them.

5. **Timeout & cleanup**: Sessions expire after 30 seconds if incomplete. Cleanup runs every 10 seconds.

6. **Thread safety**: Session manager uses async locks since multiple UDP packets may arrive concurrently.

7. **Multiple sessions**: Games may create multiple concurrent sessions (e.g., separate sessions for game data and voice chat).
