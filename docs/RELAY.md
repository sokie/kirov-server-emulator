# NAT Relay Server

UDP relay on ports **50000-59999** that provides fallback connectivity when direct P2P connections fail due to strict NAT.

## Overview

When NAT negotiation fails (strict NAT, symmetric NAT, firewall issues), clients can fall back to server-relayed traffic. The relay uses **port-based routing** - each client connects to a unique port, and the server forwards traffic between paired ports.

## Progressive Fallback

Games retry NAT negotiation up to 5 times on connection failure. The server uses this to implement progressive fallback:

| Attempt | Address Returned | Use Case |
|---------|-----------------|----------|
| 1st | Public IP | Direct P2P over internet |
| 2nd | LAN IP | Same network (LAN party) |
| 3rd+ | Relay port | Guaranteed fallback |

Most players connect directly. Relay is only used when truly needed.

## Architecture

```text
┌─────────────────────────────────────────────────────────────┐
│                     RELAY SERVER                            │
│  ┌───────────────────────────────────────────────────────┐  │
│  │              Port Pool (50000-59999)                  │  │
│  │  ┌──────────┐         ┌──────────┐                    │  │
│  │  │ Port     │◄───────►│ Port     │                    │  │
│  │  │ 50001    │ forward │ 50002    │                    │  │
│  │  │ Client A │         │ Client B │                    │  │
│  │  └──────────┘         └──────────┘                    │  │
│  └───────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
        ▲                           ▲
        │ UDP                       │ UDP
        ▼                           ▼
  ┌──────────┐                ┌──────────┐
  │ Client A │                │ Client B │
  │ (Host)   │                │ (Guest)  │
  └──────────┘                └──────────┘
```

## Session Flow

```text
Host                    Server                    Guest
  |                        |                        |
  |------- INIT x4 ------->|<------- INIT x4 -------|
  |<----- INIT_ACK --------|-------- INIT_ACK ----->|
  |                        |                        |
  |    [Attempt 1: Send public IPs - FAILS]         |
  |    [Attempt 2: Send LAN IPs - FAILS]            |
  |    [Attempt 3: Allocate relay ports]            |
  |                        |                        |
  |<-- CONNECT (relay:50001) | CONNECT (relay:50002)->|
  |                        |                        |
  |====== UDP to relay:50001 =====>|                |
  |                   [forward]    |                |
  |                        |====== UDP to Guest ===>|
```

## Configuration

```json
{
  "relay": {
    "host": "203.0.113.10",
    "port_start": 50000,
    "port_end": 59999,
    "session_timeout": 120,
    "pair_ttl": 60,
    "enabled": true
  }
}
```

| Option | Default | Description |
|--------|---------|-------------|
| `host` | `0.0.0.0` | **Must be your public IP** for clients to reach relay |
| `port_start` | `50000` | Start of UDP port range |
| `port_end` | `59999` | End of UDP port range (10,000 ports = 5,000 pairs) |
| `session_timeout` | `120` | Seconds of inactivity before relay route cleanup |
| `pair_ttl` | `60` | Seconds before connection attempt tracking expires |
| `enabled` | `true` | Enable/disable relay |

## Implementation Notes

1. **Attempt tracking by IP pair**: Tracks `(host_ip, guest_ip)` not session_id, because clients retry with new session_ids but same IPs.

2. **Dynamic port allocation**: Ports are allocated on-demand when relay is needed (3rd+ attempt) and released after timeout.

3. **Firewall requirements**: UDP ports 50000-59999 must be open and forwarded to the server.

4. **Bandwidth**: Each relay session forwards all game traffic. RA3 uses ~10-50 KB/s per player.

5. **Capacity**: 10,000 port range supports 5,000 concurrent relay sessions.
