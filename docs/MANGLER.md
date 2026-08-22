# SAGE Mangler Protocol

UDP service on port **4321** used by Generals, Zero Hour, Tiberium Wars, and Kane's Wrath to observe public UDP mappings, classify NAT behavior, and predict ports for peer-to-peer connections.

The Mangler is a small STUN-like service. It reports the public IP address and source port from which it received a packet. It does **not** forward game traffic and is not a relay.

## Service Discovery

The client obtains the Mangler endpoints from the `<Manglers>` block in the server configuration document:

```text
<Manglers>
127.0.0.1:4321
127.0.0.2:4321
127.0.0.3:4321
</Manglers>
```

Each non-empty line has the form `<host>:<port>`. `host` may be an IPv4 address or a DNS hostname. Although the port is parsed from the document, the stock game code sends Mangler requests to UDP port **4321**, so compatible configurations should always specify `4321`.

The client resolves entries in order and deduplicates them by their resolved IPv4 address, not by the text in the configuration. For example, three different hostnames which all resolve to `203.0.113.10` count as only one Mangler address.

| Resolved unique addresses | Result |
|---------------------------|--------|
| Fewer than 3 | Full classification is aborted |
| 3 | Minimum required for classification |
| 4 | Maximum retained by the client and the original EA configuration |
| More than 4 | Additional addresses are not retained after four unique addresses are found |

All configured names should resolve successfully. The stock resolution loop is sequential, and an unresolvable entry can stop discovery before the client has collected the three addresses it needs.

Distinct addresses may route to separate Mangler machines or to different interfaces/NAT rules on one machine. What matters is that the **client sees distinct destination IPv4 addresses**. Using the same server process behind several public IPs is valid; using several DNS names for one public IP is not sufficient because of deduplication.

The original EA configuration supplied four addresses, but only three are required by the classifier.

The loopback addresses above are suitable only when the game and server run on the same computer. Internet clients need publicly reachable addresses, and UDP port 4321 must reach the Mangler service on each address. The service may run on any machine; it does not need to share a host with PeerChat or the relay.

## Packet Format

Requests and responses are 20-byte UDP datagrams. Multi-byte values use network byte order.

| Offset | Size | Field | Description |
|--------|------|-------|-------------|
| 0 | 4 | checksum | Rolling checksum over bytes 4-19 |
| 4 | 2 | magic | `0xF00E` for CNC3; `0xF00D` for Generals |
| 6 | 2 | packet ID | Identifies the request and response |
| 8 | 2 | public port | Source port observed by the Mangler in a response |
| 10 | 2 | original port | Client's original UDP source port |
| 12 | 4 | public address | Source IPv4 address observed by the Mangler in a response |
| 16 | 1 | command | `0x0C` for a request; `0x2C` for a response |
| 17 | 1 | Blitz | Requests replies from adjacent Mangler ports when non-zero |
| 18 | 2 | padding | Reserved |

The server validates the packet length, checksum, and game magic. It accepts `0xF00D` for Generals/Zero Hour and `0xF00E` for Tiberium Wars/Kane's Wrath. It then copies the request, fills in the observed address and port, changes the command to `0x2C`, recalculates the checksum, and returns it to the sender.

## Blitz and Adjacent Ports

The `Blitz` byte asks the Mangler to send several copies of the response from adjacent server ports to adjacent client ports. For a Mangler configured on UDP port 4321 and a request received from client port 12000, the traffic is:

| Server source | Client destination | Purpose |
|---------------|--------------------|---------|
| `4321` | `12000` | Normal Mangler response |
| `4322` | `12001` | First Blitz packet |
| `4323` | `12002` | Second Blitz packet |
| `4324` | `12003` | Third Blitz packet |

```text
Client 12000 ---- request ----> Mangler 4321
Client 12000 <--- response ----- Mangler 4321
Client 12001 <--- Blitz -------- Mangler 4322
Client 12002 <--- Blitz -------- Mangler 4323
Client 12003 <--- Blitz -------- Mangler 4324
```

All four responses contain the public endpoint observed for the original request. The additional packets do not report four different mappings. They generate inbound traffic from different server ports toward neighboring client ports, allowing the client's firewall/NAT behavior to be exercised beyond the ordinary request-and-response mapping.

Only requests received on the primary port are processed. Ports 4322-4324 are output sockets for the additional replies; clients do not send separate Mangler requests to them as part of Blitz.

The released Generals client contains the `BlitzMe` field and helper support, but its normal classifier calls the helper with Blitz disabled. CNC3 retains the same packet field. Normal CNC3 classification does not require Blitz responses, so disabling them does not disable basic endpoint observation or NAT classification.

When `mangler.blitz_enabled` is `true`, Kirov binds UDP ports 4321-4324 and honors a non-zero Blitz byte. When it is `false`, Kirov binds only port 4321 and always sends the normal response. A public deployment that enables Blitz must allow the server to send UDP from ports 4322-4324 in addition to port 4321.

## Classification Flow

The client opens several temporary UDP sockets and sends requests through them to different Mangler addresses. It then compares the public ports reported in the responses.

```text
Client                  Mangler 1               Mangler 2               Mangler 3
  |-- socket A request --->|                        |                       |
  |<-- public endpoint A --|                        |                       |
  |-- socket A request ---------------------------->|                       |
  |<------------------------- public endpoint A' --|                       |
  |-- socket B requests --------------------------------------------------->|
  |<------------------------------------------------ observed endpoints ----|
  |
  |  Compare the observations, calculate FirewallBehavior and port delta
```

Among other tests, this reveals whether the router:

- preserves the client's source port;
- uses the same public port for different destination IP addresses;
- changes the mapping for different destination IP addresses or ports; and
- allocates new public ports according to a predictable sequence.

The classification is performed by the **game client**. The Mangler only reports observations and neither chooses nor receives the final NAT type.

## NAT Behavior Flags

`FirewallBehavior` is a decimal bitmask. More than one flag can be set at once; for example, `20` is `SMART_MANGLING | SIMPLE_PORT_ALLOCATION` (`4 | 16`).

| Value | Name | Meaning | Client behavior |
|-------|------|---------|-----------------|
| `0` | `UNKNOWN` | No cached result or classification failed | Treated like a simple connection during peer setup: advertise the ordinary source port |
| `1` | `SIMPLE` | No port translation, or the router preserves the source port | Advertise the ordinary source port; no per-peer Mangler query is needed |
| `2` | `DUMB_MANGLING` | The router translates the port but keeps the same public mapping for different destination IPs | Reuse a previously learned public port when possible |
| `4` | `SMART_MANGLING` | The public port changes with the destination IP | Query a Mangler during peer setup and predict the mapping that the peer will see |
| `8` | `NETGEAR_BUG` | Unsolicited traffic from a known IP may replace an otherwise valid mapping | Change probe ordering and delay sending so the other client opens its mapping first |
| `16` | `SIMPLE_PORT_ALLOCATION` | New mappings follow an absolute port-offset sequence | Predict the next public port as the observed Mangler port plus `FirewallPortAllocationDelta` |
| `32` | `RELATIVE_PORT_ALLOCATION` | The mapping depends partly on the original local source port | Apply the relative prediction formula using the source port and saved delta |
| `64` | `DESTINATION_PORT_DELTA` | The mapping changes with the destination UDP port | Do not reuse a mapping merely because the destination IP is unchanged; use the prediction path |
| `128` | CNC3 allocation flag | CNC3 sets this when an additional port-allocation prediction test does not match the expected sequence | Preserved and shared as part of the bitmask; its original symbolic name is not present in the Generals source release |

Flags `8`, `16`, `32`, `64`, and `128` qualify the basic mapping behavior rather than replacing it. Code consuming the value must test individual bits instead of comparing only the complete decimal value.

## How the Client Uses the Result

During peer-to-peer setup, the client first checks whether both players have the same public IP. Players behind the same router use their local endpoint information.

For players on different public IPs:

1. `UNKNOWN` and `SIMPLE` clients advertise their normal game source port.
2. A destination-independent NAT can reuse a public port learned for an earlier peer.
3. A destination-dependent or allocation-sensitive NAT sends another Mangler request from a temporary socket.
4. The client combines the observed public port with `FirewallPortAllocationDelta` and its local source port to predict the game socket's next public mapping.
5. That predicted port is sent to the other player through the PeerChat `NAT/ PORT` exchange.

If the Mangler cannot be resolved or does not reply during connection setup, the client falls back to advertising its ordinary source port. The NAT type helps the stock client choose a traversal strategy; it is not itself a command to use the relay.

## Sharing the NAT Type in a Lobby

The host owns the authoritative lobby slot list. A joining guest reports its cached NAT behavior directly to the host over PeerChat:

```text
Guest -> Host
UTM John :REQ/ NAT=4
```

The host stores `4` in that guest's human slot and sends an updated `SL/` message to the staging channel. Each human slot record contains the player's NAT behavior as one of its numeric fields:

```text
Host -> Staging channel
UTM #GSP!... :SL/ ...;S=HJohn,<ip>,<port>,...,1,...:HDoe,<ip>,<port>,...,4,...:
```

The example is abbreviated: `SL/` also carries map, color, faction, team, acceptance, and other slot data. The important flow is:

```text
Host reads its own FirewallBehavior
Guest sends REQ/ NAT=<behavior> to host
Host updates the guest slot
Host broadcasts authoritative SL/
All clients learn every player's NAT behavior from SL/
```

The server normally forwards these PeerChat messages; the NAT classification is produced and interpreted by the clients. Quick Match follows the same principle but carries each player's NAT value through the MatchBot request and response instead of a staging-room `SL/` exchange.

## Refreshing NAT Classification

While online, selecting **Options > Network > Refresh NAT** (internally `RefreshNAT`) starts a new classification immediately:

1. The client sets `FirewallNeedToRefresh = TRUE`.
2. It discards the cached behavior and runs the Mangler tests again.
3. It writes the new `FirewallBehavior` and `FirewallPortAllocationDelta` to `Options.ini`.
4. It sets `FirewallNeedToRefresh = FALSE` after the test completes.

Starting the online flow with `FirewallNeedToRefresh = TRUE` also forces a recheck instead of reusing the cached result.

## Options.ini Settings

The game stores the classification in the active player's `Options.ini` file.

| Setting | Meaning |
|---------|---------|
| `FirewallBehavior` | Decimal NAT behavior bitmask described above; normally written by the classifier |
| `FirewallPortAllocationDelta` | Signed port step or offset used to predict the next public mapping |
| `FirewallNeedToRefresh` | `TRUE` forces classification; normally returns to `FALSE` after a successful refresh |
| `FirewallPortOverride` | Manually selected UDP game port; `0` disables the override |
| `SendDelay` | Enables the Netgear workaround represented by flag `8` and changes NAT probe ordering |

Example result:

```ini
FirewallBehavior = 4
FirewallNeedToRefresh = FALSE
FirewallPortAllocationDelta = 0
FirewallPortOverride = 0
SendDelay = no
```

When `FirewallPortOverride` is non-zero, CNC3 skips the normal Mangler classification and treats the connection as `SIMPLE`. If `SendDelay` is also enabled, the resulting behavior is `9` (`SIMPLE | NETGEAR_BUG`). Running **Refresh NAT** may overwrite manually edited behavior and delta values.

## Server Configuration

The Mangler service is configured in `config.json`:

```json
{
  "mangler": {
    "host": "0.0.0.0",
    "port": 4321,
    "blitz_enabled": true,
    "enabled": true
  }
}
```

| Option | Default | Description |
|--------|---------|-------------|
| `host` | `0.0.0.0` | Local IPv4 address on which to bind |
| `port` | `4321` | Primary UDP port |
| `blitz_enabled` | `true` | Bind ports 4321-4324 and honor Blitz requests; when disabled, bind only the primary port |
| `enabled` | `true` | Enable or disable the Mangler service |

`host` is only the local bind address. The addresses advertised in `<Manglers>` must be reachable by the clients and routed to this service.

## Implementation Notes

1. **At least three distinct addresses:** The client rejects a full test when it cannot resolve at least three unique Mangler IPv4 addresses.

2. **One service can answer several addresses:** Multiple public addresses may be routed to one server, provided the client still sees them as distinct destination IPs.

3. **Mangler and relay are separate:** Mangler packets use temporary sockets to measure mappings. Gameplay packets use the game socket, and the Mangler never forwards them.

4. **Reported values are hints, not proof of reachability:** A NAT flag describes observed mapping behavior. Direct connection attempts can still succeed or fail for other firewall and routing reasons.

5. **CNC3 and Generals are similar, not identical:** The shared SAGE implementation explains flags `0`-`64`. CNC3's binary additionally uses bit `128`, so it is documented separately without assigning an unverified original name.
