# C&C Server Emulator

An open-source server emulator for the Command & Conquer series, implementing the GameSpy and EA backend protocols required for online multiplayer.

### Supported Games

- **Command & Conquer 3: Tiberium Wars** (CNC3)
- **Command & Conquer 3: Kane's Wrath** (KW)
- **Command & Conquer: Red Alert 3** (RA3)
- **Command & Conquer: Generals**
- **Command & Conquer: Generals Zero Hour**

## Project Goals

This project aims to:

- **Preserve multiplayer functionality** for C&C games after official server shutdowns
- **Document decades-old protocols** that were previously undocumented or poorly understood
- **Empower players** with ownership and control over their gaming infrastructure, working both offline and in LAN
- **Provide a reference implementation** for researchers and developers interested in the game server architecture

## Features

### Implemented

- [x] **FESL Server** - EA Frontend Service Layer for authentication and session management
- [x] **GP Server** - GameSpy Presence server for buddy system, status, and messaging
- [x] **Peerchat Server** - IRC-based lobby, chat, and game session coordination
- [x] **NAT Negotiation Server** - UDP hole punching for peer-to-peer connections
- [x] **Master Server** - Game server listing and room discovery (TCP)
- [x] **Heartbeat Server** - Game session registration and keepalive (UDP)
- [x] **GameStats Server** - Game statistics reporting and retrieval
- [x] **Multi-game support** - CNC3, Kane's Wrath, and Red Alert 3 with per-game gamekeys, entitlements, and protocol handling

> **Current Status:** The server is fully functional and supports all core gameplay features including user authentication (login), friends system, lobby browsing and creation, in-game chat, cooperative campaigns, and online multiplayer matches.

### Planned

- [x] (done)**Sake Storage Server** - Storage
- [x] (done)**Stats server** - Stats
- [x] (done)**Competition server** - Post-match stats
- [x] (done)**Web Portal** - Account registration, leaderboards, and live match viewer
- [x] (done)**Clan System** - Create, join, and manage clans with in-game integration
- [x] (done)**CNC3 & Kane's Wrath** - Multi-game support for CNC3 and Kane's Wrath
- [ ] **Auto matchmaking** - Add support for automatic ELO based matchmaking bot
- [x] (initial support)**Generals** - (low prio) Support generals games

## Quick Start

### Prerequisites

- Python 3.11+
- pip

### Game Client Setup

To redirect a game client to your emulator, you need to install a game proxy that intercepts DNS/network calls and routes them to your server.

For Red Alert 3, CNC3 and Kane's Wrath you can use the [CnC Game Proxy](https://github.com/sokie/cnc_game_proxy/):

1. Download or build the proxy from [CnC Game Proxy](https://github.com/sokie/cnc_game_proxy)
2. Install it to your game's `Data/` folder (e.g., `C:\Program Files\EA Games\Red Alert 3\Data\`) or other appropriate folder
3. Configure the proxy to point to your emulator server

### Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/ra3_backend_server.git
cd ra3_backend_server
```

2. Create a virtual environment:
```bash
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

4. Create configuration file:
```bash
cp config.example.json config.json
```

Then edit `config.json` and set your per-game keys. Each supported game requires its own gamekey:

```json
{
  "game": {
    "gamekeys": {
      "cnc3pc": "YOUR_CNC3_GAME_KEY",
      "cnc3ep1pc": "YOUR_KW_GAME_KEY",
      "cncra3pc": "YOUR_RA3_GAME_KEY"
    }
  }
}
```

See `config.example.json` for all available options.

### Running the Server

Start all servers with uvicorn ( note port 80 needs `sudo` on some systems ):

```bash
uvicorn app.main:app --host 0.0.0.0 --port 80 --reload
```

This starts:

| Service | Port | Protocol | Description |
|---------|------|----------|-------------|
| REST/SOAP API | 80 | HTTP | Web API and SOAP services |
| FESL | 18800 | TCP | Authentication and session |
| Peerchat IRC | 6667 | TCP | Lobby and chat |
| GP Server | 29900 | TCP | Buddy system and presence |
| NAT Negotiation | 27901 | UDP | P2P hole punching |
| NAT Relay | 50000-59999 | UDP | Relay fallback when direct P2P fails (`relay.host` must be your public IP) |
| Master Server | 28910 | TCP | Room/game list queries |
| Heartbeat Server | 27900 | UDP | Game session registration |
| GameStats | 29920 | TCP | Game statistics reporting |

### Web Portal

The server includes a web portal for account management, leaderboards, and live match viewing. Access it at `http://localhost/` after starting the server.

See [Web Portal Documentation](docs/ui/WEB_PORTAL.md) for detailed information and screenshots.

### Running Tests

```bash
python -m pytest app/test/ -v
```

## Documentation

Detailed protocol documentation is available in the `docs/` directory:

| Document | Description |
|----------|-------------|
| [FESL.md](docs/FESL.md) | EA authentication protocol with packet structures and authentication flow |
| [GP_SERVER.md](docs/GP_SERVER.md) | GameSpy Presence protocol for buddy system and messaging |
| [PEERCHAT.md](docs/PEERCHAT.md) | IRC-based lobby system with GameSpy extensions for game coordination |
| [NATNEG.md](docs/NATNEG.md) | NAT negotiation protocol for establishing peer-to-peer connections |
| [RELAY.md](docs/RELAY.md) | UDP relay fallback when direct P2P fails |
| [MASTER_SERVER.md](docs/MASTER_SERVER.md) | Master server for game discovery and session registration |

## Architecture Overview

```
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                          Game Client (CNC3 / Kane's Wrath / RA3)                       │
└────────────────────────────────────────────────────────────────────────────────────────┘
       │            │            │            │            │            │
       ▼            ▼            ▼            ▼            ▼            ▼
  ┌─────────┐ ┌──────────┐ ┌──────────┐ ┌─────────┐ ┌───────────────┐ ┌───────────┐
  │  FESL   │ │ Peerchat │ │    GP    │ │ NATNEG  │ │ Master Server │ │ GameStats │
  │ :18800  │ │  :6667   │ │  :29900  │ │ :27901  │ │ TCP :28910    │ │  :29920   │
  │  (TCP)  │ │  (TCP)   │ │  (TCP)   │ │  (UDP)  │ │ UDP :27900    │ │  (TCP)    │
  └────┬────┘ └────┬─────┘ └────┬─────┘ └────┬────┘ └───────┬───────┘ └─────┬─────┘
       │            │            │            │              │               │
       └────────────┴────────────┴────────────┴──────────────┴───────────────┘
                                              │
                                       ┌──────┴──────┐
                                       │   Database  │
                                       │  (SQLite)   │
                                       └─────────────┘
```

**Flow:**
1. Client connects to FESL - the `clientString` in the Hello packet identifies the game (CNC3, KW, or RA3)
2. FESL authenticates the user (NuLogin for RA3, Login for CNC3/KW) and issues a session
3. FESL issues a ticket for GP Server authentication
4. Client connects to Peerchat for lobby/chat (per-game gamekey used for encryption)
5. Client connects to GP Server for buddy system
6. Client queries Master Server (TCP :28910) for room/game lists
7. Game hosts register via Heartbeat Server (UDP :27900)
8. During game start, clients use NAT Negotiation for P2P setup
9. GameStats server handles post-match statistics reporting

## Contributing

Contributions are welcome! Please feel free to submit issues and pull requests.

## License

This project is provided for educational and preservation purposes.

## Disclaimer

This project is not affiliated with or endorsed by Electronic Arts, Westwood Studios, or any related entities. Command & Conquer, Red Alert 3, Tiberium Wars, and Kane's Wrath are trademarks of Electronic Arts Inc.








