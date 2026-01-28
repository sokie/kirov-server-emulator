# ELO Rating System and Rankings

This document describes the ELO rating system and ladder rankings implementation for the Red Alert 3 server emulator.

## ELO Rating System

### Overview

The ELO rating system is used to calculate relative skill levels between players. Each player starts with an initial rating of 1200 and gains or loses points based on match outcomes.

### Core Formulas

**Expected Score:**
```
Expected = 1 / (1 + 10^((OpponentRating - PlayerRating) / 400))
```

This calculates the probability of winning against an opponent. A player with a higher rating has a higher expected score.

**Rating Update:**
```
NewRating = OldRating + K * (ActualScore - ExpectedScore)
```

Where:
- `ActualScore`: 1.0 for win, 0.5 for draw, 0.0 for loss
- `K`: K-factor (see below)

### K-Factor Progression

The K-factor determines how much a single game affects the rating:

| Condition | K-Factor | Description |
|-----------|----------|-------------|
| Games < 30 | 40 | New players - ratings adjust quickly |
| Games >= 30 | 20 | Established players - stable ratings |
| Rating >= 2400 | 10 | Elite players - very stable ratings |

### Rating Parameters

| Parameter | Value |
|-----------|-------|
| Initial Rating | 1200 |
| Minimum Rating (floor) | 100 |
| Elite Threshold | 2400 |

### Disconnect Penalty

Players who disconnect from a match receive a 1.5x K-factor multiplier on their rating loss:

```
K_effective = K * 1.5 (on disconnect loss)
```

This discourages rage-quitting and ensures disconnected players are penalized more heavily.

## Ladder Types

The server tracks separate ELO ratings for different game modes:

| Ladder | Description |
|--------|-------------|
| Ranked 1v1 | AutoMatch 1v1 games |
| Ranked 2v2 | AutoMatch 2v2 games |
| Clan 1v1 | Clan ladder 1v1 games |
| Clan 2v2 | Clan ladder 2v2 games |

Each ladder has:
- Separate ELO rating
- Separate game count (for K-factor calculation)
- Separate win/loss/disconnect/desync counters

## Player Statistics Tracking

### Per-Game-Type Stats

For each game type (unranked, ranked_1v1, ranked_2v2, clan_1v1, clan_2v2):

- **Wins**: Total wins
- **Losses**: Total losses
- **Disconnects**: Total disconnects
- **Desyncs**: Total desync occurrences
- **Average Game Length**: Running average in seconds
- **Win Ratio**: Calculated as `(wins / (wins + losses)) * 100`

### ELO Fields (Ranked modes only)

- `elo_ranked_1v1`: ELO rating for ranked 1v1
- `elo_ranked_2v2`: ELO rating for ranked 2v2
- `elo_clan_1v1`: ELO rating for clan 1v1
- `elo_clan_2v2`: ELO rating for clan 2v2

### Game Count Fields

- `games_ranked_1v1`: Total games for K-factor calculation
- `games_ranked_2v2`: Total games for K-factor calculation
- `games_clan_1v1`: Total games for K-factor calculation
- `games_clan_2v2`: Total games for K-factor calculation

## Match Finalization Flow

1. **CreateSession**: Host creates match session, receives `csid` and `ccid`
2. **SetReportIntention**: Each player signals intent to submit report, receives unique `ccid`
3. **SubmitReport**: Each player submits their match report
4. **Finalization**: When final report is received:
   - Calculate match duration from session timestamps
   - Extract winners/losers from report data
   - Calculate average opponent ELO for each team
   - Update ELO for all players
   - Update win/loss/disconnect counters
   - Mark session as finalized

## GetPlayerLadderRatings Response Format

The `GetPlayerLadderRatings.aspx` endpoint returns CSV-formatted ladder data:

```
statID,value,rank,elo,statID,value,rank,elo,...
```

### Response Fields

| Field | Description |
|-------|-------------|
| statID | Game stat identifier |
| value | Base stat value |
| rank | Player's rank (-1 if unranked) |
| elo | Player's ELO rating |

### Stat IDs

| Stat ID | Description |
|---------|-------------|
| 72587-72743 | Various game stats (value=1, rank/elo=-1) |
| 75643, 75677-75686 | Additional stats (value=1, rank/elo=-1) |
| 58938 | RA3 v1.12 AutoMatch 1v1 ladder |
| 58940 | Corona AutoMatch 1v1 ladder |

### Example Response

```
72587,1,-1,-1,72743,1,-1,-1,75643,1,-1,-1,...,58938,32034,-1,1350,58940,1088,-1,1350,
```

## Database Schema

### PlayerStats Table

```sql
player_stats (
    id INTEGER PRIMARY KEY,
    persona_id INTEGER UNIQUE,

    -- Wins per game type
    wins_unranked INTEGER DEFAULT 0,
    wins_ranked_1v1 INTEGER DEFAULT 0,
    wins_ranked_2v2 INTEGER DEFAULT 0,
    wins_clan_1v1 INTEGER DEFAULT 0,
    wins_clan_2v2 INTEGER DEFAULT 0,

    -- Losses per game type
    losses_unranked INTEGER DEFAULT 0,
    losses_ranked_1v1 INTEGER DEFAULT 0,
    losses_ranked_2v2 INTEGER DEFAULT 0,
    losses_clan_1v1 INTEGER DEFAULT 0,
    losses_clan_2v2 INTEGER DEFAULT 0,

    -- Disconnects per game type
    disconnects_unranked INTEGER DEFAULT 0,
    disconnects_ranked_1v1 INTEGER DEFAULT 0,
    disconnects_ranked_2v2 INTEGER DEFAULT 0,
    disconnects_clan_1v1 INTEGER DEFAULT 0,
    disconnects_clan_2v2 INTEGER DEFAULT 0,

    -- Desyncs per game type
    desyncs_unranked INTEGER DEFAULT 0,
    desyncs_ranked_1v1 INTEGER DEFAULT 0,
    desyncs_ranked_2v2 INTEGER DEFAULT 0,
    desyncs_clan_1v1 INTEGER DEFAULT 0,
    desyncs_clan_2v2 INTEGER DEFAULT 0,

    -- ELO ratings
    elo_ranked_1v1 INTEGER DEFAULT 1200,
    elo_ranked_2v2 INTEGER DEFAULT 1200,
    elo_clan_1v1 INTEGER DEFAULT 1200,
    elo_clan_2v2 INTEGER DEFAULT 1200,

    -- Game counts for K-factor
    games_ranked_1v1 INTEGER DEFAULT 0,
    games_ranked_2v2 INTEGER DEFAULT 0,
    games_clan_1v1 INTEGER DEFAULT 0,
    games_clan_2v2 INTEGER DEFAULT 0,

    -- Other fields
    total_matches_online INTEGER DEFAULT 0,
    created_at TIMESTAMP,
    updated_at TIMESTAMP
)
```

### PlayerReportIntent Table

```sql
player_report_intent (
    id INTEGER PRIMARY KEY,
    csid TEXT,
    ccid TEXT,
    persona_id INTEGER,
    full_id TEXT DEFAULT '',
    reported BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP
)
```

### CompetitionSession Table

```sql
competition_session (
    id INTEGER PRIMARY KEY,
    csid TEXT UNIQUE,
    ccid TEXT,
    host_persona_id INTEGER,
    status TEXT DEFAULT 'active',
    expected_players INTEGER DEFAULT 2,
    received_reports INTEGER DEFAULT 0,
    finalized BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP
)
```

## ELO Calculation Examples

### Example 1: New Player Wins

- Player A (new): Rating 1200, 5 games played
- Player B (established): Rating 1400, 50 games played
- Result: Player A wins

Calculation for Player A:
```
Expected = 1 / (1 + 10^((1400-1200)/400)) = 0.24
K = 40 (new player)
NewRating = 1200 + 40 * (1.0 - 0.24) = 1200 + 30.4 = 1230
```

Calculation for Player B:
```
Expected = 1 / (1 + 10^((1200-1400)/400)) = 0.76
K = 20 (established)
NewRating = 1400 + 20 * (0.0 - 0.76) = 1400 - 15.2 = 1385
```

### Example 2: Disconnect Penalty

- Player A: Rating 1300, 40 games
- Player B: Rating 1300, 40 games
- Result: Player A disconnects (loss)

```
Expected = 0.5 (equal ratings)
K = 20 * 1.5 = 30 (disconnect penalty)
NewRating = 1300 + 30 * (0.0 - 0.5) = 1300 - 15 = 1285
```

Without disconnect penalty, the loss would only be 10 points.
