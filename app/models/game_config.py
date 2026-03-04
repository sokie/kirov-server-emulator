"""
Per-game configuration: faction maps, game types, display lists.

Each game defines its own faction names and storage keys.
Adding a new game requires only a new entry here — no schema changes.
"""

# Game ID constants
GAME_ID_RA = 2128
GAME_ID_KW = 1814
GAME_ID_TW = 1422

GAME_TYPES = ["unranked", "ranked_1v1", "ranked_2v2", "clan_1v1", "clan_2v2"]

# Per-game faction maps: display_name → storage_key
RA3_FACTIONS = {
    "Allied": "allied",
    "Soviet": "soviet",
    "Empire": "japan",
    "Japan": "japan",
}

KW_FACTIONS = {
    "GDI": "gdi",
    "Nod": "nod",
    "Scrin": "scrin",
    "Steel Talons": "steel_talons",
    "ZOCOM": "zocom",
    "Black Hand": "black_hand",
    "Marked of Kane": "marked_of_kane",
    "Reaper-17": "reaper_17",
    "Traveler-59": "traveler_59",
}

TW_FACTIONS = {
    "GDI": "gdi",
    "Nod": "nod",
    "Scrin": "scrin",
}

# Unified lookup: game_id → faction map
FACTION_MAPS = {
    GAME_ID_RA: RA3_FACTIONS,
    GAME_ID_KW: KW_FACTIONS,
    GAME_ID_TW: TW_FACTIONS,
}

# Faction display lists for profile pages (ordered)
RA3_FACTION_DISPLAY = [
    ("Allied", "allied"),
    ("Soviet", "soviet"),
    ("Empire", "japan"),
]

KW_FACTION_DISPLAY = [
    ("GDI", "gdi"),
    ("Steel Talons", "steel_talons"),
    ("ZOCOM", "zocom"),
    ("Nod", "nod"),
    ("Black Hand", "black_hand"),
    ("Marked of Kane", "marked_of_kane"),
    ("Scrin", "scrin"),
    ("Reaper-17", "reaper_17"),
    ("Traveler-59", "traveler_59"),
]

TW_FACTION_DISPLAY = [
    ("GDI", "gdi"),
    ("Nod", "nod"),
    ("Scrin", "scrin"),
]
