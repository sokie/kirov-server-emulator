"""
Per-game configuration: faction maps, game types, display lists, leveling.

Each game defines its own faction names and storage keys.
Adding a new game requires only a new entry here — no schema changes.
"""

# Game ID constants
GAME_ID_RA = 2128
GAME_ID_KW = 1814
GAME_ID_TW = 1422

GAME_TYPES = ["unranked", "ranked_1v1", "ranked_2v2", "clan_1v1", "clan_2v2"]

# XP thresholds for 87 ranks (shared by RA3, KW, TW — SAGE engine games)
SAGE_LEVEL_THRESHOLDS = [
    0,
    5,
    13,
    23,
    35,
    50,
    67,
    86,
    106,
    127,
    150,
    175,
    202,
    231,
    262,
    295,
    330,
    367,
    406,
    447,
    490,
    535,
    582,
    631,
    682,
    735,
    790,
    847,
    906,
    967,
    1030,
    1095,
    1162,
    1231,
    1302,
    1375,
    1454,
    1538,
    1628,
    1724,
    1825,
    1927,
    2030,
    2134,
    2239,
    2345,
    2452,
    2560,
    2674,
    2794,
    2920,
    3049,
    3180,
    3314,
    3451,
    3590,
    3738,
    3894,
    4058,
    4230,
    4410,
    4595,
    4784,
    4978,
    5177,
    5380,
    5590,
    5807,
    6031,
    6262,
    6500,
    6744,
    6993,
    7247,
    7506,
    7770,
    8044,
    8328,
    8622,
    8926,
    9240,
    9562,
    9890,
    10224,
    10564,
    10910,
    11310,
]

# XP awarded per win: index 0=unranked(1), 1=ranked_1v1(2), 2=ranked_2v2(2), 3=clan(5)
SAGE_SCORING_MULTIPLIERS = [1, 2, 2, 5]

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
