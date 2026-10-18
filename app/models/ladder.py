"""
ELO ladders: the ratings Kane's Wrath and Tiberium Wars read for QuickMatch, and the search rules the RA3
matchbot applies to the same ratings.
"""

INITIAL_ELO = 1200

# A search accepts an opponent whose rating is at most this far from its own.
SEARCH_WINDOW = 400

# Kane's Wrath and Tiberium Wars search ranks in rank +- ceil(size / 8) and clip to [1, size]. With the ELO as
# the rank, this size gives a window of SEARCH_WINDOW.
LADDER_SIZE = 8 * SEARCH_WINDOW

# GetPlayerLadderRatings ladder id -> rated mode, for the ladders the QuickMatch menus read.
KW_LADDERS = {52177: "ranked_1v1", 52178: "ranked_2v2"}
TW_LADDERS = {43738: "ranked_1v1", 43783: "ranked_2v2"}


def ladder_entry(ladder_id: int, elo: int) -> str:
    """Returns one id,size,rank,rating group of GetPlayerLadderRatings, with the ELO as the rank the games read."""
    rank = min(max(elo, 1), LADDER_SIZE)
    return f"{ladder_id},{LADDER_SIZE},{rank},{elo}"


def within_reach(elo_a: int, window_a: int, elo_b: int, window_b: int) -> bool:
    """Returns True if each rating is inside the other search's window."""
    return abs(elo_a - elo_b) <= min(window_a, window_b)


def team_average(elos: list[int]) -> float:
    return sum(elos) / len(elos)


def balanced_split(ranked: list) -> tuple[list, list]:
    """Splits four players in rating order into the most even teams: the weakest and the strongest together."""
    return [ranked[0], ranked[3]], [ranked[1], ranked[2]]
