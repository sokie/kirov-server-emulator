"""
Row selection for the Sake tables that are answered by field name.
"""

from collections.abc import Callable

from app.models.game_config import SAGE_LEVEL_THRESHOLDS
from app.soap.models.common import RecordValue
from app.soap.sake_filter import compile_filter

Getter = Callable[[str], int | float | str | None]
ValueOf = Callable[[str, int, Getter], RecordValue]  # (field, row id, getter)


def level_rows() -> list[tuple[int, Getter]]:
    """One Levels record per rank: Level (1-based) and Score (the rank's first score)."""
    rows = []
    for i, score in enumerate(SAGE_LEVEL_THRESHOLDS):
        level = i + 1
        values = {"level": level, "score": score, "recordid": level}
        rows.append((level, lambda name, v=values: v.get(name.lower())))
    return rows


def _parse_sort(sort: str) -> list[tuple[str, bool]]:
    keys = []
    for part in (sort or "").split(","):
        bits = part.split()
        if bits:
            keys.append((bits[0], len(bits) > 1 and bits[1].lower() == "desc"))
    return keys


def _sort_value(value: int | float | str | None) -> tuple[int, float | str]:
    if value is None:
        return (0, 0.0)
    try:
        return (1, float(value))
    except (TypeError, ValueError):
        return (1, str(value).lower())


def select_rows(
    rows: list[tuple[int, Getter]],
    fields: list[str],
    value_of: ValueOf,
    filter_text: str = "",
    sort: str = "",
    offset: int = 0,
    max_rows: int = 1,
    surrounding: int = 0,
    owner_ids: list[int] | None = None,
    target_filter: str = "",
) -> list[list[RecordValue]]:
    """Answers SearchForRecords over rows. Raises FilterError on a filter it cannot read."""
    predicate = compile_filter(filter_text)
    target = compile_filter(target_filter)
    selected = [
        (rid, get)
        for rid, get in rows
        if (not owner_ids or get("ownerid") in owner_ids) and (predicate is None or predicate(get))
    ]
    # Stable sorts from the last key to the first give a multi-key sort.
    for name, descending in reversed(_parse_sort(sort)):
        selected.sort(key=lambda r, n=name: _sort_value(r[1](n)), reverse=descending)

    if target is not None:
        at = next((i for i, (_rid, get) in enumerate(selected) if target(get)), None)
        if at is None:
            return []
        window = range(max(0, at - surrounding), min(len(selected), at + surrounding + 1))
    else:
        window = range(offset, min(len(selected), offset + max(0, max_rows)))

    out = []
    for i in window:
        rid, get = selected[i]
        out.append([RecordValue.from_int(i + 1) if f.lower() == "row" else value_of(f, rid, get) for f in fields])
    return out
