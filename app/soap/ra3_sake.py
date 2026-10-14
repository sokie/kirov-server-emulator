"""
Red Alert 3 Sake tables, answered by field name.

- PlayerStats_v5: one record per persona, with the 190 career columns, Score and Rank.
- Levels: one record per rank, Level (1-based) and Score (the rank's first score).
- ScoringMultipliers: record 1, the Score a match adds.
"""

from collections.abc import Callable

from sqlmodel import Session, select

from app.db.ra3_career import column_value
from app.models.game_config import GAME_ID_RA, SAGE_LEVEL_THRESHOLDS
from app.models.models import Persona, PlayerLevel, PlayerStats
from app.models.ra3_stats import SAKE_COLUMNS_LOWER, SCORING_MULTIPLIERS
from app.soap.models.common import RecordValue
from app.soap.sake_filter import compile_filter

PLAYER_STATS_TABLE = "playerstats_v5"
LEVELS_TABLE = "levels"
SCORING_TABLE = "scoringmultipliers"
TABLES = (PLAYER_STATS_TABLE, LEVELS_TABLE, SCORING_TABLE)

Getter = Callable[[str], int | float | None]


def handles(table: str) -> bool:
    return table.lower() in TABLES


def _record_value(field: str, value: int | float | None) -> RecordValue:
    column = SAKE_COLUMNS_LOWER.get(field.lower())
    if column is not None and column.stat.sake_type == "float":
        return RecordValue.from_float(float(value or 0))
    return RecordValue.from_int(int(value or 0))


def _player_getter(persona_id: int, stats: PlayerStats | None, level: PlayerLevel | None) -> Getter:
    career = (stats.stats if stats else None) or {}

    def get(name: str) -> int | float | None:
        low = name.lower()
        if low in ("ownerid", "recordid"):
            return persona_id
        if low == "score":
            return level.score if level else 0
        if low == "rank":
            return level.rank if level else 1
        column = SAKE_COLUMNS_LOWER.get(low)
        if column is not None:
            return column_value(career, column)
        return None

    return get


def _player_rows(session: Session) -> list[tuple[int, Getter]]:
    stats = {s.persona_id: s for s in session.exec(select(PlayerStats).where(PlayerStats.game_id == GAME_ID_RA))}
    levels = {lv.persona_id: lv for lv in session.exec(select(PlayerLevel).where(PlayerLevel.game_id == GAME_ID_RA))}
    personas = session.exec(select(Persona.id).order_by(Persona.id)).all()
    return [(pid, _player_getter(pid, stats.get(pid), levels.get(pid))) for pid in personas]


def _level_rows() -> list[tuple[int, Getter]]:
    rows = []
    for i, score in enumerate(SAGE_LEVEL_THRESHOLDS):
        level = i + 1
        values = {"level": level, "score": score, "recordid": level}
        rows.append((level, lambda name, v=values: v.get(name.lower())))
    return rows


def get_my_records(session: Session, persona_id: int, table: str, fields: list[str]) -> list[RecordValue] | None:
    if table.lower() != PLAYER_STATS_TABLE:
        return None
    stats = session.exec(
        select(PlayerStats).where(PlayerStats.persona_id == persona_id, PlayerStats.game_id == GAME_ID_RA)
    ).first()
    level = session.exec(
        select(PlayerLevel).where(PlayerLevel.persona_id == persona_id, PlayerLevel.game_id == GAME_ID_RA)
    ).first()
    get = _player_getter(persona_id, stats, level)
    return [_record_value(f, get(f)) for f in fields]


def get_specific_records(table: str, record_ids: list[int], fields: list[str]) -> list[list[RecordValue]] | None:
    if table.lower() != SCORING_TABLE:
        return None
    if record_ids and 1 not in record_ids:
        return []
    return [[RecordValue.from_short(SCORING_MULTIPLIERS.get(f, 0)) for f in fields]]


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


def search(
    session: Session,
    table: str,
    fields: list[str],
    filter_text: str = "",
    sort: str = "",
    offset: int = 0,
    max_rows: int = 1,
    surrounding: int = 0,
    owner_ids: list[int] | None = None,
    target_filter: str = "",
) -> list[list[RecordValue]] | None:
    """Answers SearchForRecords. Raises FilterError on a filter it cannot read."""
    low = table.lower()
    if low == PLAYER_STATS_TABLE:
        rows = _player_rows(session)
    elif low == LEVELS_TABLE:
        rows = _level_rows()
    else:
        return None

    predicate = compile_filter(filter_text)
    target = compile_filter(target_filter)
    selected = [
        (rid, get) for rid, get in rows if (not owner_ids or rid in owner_ids) and (predicate is None or predicate(get))
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
        _rid, get = selected[i]
        out.append([RecordValue.from_int(i + 1) if f.lower() == "row" else _record_value(f, get(f)) for f in fields])
    return out
