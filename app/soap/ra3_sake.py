"""
Red Alert 3 Sake tables, answered by field name.

- PlayerStats_v5: one record per persona, with the 190 career columns, Score and Rank.
- Levels: one record per rank, Level (from 1) and Score (the rank's first score).
- ScoringMultipliers: record 1, the Score a match adds.
"""

from sqlmodel import Session, select

from app.db.ra3_career import column_value
from app.models.game_config import GAME_ID_RA
from app.models.models import Persona, PlayerLevel, PlayerStats
from app.models.ra3_stats import SAKE_COLUMNS_LOWER, SCORING_MULTIPLIERS
from app.soap.models.common import RecordValue
from app.soap.sake_rows import CareerRow, level_rows, select_rows

PLAYER_STATS_TABLE = "playerstats_v5"
LEVELS_TABLE = "levels"
SCORING_TABLE = "scoringmultipliers"
TABLES = (PLAYER_STATS_TABLE, LEVELS_TABLE, SCORING_TABLE)


def handles(table: str) -> bool:
    return table.lower() in TABLES


def _career_row(persona_id: int, stats: PlayerStats | None, level: PlayerLevel | None) -> CareerRow:
    return CareerRow(
        persona_id=persona_id,
        career=(stats.stats if stats else None) or {},
        level=level,
        columns=SAKE_COLUMNS_LOWER,
        column_value=column_value,
    )


def _career_rows(session: Session) -> list[CareerRow]:
    stats = {s.persona_id: s for s in session.exec(select(PlayerStats).where(PlayerStats.game_id == GAME_ID_RA))}
    levels = {lv.persona_id: lv for lv in session.exec(select(PlayerLevel).where(PlayerLevel.game_id == GAME_ID_RA))}
    persona_ids = session.exec(select(Persona.id).order_by(Persona.id)).all()
    return [_career_row(pid, stats.get(pid), levels.get(pid)) for pid in persona_ids]


def get_my_records(session: Session, persona_id: int, table: str, fields: list[str]) -> list[RecordValue] | None:
    if table.lower() != PLAYER_STATS_TABLE:
        return None
    stats = session.exec(
        select(PlayerStats).where(PlayerStats.persona_id == persona_id, PlayerStats.game_id == GAME_ID_RA)
    ).first()
    level = session.exec(
        select(PlayerLevel).where(PlayerLevel.persona_id == persona_id, PlayerLevel.game_id == GAME_ID_RA)
    ).first()
    row = _career_row(persona_id, stats, level)
    return [row.value(field) for field in fields]


def get_specific_records(table: str, record_ids: list[int], fields: list[str]) -> list[list[RecordValue]] | None:
    if table.lower() != SCORING_TABLE:
        return None
    if record_ids and 1 not in record_ids:
        return []
    return [[RecordValue.from_short(SCORING_MULTIPLIERS.get(field, 0)) for field in fields]]


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
    if table.lower() == PLAYER_STATS_TABLE:
        rows = _career_rows(session)
    elif table.lower() == LEVELS_TABLE:
        rows = level_rows()
    else:
        return None
    return select_rows(
        rows,
        fields,
        filter_text=filter_text,
        sort=sort,
        offset=offset,
        max_rows=max_rows,
        surrounding=surrounding,
        owner_ids=owner_ids,
        target_filter=target_filter,
    )
