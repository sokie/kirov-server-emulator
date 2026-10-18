"""
Tiberium Wars and Kane's Wrath Sake tables computed from careers, answered by field name.

- PlayerStats_v5 (Tiberium Wars) and PlayerStats_v100 (Kane's Wrath): one record per persona, with every career
  column, Score and Rank.
- Levels: one record per rank, Level (from 1) and Score (the rank's first score).
- ScoringMultipliers: record 1, the Score a match adds.

RatingMatch and RatingPlayer are records the game creates; app.soap.sake_records keeps them.
"""

from sqlmodel import Session, select

from app.db.cnc3_career import column_value, level_row, stats_row
from app.models.cnc3_stats import SAKE_COLUMNS_LOWER, Cnc3Game
from app.models.models import Persona, PlayerLevel, PlayerStats
from app.models.ra3_stats import SCORING_MULTIPLIERS
from app.soap.models.common import RecordValue
from app.soap.sake_rows import CareerRow, level_rows, select_rows

LEVELS_TABLE = "levels"
SCORING_TABLE = "scoringmultipliers"


def handles(game: Cnc3Game, table: str) -> bool:
    return table.lower() in (game.sake_table.lower(), LEVELS_TABLE, SCORING_TABLE)


def _career_row(game: Cnc3Game, persona_id: int, stats: PlayerStats | None, level: PlayerLevel | None) -> CareerRow:
    return CareerRow(
        persona_id=persona_id,
        career=(stats.stats if stats else None) or {},
        level=level,
        columns=SAKE_COLUMNS_LOWER[game.game_id],
        column_value=column_value,
    )


def _career_rows(session: Session, game: Cnc3Game) -> list[CareerRow]:
    stats = {s.persona_id: s for s in session.exec(select(PlayerStats).where(PlayerStats.game_id == game.game_id))}
    levels = {lv.persona_id: lv for lv in session.exec(select(PlayerLevel).where(PlayerLevel.game_id == game.game_id))}
    persona_ids = session.exec(select(Persona.id).order_by(Persona.id)).all()
    return [_career_row(game, pid, stats.get(pid), levels.get(pid)) for pid in persona_ids]


def get_my_records(
    session: Session, game: Cnc3Game, persona_id: int, table: str, fields: list[str]
) -> list[RecordValue] | None:
    if table.lower() != game.sake_table.lower():
        return None
    row = _career_row(game, persona_id, stats_row(session, game, persona_id), level_row(session, game, persona_id))
    return [row.value(field) for field in fields]


def get_specific_records(table: str, record_ids: list[int], fields: list[str]) -> list[list[RecordValue]] | None:
    if table.lower() != SCORING_TABLE:
        return None
    if record_ids and 1 not in record_ids:
        return []
    return [[RecordValue.from_short(SCORING_MULTIPLIERS.get(field, 0)) for field in fields]]


def search(
    session: Session,
    game: Cnc3Game,
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
    if table.lower() == game.sake_table.lower():
        rows = _career_rows(session, game)
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
