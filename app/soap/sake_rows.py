"""
Row selection for the Sake tables that are answered by field name.
"""

from collections.abc import Callable
from dataclasses import dataclass
from typing import Protocol

from app.models.game_config import SAGE_LEVEL_THRESHOLDS
from app.models.models import PlayerLevel
from app.soap.models.common import RecordValue
from app.soap.sake_filter import compile_filter

Value = int | float | str | None


class SakeRow(Protocol):
    """One record of a Sake table."""

    def get(self, field: str) -> Value:
        """Returns the raw value of a field, or None if the record has no such field."""
        ...

    def value(self, field: str) -> RecordValue:
        """Returns the value of a field as a Sake value."""
        ...


@dataclass
class LevelRow:
    """One Levels record: Level, from 1, and Score, the first score of that rank."""

    level: int
    score: int

    def get(self, field: str) -> Value:
        return {"level": self.level, "score": self.score, "recordid": self.level}.get(field.lower())

    def value(self, field: str) -> RecordValue:
        return RecordValue.from_int(int(self.get(field) or 0))


def level_rows() -> list[LevelRow]:
    return [LevelRow(level, score) for level, score in enumerate(SAGE_LEVEL_THRESHOLDS, start=1)]


@dataclass
class CareerRow:
    """The PlayerStats record of one persona: its career columns, Score and Rank."""

    persona_id: int
    career: dict
    level: PlayerLevel | None
    columns: dict  # the game's Sake columns by lower-case name
    column_value: Callable  # column_value(career, column) of the game's career module

    def get(self, field: str) -> Value:
        name = field.lower()
        if name in ("ownerid", "recordid"):
            return self.persona_id
        if name == "score":
            return self.level.score if self.level else 0
        if name == "rank":
            return self.level.rank if self.level else 1
        column = self.columns.get(name)
        if column is None:
            return None
        return self.column_value(self.career, column)

    def value(self, field: str) -> RecordValue:
        raw = self.get(field)
        column = self.columns.get(field.lower())
        if column is not None and column.stat.sake_type == "float":
            return RecordValue.from_float(float(raw or 0))
        return RecordValue.from_int(int(raw or 0))


def _parse_sort(sort: str) -> list[tuple[str, bool]]:
    """Returns the fields of a Sake sort, such as "score desc, recordid", with True for descending."""
    keys = []
    for part in (sort or "").split(","):
        words = part.split()
        if words:
            keys.append((words[0], len(words) > 1 and words[1].lower() == "desc"))
    return keys


def _sort_key(value: Value) -> tuple[int, float | str]:
    """Sorts empty values first, then numbers, then text."""
    if value is None:
        return (0, 0.0)
    try:
        return (1, float(value))
    except (TypeError, ValueError):
        return (2, str(value).lower())


def _sort_by(rows: list[SakeRow], field: str, descending: bool) -> None:
    rows.sort(key=lambda row: _sort_key(row.get(field)), reverse=descending)


def select_rows(
    rows: list[SakeRow],
    fields: list[str],
    filter_text: str = "",
    sort: str = "",
    offset: int = 0,
    max_rows: int = 1,
    surrounding: int = 0,
    owner_ids: list[int] | None = None,
    target_filter: str = "",
) -> list[list[RecordValue]]:
    """Answers SearchForRecords over rows. Raises FilterError on a filter it cannot read."""
    matches_filter = compile_filter(filter_text)
    is_target = compile_filter(target_filter)

    selected = []
    for row in rows:
        if owner_ids and row.get("ownerid") not in owner_ids:
            continue
        if matches_filter is not None and not matches_filter(row.get):
            continue
        selected.append(row)

    # Stable sorts from the last key to the first give a multi-key sort.
    for field, descending in reversed(_parse_sort(sort)):
        _sort_by(selected, field, descending)

    if is_target is not None:
        target = next((index for index, row in enumerate(selected) if is_target(row.get)), None)
        if target is None:
            return []
        window = range(max(0, target - surrounding), min(len(selected), target + surrounding + 1))
    else:
        window = range(offset, min(len(selected), offset + max(0, max_rows)))

    answer = []
    for index in window:
        row = selected[index]
        values = []
        for field in fields:
            if field.lower() == "row":
                # The record's position in the sorted result, from 1.
                values.append(RecordValue.from_int(index + 1))
            else:
                values.append(row.value(field))
        answer.append(values)
    return answer
