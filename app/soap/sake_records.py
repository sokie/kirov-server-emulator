"""
Sake records that are not computed from careers: the ones a game creates with CreateRecord, such as the
Tiberium Wars and Kane's Wrath RatingMatch and RatingPlayer ratings, and fixed seed records.

A record is {field name in lower case: (Sake value type, value)}.
"""

from dataclasses import dataclass
from datetime import datetime

from sqlmodel import Session, select

from app.models.models import SakeRecord
from app.soap.models.common import RecordValue
from app.soap.sake_rows import Value, select_rows

Record = dict[str, tuple[str, int | float | str]]

INT_TYPES = ("intValue", "shortValue", "byteValue", "booleanValue")


def typed_value(kind: str, value: int | float | str) -> RecordValue:
    if kind == "floatValue":
        return RecordValue.from_float(float(value))
    if kind == "shortValue":
        return RecordValue.from_short(int(value))
    if kind == "unicodeStringValue":
        return RecordValue.from_unicode_string(str(value))
    if kind in INT_TYPES:
        return RecordValue.from_int(int(value))
    return RecordValue.from_ascii_string(str(value))


def field_value(record: Record, field: str) -> RecordValue:
    kind, value = record.get(field.lower(), ("intValue", 0))
    return typed_value(kind, value)


@dataclass
class StoredRow:
    """A stored record, as a row that SearchForRecords can select."""

    record: Record

    def get(self, field: str) -> Value:
        _kind, value = self.record.get(field.lower(), (None, None))
        return value

    def value(self, field: str) -> RecordValue:
        return field_value(self.record, field)


def stored_records(session: Session, game_id: int, table: str) -> list[Record]:
    """Returns the records the game created in a table, oldest first."""
    rows = session.exec(
        select(SakeRecord)
        .where(SakeRecord.game_id == game_id, SakeRecord.table_id == table.lower())
        .order_by(SakeRecord.id)
    ).all()
    records = []
    for row in rows:
        record: Record = {name.lower(): (v["type"], v["value"]) for name, v in row.values.items()}
        record["recordid"] = ("intValue", row.id)
        record["ownerid"] = ("intValue", row.owner_id)
        # The ratings sort on rate_datetime, the time the record was created.
        record["rate_datetime"] = ("intValue", int(row.created_at.timestamp()))
        records.append(record)
    return records


def _stored_value(kind: str, text: str) -> int | float | str:
    if kind == "booleanValue":
        return 1 if text.strip().lower() in ("true", "1") else 0
    if kind in INT_TYPES:
        return int(text or 0)
    if kind == "floatValue":
        return float(text or 0)
    return text


def create_record(session: Session, game_id: int, owner_id: int, table: str, values: list[tuple[str, str, str]]) -> int:
    """
    Stores a CreateRecord record and returns its id. values is a list of (field, Sake value type, text).

    The caller commits.
    """
    stored = {name: {"type": kind, "value": _stored_value(kind, text)} for name, kind, text in values}
    row = SakeRecord(
        game_id=game_id, table_id=table.lower(), owner_id=owner_id, values=stored, created_at=datetime.utcnow()
    )
    session.add(row)
    session.flush()
    return row.id


def specific_records(records: list[Record], record_ids: list[int], fields: list[str]) -> list[list[RecordValue]]:
    """Answers GetSpecificRecords: the records with the asked record ids, in the asked order."""
    by_id = {record["recordid"][1]: record for record in records}
    return [[field_value(by_id[rid], field) for field in fields] for rid in record_ids if rid in by_id]


def search_records(records: list[Record], fields: list[str], **params) -> list[list[RecordValue]]:
    """Answers SearchForRecords over records. Raises FilterError on a filter it cannot read."""
    return select_rows([StoredRow(record) for record in records], fields, **params)
