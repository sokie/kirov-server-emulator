"""
Sake records that are not computed from careers: the ones a game creates with CreateRecord, such as the
Tiberium Wars and Kane's Wrath RatingMatch and RatingPlayer ratings, and fixed seed records.

A record is {field name in lower case: (Sake value type, value)}.
"""

from datetime import datetime

from sqlmodel import Session, select

from app.models.models import SakeRecord
from app.soap.models.common import RecordValue
from app.soap.sake_rows import Getter, select_rows

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


def stored_records(session: Session, game_id: int, table: str) -> list[Record]:
    """The records the game created in this table, oldest first."""
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


def create_record(session: Session, game_id: int, owner_id: int, table: str, values: list[tuple[str, str, str]]) -> int:
    """Keeps a record from CreateRecord. values is [(field, Sake value type, text)]. The caller commits."""
    stored = {}
    for name, kind, text in values:
        if kind in INT_TYPES:
            value: int | float | str = int(text or 0)
        elif kind == "floatValue":
            value = float(text or 0)
        else:
            value = text
        stored[name] = {"type": kind, "value": value}
    row = SakeRecord(
        game_id=game_id, table_id=table.lower(), owner_id=owner_id, values=stored, created_at=datetime.utcnow()
    )
    session.add(row)
    session.flush()
    return row.id


def specific_records(records: list[Record], record_ids: list[int], fields: list[str]) -> list[list[RecordValue]]:
    """Answers GetSpecificRecords: the records whose recordid is asked for, in the asked order."""
    by_id = {r["recordid"][1]: r for r in records}
    return [[field_value(by_id[rid], f) for f in fields] for rid in record_ids if rid in by_id]


def search_records(records: list[Record], fields: list[str], **params) -> list[list[RecordValue]]:
    """Answers SearchForRecords over records. Raises FilterError on a filter it cannot read."""
    rows: list[tuple[int, Getter]] = [
        (i, lambda name, r=r: r.get(name.lower(), (None, None))[1]) for i, r in enumerate(records)
    ]
    return select_rows(rows, fields, lambda f, i, _get: field_value(records[i], f), **params)
