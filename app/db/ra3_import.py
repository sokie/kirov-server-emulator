"""
Loads the saved RA3 reports (Report/ra3/*.bin and their .json) into the match history.
"""

import glob
import json
import os

from sqlmodel import Session

from app.db.crud import extract_persona_from_ccid
from app.db.ra3_career import record_match
from app.models.game_config import FACTION_MAPS, GAME_ID_RA
from app.models.match_report import MatchReport
from app.util.logging_helper import get_logger

logger = get_logger(__name__)


def _saved_reports(report_dir: str) -> dict[str, list[tuple[str, str, MatchReport]]]:
    """csid -> [(save time, submitter ccid, report)] for every saved report."""
    groups: dict[str, list[tuple[str, str, MatchReport]]] = {}
    for bin_path in glob.glob(os.path.join(report_dir, "*.bin")):
        json_path = bin_path[:-4] + ".json"
        if not os.path.exists(json_path):
            logger.info("RA3 import: %s has no .json with its csid; skipped", bin_path)
            continue
        with open(json_path, encoding="utf-8") as f:
            meta = json.load(f)
        with open(bin_path, "rb") as f:
            try:
                report = MatchReport.from_bytes(f.read(), game_id=GAME_ID_RA)
            except Exception as e:
                logger.info("RA3 import: %s does not parse (%s); skipped", bin_path, e)
                continue
        groups.setdefault(meta.get("csid", ""), []).append((meta.get("save_time", ""), meta.get("ccid", ""), report))
    groups.pop("", None)
    return groups


def import_saved_reports(session: Session, report_dir: str) -> tuple[int, int]:
    """Adds one match_history row per saved csid that is not in the history yet, from its first authoritative
    report. Does not fold, so run rebuild_careers afterwards. Returns (added, skipped).

    A roster GUID the server did not mint gets the persona of the client that lists it first.
    """
    added = skipped = 0
    for csid, reports in sorted(_saved_reports(report_dir).items(), key=lambda item: min(r[0] for r in item[1])):
        reports.sort(key=lambda r: r[0])
        persona_of: dict[str, int] = {}
        for _time, ccid, report in reports:
            submitter = extract_persona_from_ccid(ccid) if ccid else None
            if submitter and report.roster_section:
                persona_of[str(report.roster_section[0].player_id)] = submitter
        base = next((r for _t, _c, r in reports if r.flags & 1), reports[0][2])

        players = []
        for i, p in enumerate(base.get_player_list()):
            players.append(
                {
                    "persona_id": p.persona_id or persona_of.get(p.full_id),
                    "full_id": p.full_id,
                    "faction": FACTION_MAPS[GAME_ID_RA].get(p.faction, ""),
                    "result": p.result,
                    "counts": base.get_ra3_counts(i),
                }
            )
        if sum(1 for p in players if p["persona_id"]) < 2:
            skipped += 1
            continue
        match = record_match(
            session,
            csid,
            base.get_ra3_mode(),
            base.get_duration(),
            players,
            map_name=base.get_map_path(),
            match_id=base.get_match_id(),
            report_md5=base.checksum.hex(),
            apply=False,
        )
        if match is None:
            skipped += 1
        else:
            added += 1
    session.commit()
    return added, skipped
