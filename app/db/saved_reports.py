"""
Reads the match reports the server saved: Report/<game>/*.bin, each with a .json that names its csid.
"""

import glob
import json
import os
from typing import NamedTuple

from app.db.crud import extract_persona_from_ccid
from app.models.match_report import MatchReport
from app.util.logging_helper import get_logger

logger = get_logger(__name__)


class SavedReport(NamedTuple):
    save_time: str
    ccid: str  # the submitter's ccid
    report: MatchReport


def saved_reports(report_dir: str, game_id: int, game_name: str) -> dict[str, list[SavedReport]]:
    """Returns the saved reports by csid: the oldest match first, and the reports of each match oldest first."""
    by_csid: dict[str, list[SavedReport]] = {}
    for bin_path in glob.glob(os.path.join(report_dir, "*.bin")):
        json_path = bin_path[:-4] + ".json"
        if not os.path.exists(json_path):
            logger.info("%s import: %s has no .json with its csid; skipped", game_name, bin_path)
            continue
        with open(json_path, encoding="utf-8") as f:
            meta = json.load(f)
        csid = meta.get("csid", "")
        if not csid:
            continue
        with open(bin_path, "rb") as f:
            data = f.read()
        try:
            report = MatchReport.from_bytes(data, game_id=game_id)
        except Exception as e:
            logger.info("%s import: %s does not parse (%s); skipped", game_name, bin_path, e)
            continue
        by_csid.setdefault(csid, []).append(SavedReport(meta.get("save_time", ""), meta.get("ccid", ""), report))

    for reports in by_csid.values():
        reports.sort(key=lambda saved: saved.save_time)
    oldest_first = sorted(by_csid, key=lambda csid: by_csid[csid][0].save_time)
    return {csid: by_csid[csid] for csid in oldest_first}


def submitter_personas(reports: list[SavedReport]) -> dict[str, int]:
    """
    Returns the persona of each submitter by its roster GUID, which is the first GUID of its report.

    Use it for a roster GUID that the server did not mint, which has no persona in it.
    """
    personas: dict[str, int] = {}
    for saved in reports:
        persona_id = extract_persona_from_ccid(saved.ccid) if saved.ccid else None
        if persona_id and saved.report.roster_section:
            personas[str(saved.report.roster_section[0].player_id)] = persona_id
    return personas
