"""
Loads the saved Tiberium Wars and Kane's Wrath reports (Report/TW and Report/KW, *.bin and their .json) into
the match history.
"""

import glob
import json
import os

from sqlmodel import Session

from app.db.cnc3_career import record_match
from app.db.crud import extract_persona_from_ccid
from app.models.cnc3_stats import Cnc3Game
from app.models.game_config import FACTION_MAPS
from app.models.match_report import MatchReport
from app.util.logging_helper import get_logger

logger = get_logger(__name__)


def _saved_reports(game: Cnc3Game, report_dir: str) -> dict[str, list[tuple[str, str, MatchReport]]]:
    """csid -> [(save time, submitter ccid, report)] for every saved report."""
    groups: dict[str, list[tuple[str, str, MatchReport]]] = {}
    for bin_path in glob.glob(os.path.join(report_dir, "*.bin")):
        json_path = bin_path[:-4] + ".json"
        if not os.path.exists(json_path):
            logger.info("%s import: %s has no .json with its csid; skipped", game.name.upper(), bin_path)
            continue
        with open(json_path, encoding="utf-8") as f:
            meta = json.load(f)
        with open(bin_path, "rb") as f:
            try:
                report = MatchReport.from_bytes(f.read(), game_id=game.game_id)
            except Exception as e:
                logger.info("%s import: %s does not parse (%s); skipped", game.name.upper(), bin_path, e)
                continue
        groups.setdefault(meta.get("csid", ""), []).append((meta.get("save_time", ""), meta.get("ccid", ""), report))
    groups.pop("", None)
    return groups


def import_saved_reports(session: Session, game: Cnc3Game, report_dir: str) -> tuple[int, int]:
    """Adds one match_history row per saved csid that is not in the history yet. Does not fold, so run rebuild_careers
    afterwards. Returns (added, skipped).

    The match comes from the authoritative report that names the most players: Kane's Wrath marks every
    report authoritative, and only the reports of a match that ended normally name everyone. A roster GUID the
    server did not mint gets the persona of the client that lists it first.
    """
    added = skipped = 0
    for csid, reports in sorted(_saved_reports(game, report_dir).items(), key=lambda item: min(r[0] for r in item[1])):
        reports.sort(key=lambda r: r[0])
        persona_of: dict[str, int] = {}
        for _time, ccid, report in reports:
            submitter = extract_persona_from_ccid(ccid) if ccid else None
            if submitter and report.roster_section:
                persona_of[str(report.roster_section[0].player_id)] = submitter
        authoritative = [r for _t, _c, r in reports if r.flags & 1] or [r for _t, _c, r in reports]
        base = max(authoritative, key=lambda r: len(r.parsed_players))

        players = []
        for i, p in enumerate(base.get_player_list()):
            players.append(
                {
                    "persona_id": p.persona_id or persona_of.get(p.full_id),
                    "full_id": p.full_id,
                    "faction": FACTION_MAPS[game.game_id].get(p.faction, ""),
                    "result": p.result,
                    "counts": base.get_cnc3_counts(i),
                }
            )
        if sum(1 for p in players if p["persona_id"]) < 2:
            skipped += 1
            continue
        match = record_match(
            session,
            game,
            csid,
            base.get_cnc3_mode(),
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
