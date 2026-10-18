"""
Loads the saved RA3 reports (Report/ra3/*.bin and their .json) into the match history.
"""

from sqlmodel import Session

from app.db.ra3_career import record_match
from app.db.saved_reports import saved_reports, submitter_personas
from app.models.game_config import FACTION_MAPS, GAME_ID_RA


def import_saved_reports(session: Session, report_dir: str) -> tuple[int, int]:
    """
    Adds one match_history row for each saved csid that is not in the history yet, and returns (added, skipped).

    The match comes from its first authoritative report. The matches are not folded, so run rebuild_careers
    afterwards.
    """
    added = skipped = 0
    for csid, reports in saved_reports(report_dir, GAME_ID_RA, "RA3").items():
        personas = submitter_personas(reports)
        base = next((saved.report for saved in reports if saved.report.is_authoritative), reports[0].report)

        players = []
        for index, player in enumerate(base.get_player_list()):
            players.append(
                {
                    "persona_id": player.persona_id or personas.get(player.full_id),
                    "full_id": player.full_id,
                    "faction": FACTION_MAPS[GAME_ID_RA].get(player.faction, ""),
                    "result": player.result,
                    "counts": base.get_ra3_counts(index),
                }
            )
        if len([player for player in players if player["persona_id"]]) < 2:
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
