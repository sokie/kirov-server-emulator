"""
Loads the saved Tiberium Wars and Kane's Wrath reports (Report/TW and Report/KW, *.bin and their .json) into
the match history.
"""

from sqlmodel import Session

from app.db.cnc3_career import record_match
from app.db.saved_reports import saved_reports, submitter_personas
from app.models.cnc3_stats import Cnc3Game
from app.models.game_config import FACTION_MAPS


def import_saved_reports(session: Session, game: Cnc3Game, report_dir: str) -> tuple[int, int]:
    """
    Adds one match_history row for each saved csid that is not in the history yet, and returns (added, skipped).

    The match comes from the authoritative report that names the most players: Kane's Wrath marks every report
    authoritative, and only the reports of a match that ended normally name every player. The matches are not
    folded, so run rebuild_careers afterwards.
    """
    added = skipped = 0
    for csid, reports in saved_reports(report_dir, game.game_id, game.name.upper()).items():
        personas = submitter_personas(reports)
        all_reports = [saved.report for saved in reports]
        authoritative = [report for report in all_reports if report.is_authoritative] or all_reports
        base = max(authoritative, key=lambda report: len(report.parsed_players))

        players = []
        for index, player in enumerate(base.get_player_list()):
            players.append(
                {
                    "persona_id": player.persona_id or personas.get(player.full_id),
                    "full_id": player.full_id,
                    "faction": FACTION_MAPS[game.game_id].get(player.faction, ""),
                    "result": player.result,
                    "counts": base.get_cnc3_counts(index),
                }
            )
        if len([player for player in players if player["persona_id"]]) < 2:
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
