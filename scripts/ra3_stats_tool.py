"""
Red Alert 3 stats tool. Run from the repository root with the server stopped.

    python scripts/ra3_stats_tool.py decode <report.bin>    names every key of a saved report
    python scripts/ra3_stats_tool.py show <persona>         career, score and rank (name or id)
    python scripts/ra3_stats_tool.py history <persona>      the matches behind a career
    python scripts/ra3_stats_tool.py rebuild                folds every career again from match_history
    python scripts/ra3_stats_tool.py import [dir]           adds saved reports (default Report/ra3) to match_history, then rebuilds
    python scripts/ra3_stats_tool.py catalog [out.csv]      writes the stat catalogue (default docs/ra3_stat_catalog.csv)
"""

import csv
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sqlmodel import Session, select  # noqa: E402

from app.models.game_config import GAME_ID_RA  # noqa: E402
from app.models.match_report import MatchReport  # noqa: E402
from app.models.ra3_stats import (  # noqa: E402
    GT_TO_MODE,
    LOCAL_ONLY_STATS,
    MODES,
    SAKE_COLUMNS,
    STATS,
    game_key_name,
    player_key_name,
)


def decode(path: str) -> None:
    with open(path, "rb") as f:
        report = MatchReport.from_bytes(f.read(), game_id=GAME_ID_RA)
    gt = report.get_game_type_from_key()
    print(f"developer version {report.developer_version}, flags {report.flags}, mode {GT_TO_MODE.get(gt, gt)}")
    for key, value in sorted(report.game_section.items()):
        print(f"  game {key:4d} {game_key_name(key):20s} {value.value!r}")
    for i, player in enumerate(report.get_player_list()):
        print(f"player {i}: {player.full_id} persona={player.persona_id} {player.faction} result={player.result}")
        for key, value in sorted(report.player_section[i].items()):
            print(f"  {key:4d} {player_key_name(key, gt):24s} {value.value!r}")


def _session() -> Session:
    import app.db.database as database

    # Creating the tables adds match_history to an older database.
    database.create_db_and_tables()
    return Session(database.engine)


def _persona(session: Session, who: str):
    from app.models.models import Persona

    if who.isdigit():
        stmt = select(Persona).where(Persona.id == int(who))
    else:
        stmt = select(Persona).where(Persona.name == who)
    persona = session.exec(stmt).first()
    if persona is None:
        sys.exit(f"no persona {who!r}")
    return persona


def show(who: str) -> None:
    from app.db.ra3_career import column_value
    from app.models.models import PlayerLevel, PlayerStats

    with _session() as session:
        persona = _persona(session, who)
        stats = session.exec(
            select(PlayerStats).where(PlayerStats.persona_id == persona.id, PlayerStats.game_id == GAME_ID_RA)
        ).first()
        level = session.exec(
            select(PlayerLevel).where(PlayerLevel.persona_id == persona.id, PlayerLevel.game_id == GAME_ID_RA)
        ).first()
        career = (stats.stats if stats else None) or {}
        score = level.score if level else 0
        rank = level.rank if level else 1
        print(f"{persona.name} (persona {persona.id}): score {score}, rank {rank}")
        for mode in MODES:
            if mode not in career:
                continue
            print(f"[{mode}]")
            for column in SAKE_COLUMNS.values():
                if column.mode == mode:
                    value = column_value(career, column)
                    if value:
                        print(f"  {column.name:45s} {value}")
            for stat in STATS:
                if stat.sake is None and career[mode].get(stat.key):
                    print(f"  {stat.key:45s} {career[mode][stat.key]} (not read by the game)")


def history(who: str) -> None:
    from app.models.models import MatchHistory

    with _session() as session:
        persona = _persona(session, who)
        matches = session.exec(select(MatchHistory).where(MatchHistory.game_id == GAME_ID_RA).order_by(MatchHistory.id))
        for match in matches.all():
            for player in match.players:
                if player.get("persona_id") == persona.id:
                    print(
                        f"{match.created_at:%Y-%m-%d %H:%M} {match.csid} {match.mode:10s} {match.duration:5d}s "
                        f"{player.get('faction') or '-':7s} result={player.get('result')} {match.map_name}"
                    )


def rebuild() -> None:
    from app.db.ra3_career import rebuild_careers

    with _session() as session:
        print(f"folded {rebuild_careers(session)} matches")


def import_reports(report_dir: str) -> None:
    from app.db.ra3_import import import_saved_reports

    with _session() as session:
        added, skipped = import_saved_reports(session, report_dir)
    print(f"added {added} matches, skipped {skipped} (already stored, or fewer than 2 named players)")
    rebuild()


def catalog(path: str) -> None:
    rows = []
    for stat in STATS:
        sake_column = ""
        if stat.sake:
            sake_column = f"{stat.sake}_<MODE>"
            if stat.per_faction:
                sake_column += "  (+ _ALLIED/_SOVIET/_JAPAN)"
        report_key = ""
        if stat.report_base is not None:
            report_key = f"{stat.report_base} + mode"
        rows.append(
            {
                "stat_id": f"0x{stat.stat_id:02X}",
                "career_key": stat.key,
                "sake_column": sake_column,
                "sake_type": stat.sake_type if stat.sake else "",
                "fold": stat.fold,
                "report_key": report_key,
                "label": stat.label,
            }
        )
    for stat_id, label in LOCAL_ONLY_STATS.items():
        rows.append(
            {
                "stat_id": f"0x{stat_id:02X}",
                "career_key": "",
                "sake_column": "",
                "sake_type": "",
                "fold": "client only",
                "report_key": "",
                "label": label,
            }
        )
    rows.sort(key=lambda r: int(r["stat_id"], 16))
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0]), lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)
    print(f"wrote {len(rows)} stats to {path}")


def main(argv: list[str]) -> None:
    if not argv:
        sys.exit(__doc__)
    command = argv[0]
    args = argv[1:]
    if command == "decode" and args:
        decode(args[0])
    elif command == "show" and args:
        show(args[0])
    elif command == "history" and args:
        history(args[0])
    elif command == "rebuild":
        rebuild()
    elif command == "import":
        from app.util.paths import get_runtime_path

        import_reports(args[0] if args else os.path.join(get_runtime_path(), "Report", "ra3"))
    elif command == "catalog":
        catalog(args[0] if args else os.path.join("docs", "ra3_stat_catalog.csv"))
    else:
        sys.exit(__doc__)


if __name__ == "__main__":
    main(sys.argv[1:])
