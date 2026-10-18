"""
Tiberium Wars and Kane's Wrath stats tool. Run from the repository root with the server stopped. <game> is tw or kw.

    python scripts/cnc3_stats_tool.py <game> decode <report.bin>    names every key of a saved report
    python scripts/cnc3_stats_tool.py <game> show <persona>         career, score and rank (name or id)
    python scripts/cnc3_stats_tool.py <game> history <persona>      the matches behind a career
    python scripts/cnc3_stats_tool.py <game> rebuild                folds every career of the game again from match_history
    python scripts/cnc3_stats_tool.py <game> import [dir]           adds saved reports (default Report/TW or Report/KW), then rebuilds
    python scripts/cnc3_stats_tool.py <game> catalog [out.csv]      writes the stat catalogue (default docs/<game>_stat_catalog.csv)
"""

import csv
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sqlmodel import Session, select  # noqa: E402

from app.models.cnc3_stats import (  # noqa: E402
    BY_NAME,
    GT_TO_MODE,
    LOCAL_ONLY_STATS,
    SAKE_COLUMNS,
    Cnc3Game,
    game_key_name,
    player_key_name,
)
from app.models.match_report import MatchReport  # noqa: E402

REPORT_FOLDER = {"tw": "TW", "kw": "KW"}


def decode(game: Cnc3Game, path: str) -> None:
    with open(path, "rb") as f:
        report = MatchReport.from_bytes(f.read(), game_id=game.game_id)
    gt = report.get_game_type_from_key()
    print(f"developer version {report.developer_version}, flags {report.flags}, mode {GT_TO_MODE.get(gt, gt)}")
    for key, value in sorted(report.game_section.items()):
        print(f"  game {key:4d} {game_key_name(game, key):24s} {value.value!r}")
    for i, player in enumerate(report.get_player_list()):
        print(f"player {i}: {player.full_id} persona={player.persona_id} {player.faction} result={player.result}")
        for key, value in sorted(report.player_section[i].items()):
            print(f"  {key:4d} {player_key_name(game, key, gt):28s} {value.value!r}")


def _session() -> Session:
    from sqlmodel import create_engine

    import app.db.database as database

    # The server's engine echoes every SQL statement. Creating the tables adds match_history to an older database.
    database.engine = create_engine(database.DATABASE_URL, connect_args={"check_same_thread": False})
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


def show(game: Cnc3Game, who: str) -> None:
    from app.db.cnc3_career import column_value, level_row, stats_row

    with _session() as session:
        persona = _persona(session, who)
        stats = stats_row(session, game, persona.id)
        level = level_row(session, game, persona.id)
        career = (stats.stats if stats else None) or {}
        score = level.score if level else 0
        rank = level.rank if level else 1
        print(f"{persona.name} (persona {persona.id}): score {score}, rank {rank}")
        for mode in game.modes:
            if mode not in career:
                continue
            print(f"[{mode}]")
            for column in SAKE_COLUMNS[game.game_id].values():
                if column.mode == mode:
                    value = column_value(career, column)
                    if value:
                        print(f"  {column.name:50s} {value}")


def history(game: Cnc3Game, who: str) -> None:
    from app.models.models import MatchHistory

    with _session() as session:
        persona = _persona(session, who)
        matches = session.exec(
            select(MatchHistory).where(MatchHistory.game_id == game.game_id).order_by(MatchHistory.id)
        )
        for match in matches.all():
            for player in match.players:
                if player.get("persona_id") == persona.id:
                    print(
                        f"{match.created_at:%Y-%m-%d %H:%M} {match.csid} {match.mode:10s} {match.duration:5d}s "
                        f"{player.get('faction') or '-':14s} result={player.get('result')} {match.map_name}"
                    )


def rebuild(game: Cnc3Game) -> None:
    from app.db.cnc3_career import rebuild_careers

    with _session() as session:
        print(f"folded {rebuild_careers(session, game)} matches")


def import_reports(game: Cnc3Game, report_dir: str) -> None:
    from app.db.cnc3_import import import_saved_reports

    with _session() as session:
        added, skipped = import_saved_reports(session, game, report_dir)
    print(f"added {added} matches, skipped {skipped} (already stored, or fewer than 2 named players)")
    rebuild(game)


def catalog(game: Cnc3Game, path: str) -> None:
    faction_parts = "/_".join([*game.sake_parent.values(), *game.sake_faction.values()])
    rows = []
    for stat in game.stats:
        sake_column = f"{stat.sake}_<MODE>"
        if stat.per_faction:
            sake_column += f"  (+ _{faction_parts})"
        report_key = ""
        if stat.report_base is not None:
            report_key = f"{stat.report_base + game.key_offset} + mode"
        rows.append(
            {
                "stat_id": f"0x{stat.stat_id:02X}",
                "career_key": stat.key,
                "sake_column": sake_column,
                "sake_type": stat.sake_type,
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
    if len(argv) < 2 or argv[0] not in BY_NAME:
        sys.exit(__doc__)
    game = BY_NAME[argv[0]]
    command = argv[1]
    args = argv[2:]
    if command == "decode" and args:
        decode(game, args[0])
    elif command == "show" and args:
        show(game, args[0])
    elif command == "history" and args:
        history(game, args[0])
    elif command == "rebuild":
        rebuild(game)
    elif command == "import":
        from app.util.paths import get_runtime_path

        default_dir = os.path.join(get_runtime_path(), "Report", REPORT_FOLDER[game.name])
        import_reports(game, args[0] if args else default_dir)
    elif command == "catalog":
        catalog(game, args[0] if args else os.path.join("docs", f"{game.name}_stat_catalog.csv"))
    else:
        sys.exit(__doc__)


if __name__ == "__main__":
    main(sys.argv[1:])
