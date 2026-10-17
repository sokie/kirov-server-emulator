"""
Tiberium Wars and Kane's Wrath careers.

Every finished match is kept in match_history and folded onto each player's career.
"""

import copy
from datetime import datetime

from sqlmodel import Session, select

from app.db.ra3_career import rank_from_score
from app.models.cnc3_stats import ALL_ONLINE, DERIVED, UNREPORTED, Cnc3Game, SakeColumn
from app.models.models import MatchHistory, PlayerLevel, PlayerStats
from app.models.ra3_stats import RESULT_DESYNC, RESULT_DISCONNECT, RESULT_LOSS, RESULT_WIN, score_delta
from app.util.logging_helper import get_logger

logger = get_logger(__name__)


def _add(bucket: dict, key: str, value: int) -> int:
    bucket[key] = bucket.get(key, 0) + value
    return bucket[key]


def _fold_result(bucket: dict, won: bool, duration: int) -> None:
    matches = _add(bucket, "total_matches", 1)
    played = _add(bucket, "total_time_played", max(0, duration))
    bucket["avg_game_length"] = played // matches
    # Any result but a win is a loss.
    if won:
        _add(bucket, "wins", 1)
        bucket["current_loss_streak"] = 0
        streak = _add(bucket, "current_win_streak", 1)
        bucket["longest_win_streak"] = max(bucket.get("longest_win_streak", 0), streak)
    else:
        _add(bucket, "losses", 1)
        bucket["current_win_streak"] = 0
        streak = _add(bucket, "current_loss_streak", 1)
        bucket["longest_loss_streak"] = max(bucket.get("longest_loss_streak", 0), streak)
    decided = bucket.get("wins", 0) + bucket.get("losses", 0)
    bucket["win_ratio"] = round(bucket.get("wins", 0) / decided * 100, 1)


def fold_match(
    game: Cnc3Game, career: dict, mode: str, faction: str | None, result: int, duration: int, counts: dict
) -> dict:
    """Returns a copy of the career with one match folded in, into its mode and into all_online."""
    out = copy.deepcopy(career)
    won = result == RESULT_WIN
    parent = game.faction_parent.get(faction or "")
    for name in (mode, ALL_ONLINE):
        total = out.setdefault(name, {})
        buckets = [total]
        if faction:
            buckets.append(total.setdefault("factions", {}).setdefault(faction, {}))
        if parent:
            buckets.append(total.setdefault("parents", {}).setdefault(parent, {}))
        for bucket in buckets:
            _fold_result(bucket, won, duration)

        for stat in game.report_stats:
            _add(total, stat.key, int(counts.get(stat.key, 0)))
        if result == RESULT_DISCONNECT:
            _add(total, "disconnects", 1)
        elif result == RESULT_DESYNC:
            _add(total, "desyncs", 1)
    return out


def column_value(career: dict, column: SakeColumn) -> int | float:
    """The value of one PlayerStats column."""
    bucket = career.get(column.mode, {})
    if column.group:
        bucket = bucket.get(column.group, {}).get(column.faction, {})
    stat = column.stat
    if stat.fold == UNREPORTED:
        return 0
    if stat.fold != DERIVED:
        return int(bucket.get(stat.key, 0))
    if stat.key == "win_loss_ratio":
        return bucket.get("wins", 0) / max(bucket.get("losses", 0), 1)
    if stat.key == "unit_kill_death_ratio":
        return bucket.get("units_killed", 0) / max(bucket.get("units_lost", 0), 1)
    if stat.key == "avg_game_length":
        matches = bucket.get("total_matches", 0)
        return bucket.get("total_time_played", 0) / matches if matches else 0.0
    raise KeyError(stat.key)


def stats_row(session: Session, game: Cnc3Game, persona_id: int, create: bool = False) -> PlayerStats | None:
    row = session.exec(
        select(PlayerStats).where(PlayerStats.persona_id == persona_id, PlayerStats.game_id == game.game_id)
    ).first()
    if row is None and create:
        row = PlayerStats(persona_id=persona_id, game_id=game.game_id)
        session.add(row)
    return row


def level_row(session: Session, game: Cnc3Game, persona_id: int, create: bool = False) -> PlayerLevel | None:
    row = session.exec(
        select(PlayerLevel).where(PlayerLevel.persona_id == persona_id, PlayerLevel.game_id == game.game_id)
    ).first()
    if row is None and create:
        row = PlayerLevel(persona_id=persona_id, game_id=game.game_id, rank=1, score=0)
        session.add(row)
    return row


def _apply_player(session: Session, game: Cnc3Game, mode: str, duration: int, player: dict) -> None:
    persona_id = player.get("persona_id")
    if not persona_id:
        return
    result = int(player.get("result", RESULT_LOSS))
    stats = stats_row(session, game, persona_id, create=True)
    stats.stats = fold_match(
        game, stats.stats or {}, mode, player.get("faction") or None, result, duration, player.get("counts", {})
    )
    stats.total_matches_online += 1
    stats.updated_at = datetime.utcnow()

    # A disconnect or desync adds no score.
    if result in (RESULT_WIN, RESULT_LOSS):
        level = level_row(session, game, persona_id, create=True)
        level.score += score_delta(mode, result == RESULT_WIN)
        level.rank = rank_from_score(level.score)


def record_match(
    session: Session,
    game: Cnc3Game,
    csid: str,
    mode: str,
    duration: int,
    players: list[dict],
    map_name: str = "",
    match_id: str = "",
    report_md5: str = "",
    apply: bool = True,
) -> MatchHistory | None:
    """Adds the match and, with apply, folds it onto every named player. The caller commits.

    A csid that is already stored is not stored or applied again.
    """
    if session.exec(select(MatchHistory).where(MatchHistory.csid == csid)).first() is not None:
        logger.info("%s match %s is already in the history; not applied again", game.name.upper(), csid)
        return None
    match = MatchHistory(
        game_id=game.game_id,
        csid=csid,
        report_md5=report_md5,
        mode=mode,
        map_name=map_name,
        match_id=match_id,
        duration=duration,
        players=players,
    )
    session.add(match)
    if apply:
        for player in players:
            _apply_player(session, game, mode, duration, player)
    session.flush()
    return match


def rebuild_careers(session: Session, game: Cnc3Game) -> int:
    """Clears every career, score and rank of the game, then folds its whole history again, oldest first.

    ELO columns are not touched. Returns the number of matches folded.
    """
    for stats in session.exec(select(PlayerStats).where(PlayerStats.game_id == game.game_id)).all():
        stats.stats = {}
        stats.total_matches_online = 0
    for level in session.exec(select(PlayerLevel).where(PlayerLevel.game_id == game.game_id)).all():
        level.score = 0
        level.rank = 1
    session.flush()
    matches = session.exec(
        select(MatchHistory).where(MatchHistory.game_id == game.game_id).order_by(MatchHistory.id)
    ).all()
    for match in matches:
        for player in match.players:
            _apply_player(session, game, match.mode, match.duration, player)
        session.flush()
    session.commit()
    return len(matches)
