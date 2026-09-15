"""Internal engagement scoring — never exposed in user-facing messages."""

from __future__ import annotations

from typing import Any

from engines.engagement.schema import (
    EVENT_ATTACK_PATH_CONFIRMED,
    EVENT_AUDIT_COMPLETE,
    EVENT_FIX_VERIFIED,
    EVENT_HTML_REPORT,
    EVENT_SCAN_COMPLETE,
    EVENT_SESSION_RETURN,
    SCORE_ATTACK_PATH,
    SCORE_FIRST_SUCCESS,
    SCORE_FIX_VERIFIED,
    SCORE_HTML_REPORT,
    SCORE_MULTIPLE_COMMANDS,
    SCORE_SECOND_SESSION,
    SCORE_VERIFIED_FINDING,
)
from engines.engagement.state import update_state


def _flag(state: dict[str, Any], name: str) -> bool:
    flags = state.get("score_flags") or {}
    return bool(flags.get(name))


def _set_flag(state: dict[str, Any], name: str) -> dict[str, Any]:
    flags = dict(state.get("score_flags") or {})
    flags[name] = True
    return update_state(state, score_flags=flags)


def _bump(state: dict[str, Any], amount: int) -> dict[str, Any]:
    if amount <= 0:
        return update_state(state)
    current = int(state.get("engagement_score") or 0)
    return update_state(state, engagement_score=current + amount)


def apply_event_score(
    state: dict[str, Any],
    event: str,
    context: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Return a new state with score bumps for ``event``.

    Score is internal only — callers must never put it in messages.
    One-shot bumps use ``score_flags`` so the same signal is not double-counted.
    """
    ctx = context or {}
    next_state = update_state(state)

    if event in (EVENT_AUDIT_COMPLETE, EVENT_SCAN_COMPLETE):
        if not _flag(next_state, "first_success"):
            next_state = _bump(next_state, SCORE_FIRST_SUCCESS)
            next_state = _set_flag(next_state, "first_success")
        if ctx.get("verified_finding") or ctx.get("verified_count", 0) > 0:
            if not _flag(next_state, "verified_finding"):
                next_state = _bump(next_state, SCORE_VERIFIED_FINDING)
                next_state = _set_flag(next_state, "verified_finding")

    if event == EVENT_FIX_VERIFIED:
        next_state = _bump(next_state, SCORE_FIX_VERIFIED)

    if event == EVENT_ATTACK_PATH_CONFIRMED:
        next_state = _bump(next_state, SCORE_ATTACK_PATH)

    if event == EVENT_HTML_REPORT:
        if not _flag(next_state, "html_report"):
            next_state = _bump(next_state, SCORE_HTML_REPORT)
            next_state = _set_flag(next_state, "html_report")

    if event == EVENT_SESSION_RETURN:
        sessions = int(next_state.get("sessions") or 0)
        if sessions >= 2 and not _flag(next_state, "second_session"):
            next_state = _bump(next_state, SCORE_SECOND_SESSION)
            next_state = _set_flag(next_state, "second_session")

    commands = list(next_state.get("commands_used") or [])
    cmd = ctx.get("command")
    if cmd and cmd not in commands:
        commands = [*commands, cmd]
        next_state = update_state(next_state, commands_used=commands)
    if len(commands) >= 2 and not _flag(next_state, "multiple_commands"):
        next_state = _bump(next_state, SCORE_MULTIPLE_COMMANDS)
        next_state = _set_flag(next_state, "multiple_commands")

    return next_state
