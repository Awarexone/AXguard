"""Suggest a specific contribution — cooldown, dismissal, no spam."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4

from engines.contributors import milestones as mile
from engines.contributors.privacy import (
    dismiss_type,
    is_type_dismissed,
    prompts_allowed,
    set_never_prompts,
)
from engines.contributors.quality import filter_strong
from engines.contributors.schema import (
    FORBIDDEN_CONTRIBUTE_PHRASES,
    INVITE_COOLDOWN_SEC,
    MAX_INVITES_PER_SESSION,
    TYPE_LABELS,
)
from engines.contributors.signals import OpportunitySignal, signals_from_context


@dataclass(frozen=True)
class ContributionInvite:
    id: str
    contribution_type: str
    difficulty: str
    reason: str
    what: str
    control: str
    quality_score: float
    message: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "contribution_type": self.contribution_type,
            "difficulty": self.difficulty,
            "reason": self.reason,
            "what": self.what,
            "control": self.control,
            "quality_score": self.quality_score,
            "message": self.message,
        }


def _parse_iso(value: str | None) -> datetime | None:
    if not value or not isinstance(value, str):
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _clean(text: str) -> str:
    lowered = text.lower()
    for phrase in FORBIDDEN_CONTRIBUTE_PHRASES:
        if phrase in lowered:
            raise ValueError(f"forbidden contribute phrase: {phrase}")
    return text


def _in_cooldown(state: dict[str, Any]) -> bool:
    last = _parse_iso(state.get("last_invite_at"))
    if last is None:
        return False
    age = (_now() - last).total_seconds()
    return age < INVITE_COOLDOWN_SEC


def _session_cap_reached(state: dict[str, Any], session_id: str | None) -> bool:
    if session_id and state.get("session_id") == session_id:
        return int(state.get("session_invite_count") or 0) >= MAX_INVITES_PER_SESSION
    return False


def _build_invite(signal: OpportunitySignal, quality_score: float) -> ContributionInvite:
    label = TYPE_LABELS.get(signal.contribution_type, signal.contribution_type)
    reason = signal.reason
    what = (
        f"Prepare a local {label} package (fixture/test/docs stubs + commit/PR draft). "
        "Nothing is pushed."
    )
    control = (
        "You can dismiss with: not now · never prompts · don't suggest this type. "
        "Push/PR only happen if you do them yourself."
    )
    message = _clean(
        "\n".join(
            [
                f"Suggested contribution: {label} ({signal.difficulty})",
                "",
                f"Why: {reason}",
                f"What: {what}",
                f"Control: {control}",
                "",
                "Run: axguard contribute prepare",
            ]
        )
    )
    return ContributionInvite(
        id=f"inv_{uuid4().hex[:10]}",
        contribution_type=signal.contribution_type,
        difficulty=signal.difficulty,
        reason=reason,
        what=what,
        control=control,
        quality_score=quality_score,
        message=message,
    )


def suggest(
    context: dict[str, Any] | None = None,
    *,
    privacy_path: Path | None = None,
    state_path: Path | None = None,
    session_id: str | None = None,
    force: bool = False,
) -> ContributionInvite | None:
    """Return at most one strong invite per meaningful session (unless force)."""
    if not force and not prompts_allowed(privacy_path):
        return None

    state = mile.load_state(state_path)
    if not force:
        if _in_cooldown(state):
            return None
        if _session_cap_reached(state, session_id):
            return None

    strong = filter_strong(signals_from_context(context), context)
    chosen: OpportunitySignal | None = None
    quality_score = 0.0
    for sig, qa in strong:
        if is_type_dismissed(sig.contribution_type, path=privacy_path):
            continue
        chosen = sig
        quality_score = qa.score
        break
    if chosen is None:
        return None

    invite = _build_invite(chosen, quality_score)

    # Persist cooldown / session accounting
    sid = session_id or state.get("session_id") or uuid4().hex[:12]
    count = int(state.get("session_invite_count") or 0)
    if state.get("session_id") == sid:
        count += 1
    else:
        count = 1
    state["session_id"] = sid
    state["session_invite_count"] = count
    state["last_invite_at"] = _now().replace(microsecond=0).isoformat()
    state["last_invite_type"] = chosen.contribution_type
    mile.save_state(state, state_path)

    # Soft engagement event (best-effort)
    try:
        from engines.engagement.engine import record_event
        from engines.engagement.schema import EVENT_CONTRIBUTION_SUGGESTED

        record_event(
            EVENT_CONTRIBUTION_SUGGESTED,
            {
                **(context or {}),
                "count_meaningful": False,
                "contribution_type": chosen.contribution_type,
                "invite_id": invite.id,
            },
        )
    except Exception:  # noqa: BLE001
        pass

    return invite


def dismiss(
    mode: str,
    *,
    contribution_type: str | None = None,
    privacy_path: Path | None = None,
    state_path: Path | None = None,
) -> dict[str, Any]:
    """Dismiss invites: not_now | never_prompts | type.

    Never spam after dismiss.
    """
    normalized = (mode or "").strip().lower().replace("-", "_").replace(" ", "_")
    result: dict[str, Any] = {"mode": normalized, "ok": True}

    state = mile.load_state(state_path)
    dismissed = list(state.get("dismissed_invites") or [])
    dismissed.append(
        {
            "at": _now().replace(microsecond=0).isoformat(),
            "mode": normalized,
            "contribution_type": contribution_type,
        }
    )
    state["dismissed_invites"] = dismissed[-50:]

    if normalized in {"not_now", "notnow", "later"}:
        # Start cooldown immediately
        state["last_invite_at"] = _now().replace(microsecond=0).isoformat()
        state["session_invite_count"] = MAX_INVITES_PER_SESSION
        result["effect"] = "cooldown"
    elif normalized in {"never_prompts", "never", "no_prompts"}:
        set_never_prompts(True, path=privacy_path)
        result["effect"] = "never_prompts"
    elif normalized in {"type", "dont_suggest_type", "don't_suggest_this_type", "dismiss_type"}:
        if not contribution_type:
            # Fall back to last invite type
            contribution_type = state.get("last_invite_type")
        if contribution_type:
            dismiss_type(contribution_type, path=privacy_path)
            result["effect"] = "type_dismissed"
            result["contribution_type"] = contribution_type
        else:
            result["ok"] = False
            result["error"] = "contribution_type required"
    else:
        result["ok"] = False
        result["error"] = "unknown dismiss mode (use not_now | never_prompts | type)"

    mile.save_state(state, state_path)

    try:
        from engines.engagement.engine import record_event
        from engines.engagement.schema import EVENT_CONTRIBUTION_DISMISSED

        record_event(
            EVENT_CONTRIBUTION_DISMISSED,
            {"count_meaningful": False, "dismiss_mode": normalized},
        )
    except Exception:  # noqa: BLE001
        pass

    return result
