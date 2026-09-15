"""Local engagement state persistence — no network calls ever."""

from __future__ import annotations

import json
from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from engines.engagement.schema import STATE_NEW_USER

DEFAULT_STATE_PATH = Path.home() / ".axguard" / "engagement.json"
PROJECT_STATE_PATH = Path(".findings") / "axguard" / "engagement-state.json"

# Keys that may appear in the same JSON file as optional config overrides.
CONFIG_KEYS = frozenset(
    {
        "yc_messaging_enabled",
        "yc_url",
        "social_proof",
        "support_score_threshold",
    }
)


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def default_state() -> dict[str, Any]:
    """Return a fresh engagement state dict (immutable caller contract)."""
    now = _utc_now_iso()
    return {
        "state": STATE_NEW_USER,
        "engagement_score": 0,  # INTERNAL — never show to users
        "first_run_shown": False,
        "sessions": 0,
        "last_session_at": None,
        "meaningful_sessions": 0,
        "commands_used": [],
        "milestones_seen": [],
        "last_message_ids": [],
        "last_support_ask_at": None,
        "support_dismiss_count": 0,
        "promo_disabled": False,
        "yc_messaging_enabled": False,
        "yc_url": None,
        "social_proof": None,  # only if explicitly configured — never fabricate
        "support_score_threshold": None,  # None → use schema default
        "score_flags": {},  # one-shot bump markers (internal)
        "created_at": now,
        "updated_at": now,
    }


def update_state(current: dict[str, Any], **changes: Any) -> dict[str, Any]:
    """Return a new state dict with ``changes`` applied (does not mutate).

    First argument is named ``current`` so callers can pass ``state=...`` to
    update the journey-state field without a keyword clash.
    """
    next_state = deepcopy(current)
    for key, value in changes.items():
        if key == "commands_used" and isinstance(value, (set, frozenset)):
            next_state[key] = sorted(value)
        elif key == "commands_used" and isinstance(value, list):
            next_state[key] = list(dict.fromkeys(value))
        else:
            next_state[key] = deepcopy(value) if isinstance(value, (dict, list)) else value
    next_state["updated_at"] = _utc_now_iso()
    return next_state


def add_command(current: dict[str, Any], command: str) -> dict[str, Any]:
    """Return state with ``command`` recorded in commands_used (deduped)."""
    if not command:
        return deepcopy(current)
    used = list(current.get("commands_used") or [])
    if command in used:
        return deepcopy(current)
    return update_state(current, commands_used=[*used, command])


def add_milestone(current: dict[str, Any], milestone: str) -> dict[str, Any]:
    """Return state with milestone appended if new."""
    seen = list(current.get("milestones_seen") or [])
    if milestone in seen:
        return deepcopy(current)
    return update_state(current, milestones_seen=[*seen, milestone])


def remember_message(current: dict[str, Any], message_id: str, *, keep: int = 20) -> dict[str, Any]:
    """Return state with recent message id recorded (capped list)."""
    ids = [message_id, *[i for i in (current.get("last_message_ids") or []) if i != message_id]]
    return update_state(current, last_message_ids=ids[:keep])


def public_snapshot(state: dict[str, Any]) -> dict[str, Any]:
    """State view safe for renderers — strips internal engagement_score."""
    snap = deepcopy(state)
    snap.pop("engagement_score", None)
    snap.pop("score_flags", None)
    return snap


def resolve_state_path(state_path: Path | None = None) -> Path:
    """Prefer ~/.axguard/engagement.json for cross-session persistence."""
    if state_path is not None:
        return Path(state_path)
    return DEFAULT_STATE_PATH


def load_state(state_path: Path | None = None) -> dict[str, Any]:
    """Load state from disk; return defaults if missing or corrupt."""
    path = resolve_state_path(state_path)
    if not path.is_file():
        return default_state()
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, UnicodeDecodeError):
        return default_state()
    if not isinstance(raw, dict):
        return default_state()
    base = default_state()
    merged = {**base, **{k: v for k, v in raw.items() if k in base or k in CONFIG_KEYS}}
    # Normalize list fields
    if isinstance(merged.get("commands_used"), set):
        merged["commands_used"] = sorted(merged["commands_used"])
    elif not isinstance(merged.get("commands_used"), list):
        merged["commands_used"] = []
    for key in ("milestones_seen", "last_message_ids"):
        if not isinstance(merged.get(key), list):
            merged[key] = []
    if merged.get("social_proof") is not None and not isinstance(merged["social_proof"], dict):
        merged["social_proof"] = None
    if not isinstance(merged.get("score_flags"), dict):
        merged["score_flags"] = {}
    return merged


def save_state(state: dict[str, Any], state_path: Path | None = None) -> Path:
    """Persist state atomically. Never performs network I/O."""
    path = resolve_state_path(state_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = deepcopy(state)
    payload["updated_at"] = _utc_now_iso()
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    tmp.replace(path)
    return path
