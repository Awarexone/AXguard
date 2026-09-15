"""Local contribution milestones — no streaks, pressure, or rankings."""

from __future__ import annotations

import json
from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from engines.contributors.schema import CONTRIBUTE_STATE_FILENAME

DEFAULT_STATE_PATH = Path.home() / ".axguard" / CONTRIBUTE_STATE_FILENAME

# Quiet, factual milestones only
MILESTONE_FIRST_REGRESSION = "first_regression_contribution"
MILESTONE_FIRST_RULE = "first_rule_contribution"
MILESTONE_FIRST_FP_FIX = "first_fp_fix_contribution"
MILESTONE_FIRST_DOCS = "first_docs_contribution"
MILESTONE_FIRST_ATTACK_PATH = "first_attack_path_contribution"
MILESTONE_FIRST_PREPARE = "first_local_prepare"

MILESTONE_LABELS: dict[str, str] = {
    MILESTONE_FIRST_REGRESSION: "First regression contribution prepared locally",
    MILESTONE_FIRST_RULE: "First rule contribution prepared locally",
    MILESTONE_FIRST_FP_FIX: "First false-positive fix prepared locally",
    MILESTONE_FIRST_DOCS: "First documentation contribution prepared locally",
    MILESTONE_FIRST_ATTACK_PATH: "First attack-path pattern prepared locally",
    MILESTONE_FIRST_PREPARE: "First local contribution package prepared",
}

_TYPE_TO_MILESTONE: dict[str, str] = {
    "REGRESSION_TEST": MILESTONE_FIRST_REGRESSION,
    "TEST": MILESTONE_FIRST_REGRESSION,
    "SECURITY_RULE": MILESTONE_FIRST_RULE,
    "RULE": MILESTONE_FIRST_RULE,
    "FALSE_POSITIVE_FIX": MILESTONE_FIRST_FP_FIX,
    "DOCUMENTATION": MILESTONE_FIRST_DOCS,
    "DOCS": MILESTONE_FIRST_DOCS,
    "ATTACK_PATH_PATTERN": MILESTONE_FIRST_ATTACK_PATH,
}


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def resolve_state_path(path: Path | None = None) -> Path:
    if path is not None:
        return Path(path)
    return DEFAULT_STATE_PATH


def default_state() -> dict[str, Any]:
    now = _utc_now_iso()
    return {
        "milestones": [],
        "last_invite_at": None,
        "last_invite_type": None,
        "session_invite_count": 0,
        "session_id": None,
        "dismissed_invites": [],
        "prepared_ids": [],
        "created_at": now,
        "updated_at": now,
    }


def load_state(path: Path | None = None) -> dict[str, Any]:
    dest = resolve_state_path(path)
    if not dest.is_file():
        return default_state()
    try:
        raw = json.loads(dest.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, UnicodeDecodeError):
        return default_state()
    if not isinstance(raw, dict):
        return default_state()
    base = default_state()
    merged = {**base, **raw}
    for key in ("milestones", "dismissed_invites", "prepared_ids"):
        if not isinstance(merged.get(key), list):
            merged[key] = []
    return merged


def save_state(state: dict[str, Any], path: Path | None = None) -> Path:
    dest = resolve_state_path(path)
    dest.parent.mkdir(parents=True, exist_ok=True)
    payload = deepcopy(state)
    payload["updated_at"] = _utc_now_iso()
    tmp = dest.with_suffix(dest.suffix + ".tmp")
    tmp.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    tmp.replace(dest)
    return dest


def list_milestones(path: Path | None = None) -> list[dict[str, str]]:
    state = load_state(path)
    out: list[dict[str, str]] = []
    for mid in state.get("milestones") or []:
        out.append(
            {
                "id": str(mid),
                "label": MILESTONE_LABELS.get(str(mid), str(mid)),
            }
        )
    return out


def record_milestone(milestone_id: str, *, path: Path | None = None) -> bool:
    """Record a local milestone once. Returns True if newly added."""
    if milestone_id not in MILESTONE_LABELS:
        return False
    state = load_state(path)
    seen = list(state.get("milestones") or [])
    if milestone_id in seen:
        return False
    seen.append(milestone_id)
    state["milestones"] = seen
    save_state(state, path)
    return True


def record_prepare_milestone(contribution_type: str, *, path: Path | None = None) -> list[str]:
    """Record prepare-related milestones. No streaks or rankings."""
    added: list[str] = []
    if record_milestone(MILESTONE_FIRST_PREPARE, path=path):
        added.append(MILESTONE_FIRST_PREPARE)
    typed = _TYPE_TO_MILESTONE.get(contribution_type)
    if typed and record_milestone(typed, path=path):
        added.append(typed)
    return added


def clear_state(path: Path | None = None) -> None:
    dest = resolve_state_path(path)
    if dest.is_file():
        dest.unlink()
