"""Local privacy prefs for contribution learning — no network, opt-in only.

State lives at ``~/.axguard/privacy.json``. Learning data defaults off.
"""

from __future__ import annotations

import json
import shutil
from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from engines.contributors.schema import (
    DEFAULT_PRIVACY_CONFIG,
    EXPORT_EXCLUDED_FIELDS,
    EXPORT_INCLUDED_FIELDS,
    PRIVACY_FILENAME,
)

DEFAULT_PRIVACY_PATH = Path.home() / ".axguard" / PRIVACY_FILENAME
LEARNING_DATA_DIRNAME = "contribute-learning"


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def resolve_privacy_path(path: Path | None = None) -> Path:
    if path is not None:
        return Path(path)
    return DEFAULT_PRIVACY_PATH


def default_privacy() -> dict[str, Any]:
    base = deepcopy(DEFAULT_PRIVACY_CONFIG)
    now = _utc_now_iso()
    base["created_at"] = now
    base["updated_at"] = now
    return base


def load_privacy(path: Path | None = None) -> dict[str, Any]:
    dest = resolve_privacy_path(path)
    if not dest.is_file():
        return default_privacy()
    try:
        raw = json.loads(dest.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, UnicodeDecodeError):
        return default_privacy()
    if not isinstance(raw, dict):
        return default_privacy()
    base = default_privacy()
    merged = {**base, **raw}
    contributions = dict(base.get("contributions") or {})
    if isinstance(raw.get("contributions"), dict):
        contributions.update(raw["contributions"])
    merged["contributions"] = contributions
    learning = deepcopy(base.get("learning") or {})
    if isinstance(raw.get("learning"), dict):
        learning.update(raw["learning"])
        cd = learning.get("contribution_data")
        if isinstance(cd, dict):
            base_cd = dict((base.get("learning") or {}).get("contribution_data") or {})
            base_cd.update(cd)
            learning["contribution_data"] = base_cd
    merged["learning"] = learning
    if not isinstance(merged.get("dismissed_types"), list):
        merged["dismissed_types"] = []
    return merged


def save_privacy(state: dict[str, Any], path: Path | None = None) -> Path:
    dest = resolve_privacy_path(path)
    dest.parent.mkdir(parents=True, exist_ok=True)
    payload = deepcopy(state)
    payload["updated_at"] = _utc_now_iso()
    tmp = dest.with_suffix(dest.suffix + ".tmp")
    tmp.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    tmp.replace(dest)
    return dest


def learning_data_dir(privacy_path: Path | None = None) -> Path:
    """Directory for local learning packs (never uploaded by this module)."""
    root = resolve_privacy_path(privacy_path).parent
    return root / LEARNING_DATA_DIRNAME


def field_explanations() -> dict[str, Any]:
    """Clear explanation of what local export may include / never includes."""
    return {
        "included": list(EXPORT_INCLUDED_FIELDS),
        "excluded": list(EXPORT_EXCLUDED_FIELDS),
        "notes": [
            "Learning and contribution packaging are opt-in.",
            "Nothing is sent over the network by AXGuard learning defaults.",
            "Secrets and private repo identity are scrubbed before any pack is written.",
            "GitHub push/PR is never automatic — prepare locally only.",
        ],
    }


def status(path: Path | None = None) -> dict[str, Any]:
    state = load_privacy(path)
    contrib = state.get("contributions") or {}
    learning = state.get("learning") or {}
    cd = learning.get("contribution_data") or {}
    return {
        "privacy_path": str(resolve_privacy_path(path)),
        "contribute_opt_in": bool(state.get("contribute_opt_in")),
        "learning_opt_in": bool(state.get("learning_opt_in")),
        "never_prompts": bool(state.get("never_prompts")),
        "dismissed_types": list(state.get("dismissed_types") or []),
        "contributions": {
            "enabled": bool(contrib.get("enabled", True)),
            "prompts": bool(contrib.get("prompts", True)),
            "auto_prepare": bool(contrib.get("auto_prepare", False)),
            "auto_push": bool(contrib.get("auto_push", False)),
            "auto_pr": bool(contrib.get("auto_pr", False)),
            "learning": bool(contrib.get("learning", False)),
        },
        "learning": {
            "contribution_data": {
                "enabled": bool(cd.get("enabled", False)),
            }
        },
        "fields": field_explanations(),
        "learning_data_dir": str(learning_data_dir(path)),
        "learning_data_present": learning_data_dir(path).is_dir(),
    }


def show(path: Path | None = None) -> dict[str, Any]:
    """Alias for status with explicit field documentation."""
    return status(path)


def opt_in(
    *,
    contribute: bool = True,
    learning: bool = False,
    path: Path | None = None,
) -> dict[str, Any]:
    """Explicit opt-in. Learning stays off unless ``learning=True``."""
    state = load_privacy(path)
    state["contribute_opt_in"] = bool(contribute)
    if learning:
        state["learning_opt_in"] = True
        contrib = dict(state.get("contributions") or {})
        contrib["learning"] = True
        state["contributions"] = contrib
        learning_cfg = deepcopy(state.get("learning") or {})
        cd = dict(learning_cfg.get("contribution_data") or {})
        cd["enabled"] = True
        learning_cfg["contribution_data"] = cd
        state["learning"] = learning_cfg
    save_privacy(state, path)
    return status(path)


def opt_out(*, path: Path | None = None, clear_learning: bool = False) -> dict[str, Any]:
    state = load_privacy(path)
    state["contribute_opt_in"] = False
    state["learning_opt_in"] = False
    contrib = dict(state.get("contributions") or {})
    contrib["learning"] = False
    state["contributions"] = contrib
    learning_cfg = deepcopy(state.get("learning") or {})
    cd = dict(learning_cfg.get("contribution_data") or {})
    cd["enabled"] = False
    learning_cfg["contribution_data"] = cd
    state["learning"] = learning_cfg
    save_privacy(state, path)
    if clear_learning:
        delete_learning_data(path)
    return status(path)


def export_privacy_bundle(dest: Path, *, path: Path | None = None) -> Path:
    """Write a local JSON export of prefs + field explanations (no secrets)."""
    dest = Path(dest)
    dest.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "exported_at": _utc_now_iso(),
        "status": status(path),
        "note": "Local export only. AXGuard does not upload this file.",
    }
    dest.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return dest


def delete_learning_data(path: Path | None = None) -> bool:
    """Delete local learning data directory. Returns True if something was removed."""
    data_dir = learning_data_dir(path)
    if data_dir.is_dir():
        shutil.rmtree(data_dir)
        return True
    return False


def reset(*, path: Path | None = None) -> dict[str, Any]:
    """Reset privacy prefs to defaults and clear local learning data."""
    delete_learning_data(path)
    dest = resolve_privacy_path(path)
    if dest.is_file():
        dest.unlink()
    save_privacy(default_privacy(), path)
    return status(path)


def is_contribute_opted_in(path: Path | None = None) -> bool:
    return bool(load_privacy(path).get("contribute_opt_in"))


def is_learning_opted_in(path: Path | None = None) -> bool:
    state = load_privacy(path)
    if not state.get("learning_opt_in"):
        return False
    contrib = state.get("contributions") or {}
    if not contrib.get("learning"):
        return False
    learning = state.get("learning") or {}
    cd = learning.get("contribution_data") or {}
    return bool(cd.get("enabled"))


def prompts_allowed(path: Path | None = None) -> bool:
    state = load_privacy(path)
    if state.get("never_prompts"):
        return False
    contrib = state.get("contributions") or {}
    if not contrib.get("enabled", True):
        return False
    return bool(contrib.get("prompts", True))


def set_never_prompts(value: bool = True, *, path: Path | None = None) -> dict[str, Any]:
    state = load_privacy(path)
    state["never_prompts"] = bool(value)
    if value:
        contrib = dict(state.get("contributions") or {})
        contrib["prompts"] = False
        state["contributions"] = contrib
    save_privacy(state, path)
    return status(path)


def dismiss_type(contribution_type: str, *, path: Path | None = None) -> dict[str, Any]:
    state = load_privacy(path)
    dismissed = list(state.get("dismissed_types") or [])
    if contribution_type and contribution_type not in dismissed:
        dismissed.append(contribution_type)
    state["dismissed_types"] = dismissed
    save_privacy(state, path)
    return status(path)


def is_type_dismissed(contribution_type: str, *, path: Path | None = None) -> bool:
    dismissed = load_privacy(path).get("dismissed_types") or []
    return contribution_type in dismissed
