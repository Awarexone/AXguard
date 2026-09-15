"""Optional local engagement config merge.

State and optional config share ``~/.axguard/engagement.json`` (or a test
override path). Network is never used for stars, metadata, or social proof —
only explicitly configured local keys are honored.
"""

from __future__ import annotations

from copy import deepcopy
from pathlib import Path
from typing import Any

from engines.engagement.schema import SUPPORT_SCORE_THRESHOLD
from engines.engagement.state import CONFIG_KEYS, load_state, resolve_state_path, update_state


def merge_config(
    state: dict[str, Any],
    overrides: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Return state with optional config overrides applied (immutable).

    Recognized keys: ``yc_messaging_enabled``, ``yc_url``, ``social_proof``,
    ``support_score_threshold``. Social proof must be a dict with factual
    keys; empty/invalid values are cleared rather than fabricated.
    """
    next_state = deepcopy(state)
    if not overrides:
        return next_state

    applied: dict[str, Any] = {}
    for key in CONFIG_KEYS:
        if key not in overrides:
            continue
        value = overrides[key]
        if key == "social_proof":
            applied[key] = _normalize_social_proof(value)
        elif key == "yc_messaging_enabled":
            applied[key] = bool(value)
        elif key == "yc_url":
            applied[key] = value if isinstance(value, str) and value.strip() else None
        elif key == "support_score_threshold":
            if value is None:
                applied[key] = None
            else:
                try:
                    applied[key] = max(0, int(value))
                except (TypeError, ValueError):
                    applied[key] = None
    if not applied:
        return next_state
    return update_state(next_state, **applied)


def _normalize_social_proof(value: Any) -> dict[str, Any] | None:
    """Accept only an explicitly configured factual dict — never invent fields."""
    if not isinstance(value, dict) or not value:
        return None
    allowed = {
        "github_stars",
        "contributors",
        "releases",
        "supported_agents",
        "projects_using",
        "community_note",
    }
    cleaned = {k: v for k, v in value.items() if k in allowed and v is not None and v != ""}
    return cleaned or None


def support_threshold(state: dict[str, Any]) -> int:
    """Effective support-ask score threshold (config override or default)."""
    override = state.get("support_score_threshold")
    if override is None:
        return SUPPORT_SCORE_THRESHOLD
    try:
        return max(0, int(override))
    except (TypeError, ValueError):
        return SUPPORT_SCORE_THRESHOLD


def load_configured_state(state_path: Path | None = None) -> dict[str, Any]:
    """Load persisted state; config keys already live in the same file."""
    return load_state(resolve_state_path(state_path))
