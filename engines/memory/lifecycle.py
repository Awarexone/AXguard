"""Finding lifecycle transitions and validity consistency."""

from __future__ import annotations

from typing import Any

from engines.memory.schema import (
    LIFE_CONFIRMED,
    LIFE_FALSE_POSITIVE,
    LIFE_LIKELY,
    LIFE_NEW,
    LIFE_RECONFIRMED,
    LIFE_REGRESSED,
    LIFE_RESOLVED,
    LIFE_UNVERIFIED,
    VALIDITY_CURRENT,
    VALIDITY_HISTORICAL,
    VALIDITY_INVALIDATED,
    VALIDITY_RECONFIRMED,
    VALIDITY_REGRESSED,
    VALIDITY_RESOLVED,
    VALIDITY_SUPERSEDED,
    VALIDITY_UNKNOWN,
)

# Statuses that mean "present / open" in adversary or scan vocabulary
_OPEN = frozenset(
    {
        LIFE_CONFIRMED,
        LIFE_LIKELY,
        LIFE_UNVERIFIED,
        LIFE_RECONFIRMED,
        LIFE_REGRESSED,
        LIFE_NEW,
        "CONFIRMED",
        "LIKELY",
        "UNVERIFIED",
        "REQUIRES_REVIEW",
        "VERIFIED",
        "NEW",
    }
)

_FP = frozenset({LIFE_FALSE_POSITIVE, "FALSE_POSITIVE"})
_RESOLVED = frozenset({LIFE_RESOLVED, "RESOLVED", "FIXED", "ABSENT", "GONE"})
_ABSENT_MARKERS = frozenset({"ABSENT", "FIXED", "GONE", "MISSING", None, ""})


def _norm_status(status: Any) -> str:
    if status is None:
        return "ABSENT"
    s = str(status).strip().upper()
    return s or "ABSENT"


def transition_finding(
    prev_status: str | None,
    new_status: str | None,
) -> tuple[str, str]:
    """Return ``(lifecycle_state, validity)`` for a status transition.

    Rules (prefer explicit over invented):
    - first seen → NEW / CURRENT
    - FALSE_POSITIVE → CONFIRMED (or other open) → REGRESSED / REGRESSED
    - CONFIRMED (open) → absent/fixed → RESOLVED / RESOLVED
    - RESOLVED → open again → REGRESSED / REGRESSED
    - same open status → RECONFIRMED / RECONFIRMED when previously confirmed
    - otherwise map into lifecycle vocabulary with UNKNOWN validity if unclear
    """
    prev = _norm_status(prev_status)
    new = _norm_status(new_status)

    if prev in _ABSENT_MARKERS or prev == "UNKNOWN":
        if new in _ABSENT_MARKERS:
            return LIFE_UNVERIFIED, VALIDITY_UNKNOWN
        if new in _FP:
            return LIFE_FALSE_POSITIVE, VALIDITY_CURRENT
        if new in {"CONFIRMED", LIFE_CONFIRMED, "VERIFIED"}:
            return LIFE_NEW, VALIDITY_CURRENT
        if new in {"LIKELY", LIFE_LIKELY}:
            return LIFE_NEW, VALIDITY_CURRENT
        if new in {"UNVERIFIED", LIFE_UNVERIFIED, "REQUIRES_REVIEW"}:
            return LIFE_NEW, VALIDITY_CURRENT
        return LIFE_NEW, VALIDITY_CURRENT

    # FP → open = regression (rejected finding came back)
    if prev in _FP and new in _OPEN:
        return LIFE_REGRESSED, VALIDITY_REGRESSED

    # open → FP
    if prev in _OPEN and new in _FP:
        return LIFE_FALSE_POSITIVE, VALIDITY_CURRENT

    # open → resolved/absent
    if prev in _OPEN and (new in _RESOLVED or new in _ABSENT_MARKERS):
        return LIFE_RESOLVED, VALIDITY_RESOLVED

    # resolved → open again
    if prev in _RESOLVED and new in _OPEN:
        return LIFE_REGRESSED, VALIDITY_REGRESSED

    # FP stays FP
    if prev in _FP and new in _FP:
        return LIFE_FALSE_POSITIVE, VALIDITY_CURRENT

    # resolved stays
    if prev in _RESOLVED and (new in _RESOLVED or new in _ABSENT_MARKERS):
        return LIFE_RESOLVED, VALIDITY_RESOLVED

    # reconfirm same open class
    if prev in {"CONFIRMED", LIFE_CONFIRMED, "VERIFIED"} and new in {
        "CONFIRMED",
        LIFE_CONFIRMED,
        "VERIFIED",
    }:
        return LIFE_RECONFIRMED, VALIDITY_RECONFIRMED

    if prev == new:
        mapped = _map_to_lifecycle(new)
        return mapped, VALIDITY_CURRENT

    # status class change while still open
    if prev in _OPEN and new in _OPEN:
        return _map_to_lifecycle(new), VALIDITY_CURRENT

    return _map_to_lifecycle(new), VALIDITY_UNKNOWN


def _map_to_lifecycle(status: str) -> str:
    s = _norm_status(status)
    mapping = {
        "NEW": LIFE_NEW,
        "CONFIRMED": LIFE_CONFIRMED,
        "VERIFIED": LIFE_CONFIRMED,
        "LIKELY": LIFE_LIKELY,
        "UNVERIFIED": LIFE_UNVERIFIED,
        "REQUIRES_REVIEW": LIFE_UNVERIFIED,
        "FALSE_POSITIVE": LIFE_FALSE_POSITIVE,
        "RESOLVED": LIFE_RESOLVED,
        "FIXED": LIFE_RESOLVED,
        "ABSENT": LIFE_RESOLVED,
        "REGRESSED": LIFE_REGRESSED,
        "RECONFIRMED": LIFE_RECONFIRMED,
    }
    return mapping.get(s, LIFE_UNVERIFIED)


def assert_consistency(item: dict[str, Any]) -> list[str]:
    """Return consistency warnings (does not mutate). Prefer UNKNOWN over lies.

    - CURRENT finding cannot cite INVALIDATED evidence as current proof
    - HISTORICAL items must not be presented as CURRENT
    """
    warnings: list[str] = []
    validity = str(item.get("validity") or VALIDITY_UNKNOWN)
    item_type = str(item.get("item_type") or "")

    if validity == VALIDITY_HISTORICAL and item.get("presented_as") == VALIDITY_CURRENT:
        warnings.append("historical_item_presented_as_current")

    if item_type == "FINDING" and validity == VALIDITY_CURRENT:
        for ev in item.get("evidence_refs") or item.get("evidence") or []:
            if isinstance(ev, dict) and ev.get("validity") == VALIDITY_INVALIDATED:
                warnings.append("current_finding_with_invalidated_evidence")
            elif isinstance(ev, str) and ev.startswith("INVALIDATED:"):
                warnings.append("current_finding_with_invalidated_evidence")

    if validity == VALIDITY_SUPERSEDED and item.get("is_latest") is True:
        warnings.append("superseded_marked_as_latest")

    return warnings


def demote_to_historical(item: dict[str, Any]) -> dict[str, Any]:
    """Return a new item dict marked HISTORICAL (immutable update)."""
    out = dict(item)
    out["validity"] = VALIDITY_HISTORICAL
    out["is_latest"] = False
    return out
