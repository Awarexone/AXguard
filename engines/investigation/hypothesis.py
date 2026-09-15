"""Hypothesis management — primary exploitability vs control/block alternatives."""

from __future__ import annotations

from typing import Any

from engines.investigation.schema import UNKNOWN, empty_hypothesis
from engines.investigation.specialists import candidate_kind


def seed_hypotheses(candidate: dict[str, Any]) -> list[dict[str, Any]]:
    kind = candidate_kind(candidate)
    h1 = empty_hypothesis(
        statement=(
            f"Attacker-influenced input can exploit {kind or 'this candidate'} "
            "along a reachable path without an effective control."
        ),
        kind="primary",
    )
    h2 = empty_hypothesis(
        statement=(
            f"A security control or safe framework pattern prevents {kind or 'this candidate'} "
            "from being exploitable (or impact is blocked)."
        ),
        kind="alternative",
    )
    return [h1, h2]


def apply_evidence_to_hypotheses(investigation: dict[str, Any]) -> None:
    """Update hypothesis status from accumulated evidence / counter-evidence."""
    hyps = investigation.get("hypotheses") or []
    if not hyps:
        return
    primary = next((h for h in hyps if h.get("kind") == "primary"), hyps[0])
    alt = next((h for h in hyps if h.get("kind") == "alternative"), None)

    support = [
        e
        for e in (investigation.get("evidence") or [])
        if e.get("supports") == "hypothesis"
    ]
    counter = list(investigation.get("counter_evidence") or [])

    primary["supporting_evidence_ids"] = [e.get("evidence_id") for e in support]
    primary["counter_evidence_ids"] = [e.get("evidence_id") for e in counter]

    if alt is not None:
        alt["supporting_evidence_ids"] = [e.get("evidence_id") for e in counter]
        alt["counter_evidence_ids"] = [e.get("evidence_id") for e in support]

    # Strong counter → refute primary, support alternative
    strong_counter = [
        e
        for e in counter
        if str(e.get("strength") or "")
        in {"DIRECT_CODE", "DATA_FLOW", "SECURITY_CONTROL", "CONTROL_FLOW"}
    ]
    if strong_counter and len(strong_counter) >= 1 and not _strong_support(support):
        primary["status"] = "REFUTED"
        primary["confidence"] = "likely"
        if alt is not None:
            alt["status"] = "SUPPORTED"
            alt["confidence"] = "likely"
        investigation["hypothesis"] = alt.get("statement") if alt else primary.get("statement")
        return

    if len(support) >= 2 and not strong_counter:
        primary["status"] = "SUPPORTED"
        primary["confidence"] = "likely"
        if alt is not None:
            alt["status"] = "REFUTED"
            alt["confidence"] = "likely"
        investigation["hypothesis"] = primary.get("statement")
        return

    if support and not counter:
        primary["status"] = "SUPPORTED"
        primary["confidence"] = "unknown"
        investigation["hypothesis"] = primary.get("statement")
        return

    if counter and support:
        primary["status"] = "UNKNOWN"
        primary["confidence"] = UNKNOWN
        if alt is not None:
            alt["status"] = "UNKNOWN"
        investigation["hypothesis"] = primary.get("statement")
        investigation.setdefault("contradictions", []).append(
            {
                "detail": "Supporting evidence and counter-evidence both present",
                "support_count": len(support),
                "counter_count": len(counter),
            }
        )
        return

    primary["status"] = "OPEN"
    primary["confidence"] = UNKNOWN
    investigation["hypothesis"] = primary.get("statement")


def _strong_support(support: list[dict[str, Any]]) -> bool:
    return any(
        str(e.get("strength") or "") in {"DIRECT_CODE", "DATA_FLOW", "CONTROL_FLOW"}
        for e in support
    )
