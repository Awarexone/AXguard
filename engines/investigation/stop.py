"""Stopping policy — know when investigation is enough."""

from __future__ import annotations

from typing import Any

from engines.investigation.budget import budget_exhausted
from engines.investigation.schema import (
    OUTCOME_FALSE_POSITIVE,
    OUTCOME_LIKELY,
    OUTCOME_REQUIRES_REVIEW,
    OUTCOME_UNVERIFIED,
    OUTCOME_VERIFIED,
    STATUS_BLOCKED,
    STATUS_COMPLETED,
    STATUS_INSUFFICIENT_EVIDENCE,
    TERM_CONTROLS,
    TERM_COUNTER_EVIDENCE,
    TERM_COST,
    TERM_INSUFFICIENT,
    TERM_MEMORY_REUSE,
    TERM_PATH_BLOCKED,
    TERM_STATIC_LIMIT,
    TERM_TRUSTWORTHY,
    TERM_VERIFIED,
    UNKNOWN,
)


def evaluate_stop(investigation: dict[str, Any]) -> dict[str, Any] | None:
    """Return stop decision dict or None if investigation should continue."""
    # Memory reuse of current FP
    for note in _action_notes(investigation):
        if note == "memory_reuse_fp":
            return _stop(
                STATUS_COMPLETED,
                OUTCOME_FALSE_POSITIVE,
                TERM_MEMORY_REUSE,
                "Prior Security Memory FALSE_POSITIVE still valid",
            )

    hyps = investigation.get("hypotheses") or []
    primary = next((h for h in hyps if h.get("kind") == "primary"), None)
    alt = next((h for h in hyps if h.get("kind") == "alternative"), None)

    counter = investigation.get("counter_evidence") or []
    evidence = [
        e
        for e in (investigation.get("evidence") or [])
        if e.get("supports") == "hypothesis"
    ]
    strong_counter = [
        e
        for e in counter
        if str(e.get("strength"))
        in {"DIRECT_CODE", "DATA_FLOW", "SECURITY_CONTROL", "CONTROL_FLOW"}
    ]

    # Twin blocked impact for agent/prompt without privileged path
    for note in _action_notes(investigation):
        if note == "twin_blocks_impact" and not evidence:
            return _stop(
                STATUS_COMPLETED,
                OUTCOME_FALSE_POSITIVE,
                TERM_PATH_BLOCKED,
                "Security Twin shows no privileged impact path",
            )

    if primary and primary.get("status") == "REFUTED" and strong_counter:
        return _stop(
            STATUS_COMPLETED,
            OUTCOME_FALSE_POSITIVE,
            TERM_COUNTER_EVIDENCE,
            "Strong counter-evidence refutes primary hypothesis",
        )

    if investigation.get("controls_found") and primary and primary.get("status") == "REFUTED":
        return _stop(
            STATUS_COMPLETED,
            OUTCOME_FALSE_POSITIVE,
            TERM_CONTROLS,
            "Relevant security controls verified",
        )

    # Path blocked without supporting exploit evidence
    blocked_paths = [
        p
        for p in (investigation.get("attack_paths") or [])
        if str(p.get("status") or "").upper() == "BLOCKED"
    ]
    open_paths = [
        p
        for p in (investigation.get("attack_paths") or [])
        if str(p.get("status") or "").upper() in {"OPEN", "REACHABLE", "EXPLOITABLE"}
    ]
    if blocked_paths and not open_paths and not evidence:
        return _stop(
            STATUS_BLOCKED,
            OUTCOME_FALSE_POSITIVE,
            TERM_PATH_BLOCKED,
            "Attack path proven blocked",
        )

    if primary and primary.get("status") == "SUPPORTED" and len(evidence) >= 2 and not strong_counter:
        # Alternate path bypass elevates to VERIFIED when present
        if any(
            "alternate" in str(e.get("kind") or "").lower()
            or "alternate" in str(e.get("summary") or "").lower()
            for e in evidence
        ):
            return _stop(
                STATUS_COMPLETED,
                OUTCOME_VERIFIED,
                TERM_VERIFIED,
                "Alternate path confirms control bypass with supporting evidence",
            )
        return _stop(
            STATUS_COMPLETED,
            OUTCOME_LIKELY if len(evidence) < 3 else OUTCOME_VERIFIED,
            TERM_VERIFIED if len(evidence) >= 3 else TERM_TRUSTWORTHY,
            "Hypothesis supported by multiple evidence items without strong counter-evidence",
        )

    if budget_exhausted(investigation):
        if evidence and not strong_counter:
            return _stop(
                STATUS_INSUFFICIENT_EVIDENCE,
                OUTCOME_LIKELY if evidence else OUTCOME_UNVERIFIED,
                TERM_COST,
                "Budget exhausted with residual supporting evidence",
            )
        if strong_counter and not evidence:
            return _stop(
                STATUS_COMPLETED,
                OUTCOME_FALSE_POSITIVE,
                TERM_COST,
                "Budget exhausted; counter-evidence dominates",
            )
        if evidence and strong_counter:
            return _stop(
                STATUS_INSUFFICIENT_EVIDENCE,
                OUTCOME_REQUIRES_REVIEW,
                TERM_COST,
                "Budget exhausted with contradictory evidence",
            )
        unknowns = investigation.get("unknowns") or []
        if unknowns:
            return _stop(
                STATUS_INSUFFICIENT_EVIDENCE,
                OUTCOME_UNVERIFIED,
                TERM_INSUFFICIENT,
                "Budget exhausted; unknowns remain",
            )
        return _stop(
            STATUS_INSUFFICIENT_EVIDENCE,
            OUTCOME_UNVERIFIED,
            TERM_COST,
            "Investigation cost exceeded",
        )

    # If all questions answered and still ambiguous
    questions = investigation.get("questions") or []
    if questions and all(q.get("status") != "OPEN" for q in questions):
        if primary and primary.get("status") == "SUPPORTED" and not strong_counter:
            return _stop(
                STATUS_COMPLETED,
                OUTCOME_LIKELY,
                TERM_TRUSTWORTHY,
                "All planner questions resolved; hypothesis likely",
            )
        if alt and alt.get("status") == "SUPPORTED":
            return _stop(
                STATUS_COMPLETED,
                OUTCOME_FALSE_POSITIVE,
                TERM_COUNTER_EVIDENCE,
                "All questions resolved; alternative (control) hypothesis supported",
            )
        open_unknowns = [
            q for q in questions if q.get("status") == "UNKNOWN" or q.get("answer") == UNKNOWN
        ]
        if open_unknowns and not evidence:
            return _stop(
                STATUS_INSUFFICIENT_EVIDENCE,
                OUTCOME_UNVERIFIED,
                TERM_STATIC_LIMIT,
                "Remaining uncertainty cannot be resolved statically",
            )
        if evidence and strong_counter:
            return _stop(
                STATUS_COMPLETED,
                OUTCOME_REQUIRES_REVIEW,
                TERM_TRUSTWORTHY,
                "Contradictory evidence after full question pass",
            )

    return None


def _stop(
    status: str,
    decision: str,
    termination_reason: str,
    reasoning: str,
) -> dict[str, Any]:
    return {
        "status": status,
        "decision": decision,
        "termination_reason": termination_reason,
        "reasoning_summary": reasoning,
        "next_action": "STOP",
    }


def _action_notes(investigation: dict[str, Any]) -> list[str]:
    notes: list[str] = []
    for a in investigation.get("investigations_performed") or []:
        result = a.get("result") or {}
        n = result.get("notes")
        if n:
            notes.append(str(n))
    return notes


def map_decision_to_confidence(decision: str | None) -> str:
    if decision == OUTCOME_VERIFIED:
        return "confirmed"
    if decision == OUTCOME_LIKELY:
        return "likely"
    if decision == OUTCOME_FALSE_POSITIVE:
        return "likely"
    if decision == OUTCOME_REQUIRES_REVIEW:
        return "unknown"
    return "unknown"
