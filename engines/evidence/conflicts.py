"""Detect and resolve conflicts between supporting and counter evidence.

A conflict is when the finding has real supporting exploit evidence (source →
flow → sink) *and* counter evidence for a mitigating control aspect
(authorization, input neutralization, framework, configuration). Example: local
handler lacks authorization but a global middleware provides it → ``CONFLICT``.

Resolution never invents SAFE:

* counter clearly stronger than support  → ``RESOLVED_COUNTER``
* support clearly stronger / counter weak → ``RESOLVED_SUPPORTING``
* otherwise (ambiguous or comparable)     → ``REQUIRES_REVIEW``
"""

from __future__ import annotations

from typing import Any

from engines.evidence.schema import (
    CONF_UNKNOWN,
    EV_AUTHORIZATION,
    EV_CONFIGURATION,
    EV_DATA_FLOW,
    EV_FRAMEWORK_BEHAVIOR,
    EV_REACHABILITY,
    EV_SANITIZATION,
    EV_SECURITY_CONTROL,
    EV_SINK,
    EV_SOURCE,
    EV_VALIDATION,
    QUALITY_MODERATE,
    QUALITY_RANK,
    QUALITY_STRONG,
    REL_COUNTER,
    REL_SUPPORTING,
)

RESOLUTION_REVIEW = "REQUIRES_REVIEW"
RESOLUTION_COUNTER = "RESOLVED_COUNTER"
RESOLUTION_SUPPORTING = "RESOLVED_SUPPORTING"

_SUPPORT_EXPLOIT_TYPES = {EV_SOURCE, EV_DATA_FLOW, EV_SINK, EV_REACHABILITY}

# aspect → (evidence types, kinds)
_ASPECTS: dict[str, tuple[set[str], set[str]]] = {
    "authorization": (
        {EV_AUTHORIZATION},
        {"authorization", "authentication", "tenant_isolation"},
    ),
    "input_neutralization": (
        {EV_VALIDATION, EV_SANITIZATION},
        {"parameterization", "path_jail", "sanitization", "validation", "allowlist"},
    ),
    "framework": ({EV_FRAMEWORK_BEHAVIOR}, {"framework"}),
    "configuration": ({EV_CONFIGURATION}, {"configuration"}),
}


def _max_quality(refs: list[dict[str, Any]]) -> str:
    best = CONF_UNKNOWN
    best_rank = -1
    q = "UNKNOWN"
    for r in refs:
        rank = QUALITY_RANK.get(str(r.get("quality")), 0)
        if rank > best_rank:
            best_rank = rank
            q = str(r.get("quality"))
    _ = best
    return q


def detect_conflicts(
    evidence_refs: list[dict[str, Any]],
    finding: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    """Return a list of conflict records for one finding."""
    status = str((finding or {}).get("status") or "")
    support_exploit = [
        r
        for r in evidence_refs
        if str(r.get("relationship")) == REL_SUPPORTING
        and str(r.get("type")) in _SUPPORT_EXPLOIT_TYPES
        and QUALITY_RANK.get(str(r.get("quality")), 0) >= QUALITY_RANK[QUALITY_MODERATE]
    ]
    if not support_exploit:
        return []  # nothing exploitable to conflict with
    support_ids = [str(r.get("id")) for r in support_exploit if r.get("id")]
    support_rank = max(
        QUALITY_RANK.get(str(r.get("quality")), 0) for r in support_exploit
    )

    conflicts: list[dict[str, Any]] = []
    for aspect, (types, kinds) in _ASPECTS.items():
        counters = [
            r
            for r in evidence_refs
            if str(r.get("relationship")) == REL_COUNTER
            and not r.get("name_only")
            and (str(r.get("type")) in types or str(r.get("kind")) in kinds)
        ]
        if not counters:
            continue
        counter_ids = [str(r.get("id")) for r in counters if r.get("id")]
        counter_rank = max(QUALITY_RANK.get(str(r.get("quality")), 0) for r in counters)

        resolution, reason = _resolve(
            aspect=aspect,
            support_rank=support_rank,
            counter_rank=counter_rank,
            status=status,
        )
        conflicts.append(
            {
                "aspect": aspect,
                "supporting_ids": support_ids,
                "counter_ids": counter_ids,
                "supporting_strength": _rank_name(support_rank),
                "counter_strength": _rank_name(counter_rank),
                "resolution": resolution,
                "reason": reason,
            }
        )
    return conflicts


def _resolve(
    *,
    aspect: str,
    support_rank: int,
    counter_rank: int,
    status: str,
) -> tuple[str, str]:
    strong = QUALITY_RANK[QUALITY_STRONG]
    # Adversary already resolved to FALSE_POSITIVE with a strong control.
    if status == "FALSE_POSITIVE" and counter_rank >= QUALITY_RANK[QUALITY_MODERATE]:
        return (
            RESOLUTION_COUNTER,
            f"{aspect}: adversary marked FALSE_POSITIVE with a mitigating control",
        )
    if counter_rank >= strong and support_rank < strong:
        return (
            RESOLUTION_COUNTER,
            f"{aspect}: counter evidence stronger than support — mitigated (verify manually)",
        )
    if support_rank >= strong and counter_rank < strong:
        return (
            RESOLUTION_REVIEW if aspect == "authorization" else RESOLUTION_SUPPORTING,
            f"{aspect}: exploit evidence stronger than a {_rank_name(counter_rank)} control",
        )
    # Comparable strengths, or a global vs local disagreement → needs a human.
    return (
        RESOLUTION_REVIEW,
        f"{aspect}: supporting and counter evidence are comparable — REQUIRES_REVIEW",
    )


def _rank_name(rank: int) -> str:
    for name, r in QUALITY_RANK.items():
        if r == rank:
            return name
    return "UNKNOWN"


def has_unresolved_conflict(conflicts: list[dict[str, Any]]) -> bool:
    return any(c.get("resolution") == RESOLUTION_REVIEW for c in conflicts)
