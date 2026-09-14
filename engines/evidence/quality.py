"""Explainable evidence-quality scoring.

Quality is derived deterministically from *what kind* of evidence it is, *where*
it came from (provenance), whether it has an **exact location**, and the
underlying static-analysis strength. There is no arbitrary LLM percentage.
"""

from __future__ import annotations

from typing import Any

from engines.evidence.schema import (
    EV_CODE_PATTERN,
    EV_CONFIGURATION,
    EV_DATA_FLOW,
    EV_DEPENDENCY,
    EV_FRAMEWORK_BEHAVIOR,
    EV_REACHABILITY,
    EV_RUNTIME_ASSUMPTION,
    EV_SINK,
    EV_SOURCE,
    PROV_CONFIGURATION,
    PROV_DEPENDENCY_METADATA,
    PROV_FRAMEWORK_KNOWLEDGE,
    PROV_SOURCE_CODE,
    PROV_STATIC_ANALYSIS,
    QUALITY_DIRECT,
    QUALITY_MODERATE,
    QUALITY_RANK,
    QUALITY_STRONG,
    QUALITY_UNKNOWN,
    QUALITY_WEAK,
    UNKNOWN_LOCATION,
)

# Adversary counter-evidence strength → base quality
_STRENGTH_QUALITY = {
    "confirmed": QUALITY_STRONG,
    "likely": QUALITY_MODERATE,
    "weak": QUALITY_WEAK,
}

# Kinds that are name-only / advisory and must never score above WEAK
_NAME_ONLY_KINDS = frozenset({"name_only_control", "ignored_comment"})

# Provenance that can support a DIRECT observation when located precisely
_DIRECT_PROVENANCE = frozenset({PROV_SOURCE_CODE, PROV_STATIC_ANALYSIS})


def has_exact_location(item: dict[str, Any]) -> bool:
    file = item.get("file")
    return bool(file) and file != UNKNOWN_LOCATION and bool(item.get("line_start"))


def score_quality(
    item: dict[str, Any],
    *,
    strength: str | None = None,
    name_only: bool = False,
    direct_observation: bool = False,
) -> str:
    """Return an explainable quality level for one evidence item.

    ``direct_observation`` marks first-hand facts (a taint path we computed, a
    sink literal we matched). ``strength`` carries adversary counter-evidence
    strength. ``name_only`` caps at WEAK (a function *named* ``sanitize`` proves
    nothing).
    """
    etype = str(item.get("type") or "")
    provenance = str(item.get("provenance") or "")
    located = has_exact_location(item)

    if name_only:
        return QUALITY_WEAK

    base = QUALITY_UNKNOWN
    if strength:
        base = _STRENGTH_QUALITY.get(str(strength).lower(), QUALITY_UNKNOWN)

    # First-hand, precisely-located source-code / static-analysis facts.
    if direct_observation and located and provenance in _DIRECT_PROVENANCE:
        base = _max(base, QUALITY_DIRECT)
    elif located and provenance in _DIRECT_PROVENANCE:
        base = _max(base, QUALITY_STRONG)

    # Configuration / dependency metadata with a concrete file → moderate+
    if provenance in {PROV_CONFIGURATION, PROV_DEPENDENCY_METADATA} and located:
        base = _max(base, QUALITY_MODERATE)
    if etype in {EV_CONFIGURATION, EV_DEPENDENCY} and located:
        base = _max(base, QUALITY_MODERATE)

    # Framework knowledge is inferential — moderate at best.
    if provenance == PROV_FRAMEWORK_KNOWLEDGE or etype == EV_FRAMEWORK_BEHAVIOR:
        base = _min(_max(base, QUALITY_MODERATE), QUALITY_MODERATE)

    # Runtime assumptions and pure pattern hits without a location stay weak.
    if etype in {EV_RUNTIME_ASSUMPTION, EV_CODE_PATTERN} and not located:
        base = _min(base, QUALITY_WEAK)

    # Anything with no location at all cannot be DIRECT/STRONG.
    if not located:
        base = _min(base, QUALITY_MODERATE if base != QUALITY_UNKNOWN else QUALITY_UNKNOWN)
        if etype not in {EV_DATA_FLOW, EV_REACHABILITY}:
            base = _min(base, QUALITY_WEAK)

    return base


def is_strong(quality: str) -> bool:
    return QUALITY_RANK.get(str(quality), 0) >= QUALITY_RANK[QUALITY_STRONG]


def _max(a: str, b: str) -> str:
    return a if QUALITY_RANK.get(a, 0) >= QUALITY_RANK.get(b, 0) else b


def _min(a: str, b: str) -> str:
    return a if QUALITY_RANK.get(a, 0) <= QUALITY_RANK.get(b, 0) else b
