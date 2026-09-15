"""Evidence & Confidence engine (Phase 5) schema constants and factories.

This module never invents evidence. Missing locations are marked ``UNKNOWN``
explicitly rather than guessed, and secret values are never emitted (see
``engines.dataflow.schema.ensure_no_secret_values``).
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

EVIDENCE_VERSION = "1.0.0"
TOOL_NAME = "axguard"

# ---------------------------------------------------------------------------
# Evidence types
# ---------------------------------------------------------------------------
EV_SOURCE = "SOURCE"
EV_SINK = "SINK"
EV_DATA_FLOW = "DATA_FLOW"
EV_CONTROL_FLOW = "CONTROL_FLOW"
EV_SECURITY_CONTROL = "SECURITY_CONTROL"
EV_VALIDATION = "VALIDATION"
EV_SANITIZATION = "SANITIZATION"
EV_AUTHORIZATION = "AUTHORIZATION"
EV_CONFIGURATION = "CONFIGURATION"
EV_FRAMEWORK_BEHAVIOR = "FRAMEWORK_BEHAVIOR"
EV_DEPENDENCY = "DEPENDENCY"
EV_REACHABILITY = "REACHABILITY"
EV_TRUST_BOUNDARY = "TRUST_BOUNDARY"
EV_CALL_GRAPH = "CALL_GRAPH"
EV_CODE_PATTERN = "CODE_PATTERN"
EV_RUNTIME_ASSUMPTION = "RUNTIME_ASSUMPTION"
EV_COUNTER_EVIDENCE = "COUNTER_EVIDENCE"

EVIDENCE_TYPES = frozenset(
    {
        EV_SOURCE,
        EV_SINK,
        EV_DATA_FLOW,
        EV_CONTROL_FLOW,
        EV_SECURITY_CONTROL,
        EV_VALIDATION,
        EV_SANITIZATION,
        EV_AUTHORIZATION,
        EV_CONFIGURATION,
        EV_FRAMEWORK_BEHAVIOR,
        EV_DEPENDENCY,
        EV_REACHABILITY,
        EV_TRUST_BOUNDARY,
        EV_CALL_GRAPH,
        EV_CODE_PATTERN,
        EV_RUNTIME_ASSUMPTION,
        EV_COUNTER_EVIDENCE,
    }
)

# Critical evidence types — an UNKNOWN here must pull down overall confidence
# and must not be hidden by another HIGH component.
CRITICAL_EVIDENCE_TYPES = frozenset(
    {EV_SOURCE, EV_SINK, EV_DATA_FLOW, EV_REACHABILITY}
)

# ---------------------------------------------------------------------------
# Relationship
# ---------------------------------------------------------------------------
REL_SUPPORTING = "SUPPORTING_EVIDENCE"
REL_COUNTER = "COUNTER_EVIDENCE"
RELATIONSHIPS = frozenset({REL_SUPPORTING, REL_COUNTER})

# ---------------------------------------------------------------------------
# Quality levels (explainable — never an arbitrary LLM percentage)
# ---------------------------------------------------------------------------
QUALITY_DIRECT = "DIRECT"
QUALITY_STRONG = "STRONG"
QUALITY_MODERATE = "MODERATE"
QUALITY_WEAK = "WEAK"
QUALITY_UNKNOWN = "UNKNOWN"
QUALITY_LEVELS = (
    QUALITY_UNKNOWN,
    QUALITY_WEAK,
    QUALITY_MODERATE,
    QUALITY_STRONG,
    QUALITY_DIRECT,
)
QUALITY_RANK = {name: i for i, name in enumerate(QUALITY_LEVELS)}

# ---------------------------------------------------------------------------
# Confidence levels
# ---------------------------------------------------------------------------
CONF_UNKNOWN = "UNKNOWN"
CONF_LOW = "LOW"
CONF_MEDIUM = "MEDIUM"
CONF_HIGH = "HIGH"
CONF_VERY_HIGH = "VERY_HIGH"
CONFIDENCE_LEVELS = (
    CONF_UNKNOWN,
    CONF_LOW,
    CONF_MEDIUM,
    CONF_HIGH,
    CONF_VERY_HIGH,
)
CONFIDENCE_RANK = {name: i for i, name in enumerate(CONFIDENCE_LEVELS)}

# ---------------------------------------------------------------------------
# Provenance (where the evidence physically came from)
# ---------------------------------------------------------------------------
PROV_SOURCE_CODE = "source_code"
PROV_CONFIGURATION = "configuration"
PROV_DEPENDENCY_METADATA = "dependency_metadata"
PROV_FRAMEWORK_KNOWLEDGE = "framework_knowledge"
PROV_SECURITY_RULE = "security_rule"
PROV_STATIC_ANALYSIS = "static_analysis"
PROV_AXGUARD_ANALYSIS = "axguard_analysis"
PROV_LLM_REASONING = "llm_reasoning"
PROVENANCES = frozenset(
    {
        PROV_SOURCE_CODE,
        PROV_CONFIGURATION,
        PROV_DEPENDENCY_METADATA,
        PROV_FRAMEWORK_KNOWLEDGE,
        PROV_SECURITY_RULE,
        PROV_STATIC_ANALYSIS,
        PROV_AXGUARD_ANALYSIS,
        PROV_LLM_REASONING,
    }
)

# ---------------------------------------------------------------------------
# Legacy adversary/judge confidence → new confidence levels
# ---------------------------------------------------------------------------
LEGACY_CONFIDENCE_MAP: dict[str, str] = {
    "confirmed": CONF_HIGH,
    "likely": CONF_MEDIUM,
    "unknown": CONF_UNKNOWN,
}

# Adversary final status → confidence anchor (base level before adjustment)
STATUS_CONFIDENCE_ANCHOR: dict[str, str] = {
    "CONFIRMED": CONF_HIGH,
    "LIKELY": CONF_MEDIUM,
    "REQUIRES_REVIEW": CONF_LOW,
    "UNVERIFIED": CONF_UNKNOWN,
    "FALSE_POSITIVE": CONF_LOW,
}

# Special marker for an unknown / unresolved location — never guessed.
UNKNOWN_LOCATION = "UNKNOWN"


def map_legacy_confidence(value: str | None) -> str:
    """Map ``confirmed|likely|unknown`` into the new confidence vocabulary."""
    return LEGACY_CONFIDENCE_MAP.get(str(value or "").lower(), CONF_UNKNOWN)


def compute_content_hash(
    *,
    type: str,
    file: str | None,
    line_start: int | None,
    line_end: int | None,
    symbol: str | None,
    description: str,
    snippet: str | None = None,
) -> str:
    """Stable content hash used for freshness / staleness detection.

    Any change to the underlying located content (snippet, description, lines)
    changes the hash, so a stored item can be invalidated when the source moves.
    """
    payload = json.dumps(
        {
            "type": str(type or ""),
            "file": str(file or ""),
            "line_start": int(line_start or 0),
            "line_end": int(line_end or 0),
            "symbol": str(symbol or ""),
            "description": str(description or ""),
            "snippet": str(snippet or ""),
        },
        sort_keys=True,
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]


def dedupe_key(item: dict[str, Any]) -> tuple[str, str, int, str, str]:
    """Dedupe key: (type, file, line, symbol, description)."""
    return (
        str(item.get("type") or ""),
        str(item.get("file") or UNKNOWN_LOCATION),
        int(item.get("line_start") or 0),
        str(item.get("symbol") or ""),
        str(item.get("description") or ""),
    )


def evidence_item(
    *,
    type: str,
    description: str,
    relationship: str = REL_SUPPORTING,
    file: str | None = None,
    line_start: int | None = None,
    line_end: int | None = None,
    symbol: str | None = None,
    quality: str = QUALITY_UNKNOWN,
    confidence: str = CONF_UNKNOWN,
    provenance: str = PROV_AXGUARD_ANALYSIS,
    source: str = "evidence",
    snippet: str | None = None,
) -> dict[str, Any]:
    """Build a single evidence item.

    Unknown locations are recorded explicitly (``file`` = ``"UNKNOWN"``) rather
    than fabricated. ``content_hash`` is derived from the located content.
    """
    etype = str(type)
    if etype not in EVIDENCE_TYPES:
        etype = EV_CODE_PATTERN
    rel = relationship if relationship in RELATIONSHIPS else REL_SUPPORTING
    loc_file = file if file else UNKNOWN_LOCATION
    item: dict[str, Any] = {
        "id": "",  # assigned by the store
        "type": etype,
        "file": loc_file,
        "line_start": int(line_start) if line_start else None,
        "line_end": int(line_end) if line_end else (int(line_start) if line_start else None),
        "symbol": symbol or None,
        "description": str(description or ""),
        "relationship": rel,
        "quality": quality if quality in QUALITY_RANK else QUALITY_UNKNOWN,
        "confidence": confidence if confidence in CONFIDENCE_RANK else CONF_UNKNOWN,
        "provenance": provenance if provenance in PROVENANCES else PROV_AXGUARD_ANALYSIS,
        "source": str(source or "evidence"),
    }
    if snippet:
        item["snippet"] = str(snippet)
    item["content_hash"] = compute_content_hash(
        type=item["type"],
        file=None if loc_file == UNKNOWN_LOCATION else loc_file,
        line_start=item["line_start"],
        line_end=item["line_end"],
        symbol=item["symbol"],
        description=item["description"],
        snippet=item.get("snippet"),
    )
    return item


def empty_evidence(target: Path) -> dict[str, Any]:
    root = str(Path(target).resolve())
    return {
        "schema_version": EVIDENCE_VERSION,
        "tool": TOOL_NAME,
        "target": root,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "findings_evidence": [],
        "evidence_store": {},
        "summary": {
            "finding_count": 0,
            "evidence_count": 0,
            "unique_evidence_count": 0,
            "reused_evidence_count": 0,
            "conflict_count": 0,
            "unknown_count": 0,
            "by_confidence": {level: 0 for level in CONFIDENCE_LEVELS},
        },
        "meta": {},
    }
