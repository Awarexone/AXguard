"""Evidence helpers and hierarchy weights for Hunter → Judge."""

from __future__ import annotations

from typing import Any

from engines.dataflow.schema import ensure_no_secret_values, evidence as _df_evidence
from engines.verify.schema import (
    EV_ALLOWLIST,
    EV_COMMENT_OR_FIXTURE,
    EV_CONTRADICTION,
    EV_CONTROL,
    EV_MISSING_LINK,
    EV_PARAMETERIZATION,
    EV_PATTERN_ONLY,
    EV_SANITIZATION,
    EV_SINK_MATCH,
    EV_SOURCE_MATCH,
    EV_TAINT_PATH,
    EV_VALIDATION,
)

# Higher weight = stronger signal toward verification (negative used for FP signals)
EVIDENCE_WEIGHTS: dict[str, int] = {
    EV_TAINT_PATH: 40,
    EV_SOURCE_MATCH: 20,
    EV_SINK_MATCH: 15,
    EV_CONTROL: 0,
    EV_PARAMETERIZATION: -50,
    EV_ALLOWLIST: -40,
    EV_SANITIZATION: -35,
    EV_VALIDATION: -25,
    EV_PATTERN_ONLY: 5,
    EV_COMMENT_OR_FIXTURE: -80,
    EV_CONTRADICTION: -60,
    EV_MISSING_LINK: -30,
}


def make_evidence(
    evidence_type: str,
    *,
    file: str | None = None,
    line: int | None = None,
    symbol: str | None = None,
    reason: str = "",
    snippet: str | None = None,
    weight: int | None = None,
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build a typed evidence record; never includes secret values."""
    base = _df_evidence(
        file,
        line,
        symbol=symbol,
        reason=reason,
        snippet=snippet,
    )
    ev: dict[str, Any] = {
        "type": evidence_type,
        "weight": EVIDENCE_WEIGHTS.get(evidence_type, 0) if weight is None else weight,
        **base,
    }
    if extra:
        for k, v in extra.items():
            if k not in ev:
                ev[k] = v
    ensure_no_secret_values(ev)
    return ev


def evidence_score(evidence_list: list[dict[str, Any]]) -> int:
    """Sum weights; used as a soft signal, never sole VERIFIED gate."""
    total = 0
    for ev in evidence_list or []:
        w = ev.get("weight")
        if w is None:
            w = EVIDENCE_WEIGHTS.get(str(ev.get("type") or ""), 0)
        total += int(w)
    return total


def has_evidence_type(evidence_list: list[dict[str, Any]], *types: str) -> bool:
    wanted = set(types)
    return any(str(ev.get("type") or "") in wanted for ev in (evidence_list or []))


def control_evidence_types(control_kind: str) -> str:
    mapping = {
        "parameterization": EV_PARAMETERIZATION,
        "allowlist": EV_ALLOWLIST,
        "sanitization": EV_SANITIZATION,
        "validation": EV_VALIDATION,
        "authorization": EV_CONTROL,
    }
    return mapping.get(control_kind, EV_CONTROL)
