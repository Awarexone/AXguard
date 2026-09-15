"""Evidence chains.

An evidence chain narrates a finding as an ordered set of stages:

    Finding → Source → Flow → Transform → Control → Sink → Reachability →
    Config → Judgment

Each stage references the evidence ids that back it. Stages with no evidence are
still emitted (marked ``present=False`` / ``UNKNOWN``) so that gaps are explicit
rather than hidden.
"""

from __future__ import annotations

from typing import Any

from engines.evidence.schema import (
    EV_AUTHORIZATION,
    EV_CONFIGURATION,
    EV_DATA_FLOW,
    EV_FRAMEWORK_BEHAVIOR,
    EV_REACHABILITY,
    EV_SANITIZATION,
    EV_SECURITY_CONTROL,
    EV_SINK,
    EV_SOURCE,
    EV_TRUST_BOUNDARY,
    EV_VALIDATION,
)

# stage name → evidence types that populate it
_STAGE_TYPES: list[tuple[str, tuple[str, ...]]] = [
    ("source", (EV_SOURCE, EV_TRUST_BOUNDARY)),
    ("flow", (EV_DATA_FLOW,)),
    ("transform", (EV_SANITIZATION, EV_VALIDATION)),
    ("control", (EV_SECURITY_CONTROL, EV_AUTHORIZATION)),
    ("sink", (EV_SINK,)),
    ("reachability", (EV_REACHABILITY,)),
    ("config", (EV_CONFIGURATION, EV_FRAMEWORK_BEHAVIOR)),
]


def build_chain(
    finding: dict[str, Any],
    evidence_refs: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Build the ordered evidence chain for a finding.

    ``evidence_refs`` is a list of ``{"id", "type", "relationship", "quality"}``
    dicts (resolved from the store) belonging to this finding.
    """
    by_type: dict[str, list[dict[str, Any]]] = {}
    for ref in evidence_refs:
        by_type.setdefault(str(ref.get("type")), []).append(ref)

    chain: list[dict[str, Any]] = [
        {
            "stage": "finding",
            "present": True,
            "description": (
                f"{finding.get('vulnerability_type') or 'finding'} "
                f"[{finding.get('status')}]"
            ),
            "evidence_ids": [],
        }
    ]

    for stage, types in _STAGE_TYPES:
        refs: list[dict[str, Any]] = []
        for t in types:
            refs.extend(by_type.get(t, []))
        ids = [str(r.get("id")) for r in refs if r.get("id")]
        chain.append(
            {
                "stage": stage,
                "present": bool(ids),
                "description": _describe_stage(stage, refs),
                "evidence_ids": ids,
            }
        )

    chain.append(
        {
            "stage": "judgment",
            "present": True,
            "description": (
                f"Adversary status={finding.get('status')} "
                f"(prior judge={finding.get('prior_judge_status')})"
            ),
            "evidence_ids": [],
        }
    )
    return chain


def _describe_stage(stage: str, refs: list[dict[str, Any]]) -> str:
    if not refs:
        return f"{stage}: UNKNOWN (no evidence)"
    qualities = sorted({str(r.get("quality")) for r in refs})
    rels = sorted({str(r.get("relationship")) for r in refs})
    return f"{stage}: {len(refs)} item(s) quality={','.join(qualities)} rel={','.join(rels)}"
