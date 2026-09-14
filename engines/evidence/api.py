"""Query helpers over an evidence result.

All helpers accept an evidence ``result`` dict (from ``run_evidence``) and a
finding id, and read from the shared ``evidence_store`` so callers never need to
know how evidence is deduplicated internally.
"""

from __future__ import annotations

from typing import Any

from engines.evidence.schema import REL_COUNTER, REL_SUPPORTING


def _entry(result: dict[str, Any], finding_id: str) -> dict[str, Any] | None:
    for e in result.get("findings_evidence") or []:
        if e.get("finding_id") == finding_id:
            return e
    return None


def _resolve(result: dict[str, Any], ids: list[str]) -> list[dict[str, Any]]:
    store = result.get("evidence_store") or {}
    return [store[i] for i in ids if i in store]


def get_evidence(result: dict[str, Any], finding_id: str) -> list[dict[str, Any]]:
    """All evidence items (supporting + counter) for a finding."""
    entry = _entry(result, finding_id)
    if not entry:
        return []
    ids = list(entry.get("supporting_evidence_ids") or []) + list(
        entry.get("counter_evidence_ids") or []
    )
    return _resolve(result, ids)


def get_supporting_evidence(
    result: dict[str, Any], finding_id: str
) -> list[dict[str, Any]]:
    entry = _entry(result, finding_id)
    if not entry:
        return []
    return _resolve(result, list(entry.get("supporting_evidence_ids") or []))


def get_counter_evidence(
    result: dict[str, Any], finding_id: str
) -> list[dict[str, Any]]:
    entry = _entry(result, finding_id)
    if not entry:
        return []
    return _resolve(result, list(entry.get("counter_evidence_ids") or []))


def get_unknowns(result: dict[str, Any], finding_id: str) -> list[str]:
    entry = _entry(result, finding_id)
    if not entry:
        return []
    return list(entry.get("unknowns") or [])


def get_confidence(result: dict[str, Any], finding_id: str) -> dict[str, Any] | None:
    """Full confidence result (level, components, reasons, unknowns)."""
    entry = _entry(result, finding_id)
    if not entry:
        return None
    return entry.get("evidence_confidence")


def get_confidence_level(result: dict[str, Any], finding_id: str) -> str | None:
    entry = _entry(result, finding_id)
    if not entry:
        return None
    return entry.get("confidence_level")


def get_evidence_chain(
    result: dict[str, Any], finding_id: str
) -> list[dict[str, Any]]:
    entry = _entry(result, finding_id)
    if not entry:
        return []
    return list(entry.get("chain") or [])


def get_conflicts(result: dict[str, Any], finding_id: str) -> list[dict[str, Any]]:
    entry = _entry(result, finding_id)
    if not entry:
        return []
    return list(entry.get("conflicts") or [])


__all__ = [
    "get_evidence",
    "get_supporting_evidence",
    "get_counter_evidence",
    "get_unknowns",
    "get_confidence",
    "get_confidence_level",
    "get_evidence_chain",
    "get_conflicts",
]

# Referenced for symmetry with relationship vocabulary in tests/tools.
_RELATIONSHIPS = (REL_SUPPORTING, REL_COUNTER)
