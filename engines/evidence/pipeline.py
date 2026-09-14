"""Evidence & Confidence pipeline (Phase 5).

``run_evidence(target, adversary=None)`` consumes Phase 4 adversary findings
(running the adversary if not supplied), reuses the verification / application
model / dataflow already computed (never rebuilding graphs), collects evidence
per finding, deduplicates it into a shared store, builds chains, detects
conflicts, and computes an explainable confidence level per finding.

Backward compatibility: existing finding ``status`` / ``confidence`` fields are
preserved. New fields ``confidence_level`` and ``evidence_confidence`` are added.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from engines.dataflow.schema import ensure_no_secret_values
from engines.evidence.chain import build_chain
from engines.evidence.collect import collect_evidence
from engines.evidence.confidence import compute_confidence, propagate_confidence
from engines.evidence.conflicts import detect_conflicts, has_unresolved_conflict
from engines.evidence.schema import (
    CONFIDENCE_LEVELS,
    EVIDENCE_VERSION,
    REL_COUNTER,
    REL_SUPPORTING,
    empty_evidence,
    map_legacy_confidence,
)
from engines.evidence.store import EvidenceStore
from engines.evidence.summarize import summarize_entry


def run_evidence(
    target: Path,
    adversary: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build the evidence & confidence graph for a target.

    If ``adversary`` is ``None``, runs the Phase 4 adversary first. Reuses the
    embedded ``_verification`` / ``_application_model`` / ``_dataflow`` models.
    """
    root = Path(target).resolve()

    if adversary is None:
        from engines.adversary import run_adversary

        adversary = run_adversary(root)

    verification = adversary.get("_verification") or {}
    application_model = verification.get("_application_model")
    dataflow = verification.get("_dataflow")

    candidates_by_id = {
        c.get("id"): c
        for c in (verification.get("candidates") or [])
        if c.get("id")
    }

    result = empty_evidence(root)
    result["schema_version"] = EVIDENCE_VERSION
    result["generated_at"] = datetime.now(timezone.utc).isoformat()

    store = EvidenceStore()
    entries: list[dict[str, Any]] = []
    findings = list(adversary.get("findings") or [])

    for finding in findings:
        candidate = candidates_by_id.get(finding.get("from_judgment_id"))
        raw_items = collect_evidence(
            finding,
            candidate=candidate,
            dataflow=dataflow,
            application_model=application_model,
        )

        supporting_ids: list[str] = []
        counter_ids: list[str] = []
        resolved_refs: list[dict[str, Any]] = []
        for item in raw_items:
            eid = store.add(item)
            stored = store.get(eid) or item
            ref = {
                "id": eid,
                "type": stored.get("type"),
                "quality": stored.get("quality"),
                "relationship": item.get("relationship"),
                "kind": item.get("kind"),
                "name_only": bool(item.get("name_only")),
            }
            resolved_refs.append(ref)
            if item.get("relationship") == REL_COUNTER:
                counter_ids.append(eid)
            else:
                supporting_ids.append(eid)

        conflicts = detect_conflicts(resolved_refs, finding)
        confidence = compute_confidence(finding, resolved_refs)
        chain = build_chain(finding, resolved_refs)

        # Unresolved conflicts nudge the finding toward review handling.
        conflict_handling = None
        if has_unresolved_conflict(conflicts):
            conflict_handling = "REQUIRES_REVIEW"
            if "unresolved conflict → REQUIRES_REVIEW" not in confidence["reasons"]:
                confidence["reasons"].append("unresolved conflict → REQUIRES_REVIEW")

        loc = finding.get("location") or {}
        entry: dict[str, Any] = {
            "finding_id": finding.get("id"),
            "vulnerability_type": finding.get("vulnerability_type"),
            "status": finding.get("status"),
            "severity": finding.get("severity"),
            "prior_judge_status": finding.get("prior_judge_status"),
            # --- backward-compat: keep legacy confidence untouched ---
            "legacy_confidence": finding.get("confidence"),
            # --- new fields ---
            "confidence_level": confidence["level"],
            "evidence_confidence": confidence,
            "mapped_from_legacy": map_legacy_confidence(finding.get("confidence")),
            "supporting_evidence_ids": _dedupe(supporting_ids),
            "counter_evidence_ids": _dedupe(counter_ids),
            "unknowns": list(confidence.get("unknowns") or []),
            "conflicts": conflicts,
            "conflict_handling": conflict_handling,
            "chain": chain,
            "root_cause": finding.get("root_cause"),
            "location": dict(loc),
            "is_false_positive": finding.get("status") == "FALSE_POSITIVE",
        }
        entry["summary"] = summarize_entry(entry)
        entries.append(entry)

    # Propagate shared-evidence uncertainty across findings.
    propagate_confidence(entries, store)

    # Refresh summaries after propagation may have changed confidence.
    for entry in entries:
        entry["summary"] = summarize_entry(entry)

    result["findings_evidence"] = entries
    result["evidence_store"] = store.to_dict()
    result["summary"] = _build_summary(entries, store)
    result["meta"] = {
        "adversary": (adversary.get("meta") or {}).get("adversary", "deterministic"),
        "adversary_finding_count": len(findings),
        "application_model_present": application_model is not None,
        "dataflow_present": dataflow is not None,
        "verification_present": bool(verification),
    }
    result["_adversary"] = adversary

    # Attach compact evidence summaries onto the adversary findings (adds new
    # fields only; never touches legacy status/confidence).
    from engines.evidence.writers import attach_finding_summaries

    attach_finding_summaries(result)

    ensure_no_secret_values(result)
    return result


def write_evidence_report(result: dict[str, Any], out_dir: Path) -> dict[str, Any]:
    """Write ``evidence.json`` + ``evidence.md`` under ``out_dir``."""
    from engines.evidence.writers import write_evidence_artifacts

    return write_evidence_artifacts(result, out_dir)


def _dedupe(ids: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for i in ids:
        if i not in seen:
            seen.add(i)
            out.append(i)
    return out


def _build_summary(
    entries: list[dict[str, Any]], store: EvidenceStore
) -> dict[str, Any]:
    by_conf = {level: 0 for level in CONFIDENCE_LEVELS}
    conflict_count = 0
    unknown_count = 0
    for entry in entries:
        level = str(entry.get("confidence_level") or "UNKNOWN")
        if level in by_conf:
            by_conf[level] += 1
        conflict_count += len(entry.get("conflicts") or [])
        unknown_count += len(entry.get("unknowns") or [])
    all_items = store.all()
    return {
        "finding_count": len(entries),
        "evidence_count": sum(int(i.get("reuse_count", 1)) for i in all_items),
        "unique_evidence_count": len(all_items),
        "reused_evidence_count": store.reused_count(),
        "stale_evidence_count": len(store.stale_ids()),
        "conflict_count": conflict_count,
        "unknown_count": unknown_count,
        "findings_with_conflicts": sum(
            1 for e in entries if e.get("conflicts")
        ),
        "by_confidence": by_conf,
    }
