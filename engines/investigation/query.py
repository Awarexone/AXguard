"""Deterministic investigation Q/A and explain helpers."""

from __future__ import annotations

from typing import Any

from engines.investigation.schema import UNKNOWN


def explain_investigation(inv: dict[str, Any]) -> str:
    """Human-readable explanation from structured fields only."""
    lines = [
        f"Investigation {inv.get('investigation_id') or UNKNOWN}",
        f"Candidate: {inv.get('candidate_id')}",
        f"Status: {inv.get('status')}  Decision: {inv.get('decision') or UNKNOWN}",
        f"Hypothesis: {inv.get('hypothesis') or UNKNOWN}",
        f"Reasoning: {inv.get('reasoning_summary') or UNKNOWN}",
        f"Stopped because: {inv.get('termination_reason') or UNKNOWN}",
        f"Confidence: {inv.get('confidence_before')} → {inv.get('confidence_after')}",
        f"Actions: {len(inv.get('investigations_performed') or [])} "
        f"(cost weight {inv.get('cost_spent', 0)})",
        f"Evidence: {len(inv.get('evidence') or [])}  "
        f"Counter-evidence: {len(inv.get('counter_evidence') or [])}  "
        f"Unknowns: {len(inv.get('unknowns') or [])}",
    ]
    return "\n".join(lines)


def answer_investigation_query(result: dict[str, Any], question: str) -> dict[str, Any]:
    """Keyword Q/A over an investigation run (no LLM)."""
    q = (question or "").lower().strip()
    investigations = result.get("investigations") or []
    summary = result.get("summary") or {}

    if "false positive" in q or " fp" in q or q.strip() == "fp":
        fps = [i for i in investigations if i.get("decision") == "FALSE_POSITIVE"]
        return {
            "intent": "false_positives",
            "answer": {
                "count": len(fps),
                "ids": [i.get("investigation_id") for i in fps],
            },
        }
    if "verified" in q:
        hits = [i for i in investigations if i.get("decision") == "VERIFIED"]
        return {
            "intent": "verified",
            "answer": {
                "count": len(hits),
                "ids": [i.get("investigation_id") for i in hits],
            },
        }
    if "how many" in q or "count" in q:
        return {
            "intent": "summary",
            "answer": summary,
        }
    if "unknown" in q:
        return {
            "intent": "unknowns",
            "answer": [
                {"candidate_id": i.get("candidate_id"), "unknowns": i.get("unknowns")}
                for i in investigations
                if i.get("unknowns")
            ],
        }
    if "explain" in q or "why" in q:
        # Explain first matching id substring in question
        for inv in investigations:
            cid = str(inv.get("candidate_id") or "")
            iid = str(inv.get("investigation_id") or "")
            if cid and cid in q or iid and iid in q:
                return {"intent": "explain", "answer": explain_investigation(inv)}
        if investigations:
            return {
                "intent": "explain",
                "answer": explain_investigation(investigations[0]),
            }
    return {
        "intent": "unknown",
        "answer": UNKNOWN,
        "note": "No deterministic match for question",
    }


def find_investigation(
    result: dict[str, Any], finding_id: str
) -> dict[str, Any] | None:
    for inv in result.get("investigations") or []:
        if finding_id in str(inv.get("candidate_id") or "") or finding_id in str(
            inv.get("investigation_id") or ""
        ):
            return inv
    return None
