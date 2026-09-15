"""Export investigation trajectories (EVALUATION_ONLY)."""

from __future__ import annotations

from typing import Any

from engines.data.schema import STATUS_EVALUATION_ONLY

EVALUATION_ONLY = STATUS_EVALUATION_ONLY


def export_investigation_examples(result: dict[str, Any]) -> list[dict[str, Any]]:
    """Trajectory examples for training — never include protected benchmark answers."""
    examples: list[dict[str, Any]] = []
    target = result.get("target") or "unknown"
    for i, inv in enumerate(result.get("investigations") or []):
        timeline = inv.get("timeline") or []
        actions = [
            {"type": a.get("type"), "cost": a.get("cost"), "purpose": a.get("purpose")}
            for a in (inv.get("investigations_performed") or [])
        ]
        examples.append(
            {
                "id": f"inv-{target}-{i:03d}",
                "category": "INVESTIGATION_TRAJECTORY",
                "status": EVALUATION_ONLY,
                "question": "What is the next-best investigation action?",
                "input": {
                    "candidate_id": inv.get("candidate_id"),
                    "hypothesis": inv.get("hypothesis"),
                    "open_questions": [
                        q.get("question_id")
                        for q in (inv.get("questions") or [])
                        if q.get("status") == "OPEN"
                    ],
                },
                "answer": {
                    "actions": actions,
                    "decision": inv.get("decision"),
                    "termination_reason": inv.get("termination_reason"),
                    "confidence_after": inv.get("confidence_after"),
                },
                "meta": {
                    "timeline_events": [t.get("event") for t in timeline],
                    "specialists": inv.get("specialists_used"),
                },
            }
        )
        examples.append(
            {
                "id": f"inv-{target}-{i:03d}-stop",
                "category": "INVESTIGATION_STOPPING",
                "status": EVALUATION_ONLY,
                "question": "When should investigation stop?",
                "input": {
                    "evidence_count": len(inv.get("evidence") or []),
                    "counter_count": len(inv.get("counter_evidence") or []),
                    "unknown_count": len(inv.get("unknowns") or []),
                    "cost_spent": inv.get("cost_spent"),
                },
                "answer": {
                    "termination_reason": inv.get("termination_reason"),
                    "decision": inv.get("decision"),
                },
            }
        )
    return examples
