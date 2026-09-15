"""Per-candidate investigation loop."""

from __future__ import annotations

from typing import Any

from engines.investigation.actions import execute_action
from engines.investigation.budget import action_cost_weight, budget_limits
from engines.investigation.graph import (
    ensure_candidate_node,
    record_action_node,
    record_decision_node,
    record_evidence_nodes,
)
from engines.investigation.hypothesis import apply_evidence_to_hypotheses, seed_hypotheses
from engines.investigation.planner import plan_actions
from engines.investigation.questions import initial_questions, mark_question
from engines.investigation.schema import (
    STATUS_CHALLENGING,
    STATUS_COMPLETED,
    STATUS_CREATED,
    STATUS_FAILED,
    STATUS_INVESTIGATING,
    STATUS_PLANNING,
    STATUS_REASSESSING,
    TERM_ERROR,
    UNKNOWN,
    empty_investigation,
    utc_now,
)
from engines.investigation.specialists import select_specialists
from engines.investigation.stop import evaluate_stop, map_decision_to_confidence


def investigate_candidate(
    candidate: dict[str, Any],
    *,
    context: dict[str, Any] | None = None,
    budget: str = "BALANCED",
) -> dict[str, Any]:
    """Run the OBSERVE→…→STOP loop for one candidate. Deterministic & symbolic."""
    ctx = dict(context or {})
    inv = empty_investigation(candidate=candidate, budget=budget)
    cand_node = ensure_candidate_node(inv)

    try:
        _timeline(inv, "OBSERVE", "Candidate accepted for investigation")
        inv["status"] = STATUS_PLANNING
        inv["hypotheses"] = seed_hypotheses(candidate)
        inv["hypothesis"] = inv["hypotheses"][0]["statement"]
        inv["questions"] = initial_questions(candidate)

        limits = budget_limits(budget)
        inv["specialists_used"] = select_specialists(
            candidate, max_specialists=limits["max_specialists"]
        )
        _timeline(
            inv,
            "FORM_HYPOTHESIS",
            inv["hypothesis"] or "",
        )

        # Main loop
        safety = 0
        last_parent = cand_node
        while safety < 64:
            safety += 1
            stop = evaluate_stop(inv)
            if stop:
                _apply_stop(inv, stop, last_parent)
                break

            inv["status"] = STATUS_PLANNING
            _timeline(inv, "IDENTIFY_MISSING_EVIDENCE", "Planning next actions")
            actions = plan_actions(inv)
            if not actions:
                # Nothing left to do
                stop = evaluate_stop(inv) or {
                    "status": STATUS_COMPLETED
                    if inv.get("decision")
                    else "INSUFFICIENT_EVIDENCE",
                    "decision": inv.get("decision") or "UNVERIFIED",
                    "termination_reason": "no_further_actions",
                    "reasoning_summary": "No further cost-effective actions remain",
                    "next_action": "STOP",
                }
                # normalize insufficient status constant
                if stop["status"] == "INSUFFICIENT_EVIDENCE":
                    from engines.investigation.schema import STATUS_INSUFFICIENT_EVIDENCE

                    stop["status"] = STATUS_INSUFFICIENT_EVIDENCE
                _apply_stop(inv, stop, last_parent)
                break

            action = actions[0]
            inv["status"] = STATUS_INVESTIGATING
            inv["next_action"] = action.get("type")
            _timeline(
                inv,
                "SELECT_INVESTIGATION",
                f"{action.get('type')} (cost={action.get('cost')})",
            )
            action_node = record_action_node(inv, action, last_parent)
            last_parent = action_node

            result = execute_action(action, candidate, ctx)
            inv["investigations_performed"].append(action)
            inv["actions_spent"] = int(inv.get("actions_spent") or 0) + 1
            inv["cost_spent"] = int(inv.get("cost_spent") or 0) + action_cost_weight(
                str(action.get("cost"))
            )

            # Collect evidence
            inv["status"] = STATUS_CHALLENGING
            _timeline(inv, "COLLECT_EVIDENCE", result.get("notes") or action.get("type"))
            for item in result.get("evidence") or []:
                inv["evidence"].append(item)
            for item in result.get("counter_evidence") or []:
                inv["counter_evidence"].append(item)
            for u in result.get("unknowns") or []:
                inv.setdefault("unknowns", []).append(
                    {"topic": str(u), "detail": str(u)}
                    if not isinstance(u, dict)
                    else u
                )
            for c in result.get("controls") or []:
                inv.setdefault("controls_found", []).append(c)
            for p in result.get("attack_paths") or []:
                inv.setdefault("attack_paths", []).append(p)

            record_evidence_nodes(
                inv, result.get("evidence") or [], action_node, kind="evidence"
            )
            record_evidence_nodes(
                inv,
                result.get("counter_evidence") or [],
                action_node,
                kind="counter_evidence",
            )

            for ans in result.get("answered_questions") or []:
                mark_question(
                    inv["questions"],
                    str(ans.get("question_id")),
                    status=str(ans.get("status") or "ANSWERED"),
                    answer=ans.get("answer"),
                )

            inv["status"] = STATUS_REASSESSING
            _timeline(inv, "CHALLENGE_HYPOTHESIS", "Updating hypotheses from evidence")
            apply_evidence_to_hypotheses(inv)
            _timeline(inv, "UPDATE_CONFIDENCE", f"hypothesis={inv.get('hypothesis')}")
        else:
            _apply_stop(
                inv,
                {
                    "status": STATUS_FAILED,
                    "decision": "UNVERIFIED",
                    "termination_reason": TERM_ERROR,
                    "reasoning_summary": "Investigation loop safety cap reached",
                    "next_action": "STOP",
                },
                last_parent,
            )

    except Exception as exc:  # noqa: BLE001 — never crash caller
        inv["status"] = STATUS_FAILED
        inv["decision"] = "UNVERIFIED"
        inv["termination_reason"] = TERM_ERROR
        inv["reasoning_summary"] = f"Investigation error: {exc}"
        inv["next_action"] = "STOP"
        inv["unknowns"].append({"topic": "investigation_error", "detail": str(exc)})

    inv["confidence_after"] = map_decision_to_confidence(inv.get("decision"))
    inv["generated_at"] = utc_now()
    # Judge package: structured handoff (no invented facts)
    inv["judge_package"] = {
        "candidate_id": inv.get("candidate_id"),
        "decision": inv.get("decision") or UNKNOWN,
        "confidence": inv.get("confidence_after"),
        "evidence": inv.get("evidence") or [],
        "counter_evidence": inv.get("counter_evidence") or [],
        "unknowns": inv.get("unknowns") or [],
        "assumptions": inv.get("assumptions") or [],
        "contradictions": inv.get("contradictions") or [],
        "attack_paths": inv.get("attack_paths") or [],
        "controls_found": inv.get("controls_found") or [],
        "specialists_used": inv.get("specialists_used") or [],
        "termination_reason": inv.get("termination_reason"),
        "reasoning_summary": inv.get("reasoning_summary"),
        "investigation_id": inv.get("investigation_id"),
    }
    return inv


def _apply_stop(inv: dict[str, Any], stop: dict[str, Any], parent_id: str) -> None:
    inv["status"] = stop["status"]
    inv["decision"] = stop["decision"]
    inv["termination_reason"] = stop["termination_reason"]
    inv["reasoning_summary"] = stop["reasoning_summary"]
    inv["next_action"] = stop.get("next_action") or "STOP"
    _timeline(inv, "STOP", stop["reasoning_summary"])
    record_decision_node(inv, parent_id)


def _timeline(inv: dict[str, Any], event: str, detail: str) -> None:
    inv.setdefault("timeline", []).append(
        {"at": utc_now(), "event": event, "detail": detail}
    )
