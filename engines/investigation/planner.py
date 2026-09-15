"""Investigation planner — missing evidence → cost-aware actions."""

from __future__ import annotations

from typing import Any

from engines.investigation.actions import ACTION_META, make_action
from engines.investigation.budget import action_cost_weight, budget_limits
from engines.investigation.questions import unanswered
from engines.investigation.schema import (
    ACTION_CHECK_SECURITY_MEMORY,
    ACTION_SEARCH_COUNTER_EVIDENCE,
    BUDGET_FAST,
)


def plan_actions(investigation: dict[str, Any]) -> list[dict[str, Any]]:
    """Convert unanswered questions into prioritized, cost-aware actions.

    Prefers the cheapest action that can answer the current question.
    Always prefers counter-evidence and memory checks early.
    """
    limits = budget_limits(str(investigation.get("budget") or "BALANCED"))
    performed = {
        str(a.get("type"))
        for a in (investigation.get("investigations_performed") or [])
        if a.get("status") == "DONE"
    }
    planned: list[dict[str, Any]] = []

    # Bootstrap: memory then counter-evidence unless already done
    bootstrap = [ACTION_CHECK_SECURITY_MEMORY, ACTION_SEARCH_COUNTER_EVIDENCE]
    if str(investigation.get("budget") or "").upper() != BUDGET_FAST:
        # Still include both on FAST — they are LOW cost
        pass
    for b in bootstrap:
        if b not in performed:
            planned.append(make_action(b, question_id="Q_CONTROL_PRESENT" if "COUNTER" in b else "Q_UNKNOWNS"))

    for q in unanswered(investigation.get("questions") or []):
        preferred = list(q.get("preferred_actions") or [])
        # Sort preferred by cost ascending, then priority ascending
        preferred.sort(
            key=lambda t: (
                action_cost_weight(str((ACTION_META.get(t) or {}).get("cost") or "LOW")),
                int((ACTION_META.get(t) or {}).get("priority") or 50),
            )
        )
        for atype in preferred:
            if atype in performed:
                continue
            if any(p.get("type") == atype for p in planned):
                continue
            planned.append(make_action(atype, question_id=str(q.get("question_id"))))
            break  # cheapest unanswered action for this question

    # Cap plan size to remaining budget
    remaining_actions = max(
        0, limits["max_actions"] - int(investigation.get("actions_spent") or 0)
    )
    remaining_cost = max(
        0, limits["max_cost"] - int(investigation.get("cost_spent") or 0)
    )
    selected: list[dict[str, Any]] = []
    cost_acc = 0
    for act in sorted(
        planned,
        key=lambda a: (int(a.get("priority") or 50), action_cost_weight(str(a.get("cost")))),
    ):
        w = action_cost_weight(str(act.get("cost")))
        if len(selected) >= remaining_actions:
            break
        if cost_acc + w > remaining_cost:
            continue
        selected.append(act)
        cost_acc += w
    return selected
