"""Investigation budgets: FAST / BALANCED / DEEP."""

from __future__ import annotations

from typing import Any

from engines.investigation.schema import (
    BUDGET_BALANCED,
    BUDGET_DEEP,
    BUDGET_FAST,
    COST_WEIGHT,
)


def budget_limits(budget: str) -> dict[str, int]:
    """Configurable action / cost / depth limits. No infinite loops."""
    b = (budget or BUDGET_BALANCED).upper()
    if b == BUDGET_FAST:
        return {
            "max_actions": 6,
            "max_cost": 12,
            "max_files": 8,
            "max_depth": 2,
            "max_specialists": 2,
        }
    if b == BUDGET_DEEP:
        return {
            "max_actions": 24,
            "max_cost": 80,
            "max_files": 40,
            "max_depth": 6,
            "max_specialists": 6,
        }
    return {
        "max_actions": 12,
        "max_cost": 36,
        "max_files": 20,
        "max_depth": 4,
        "max_specialists": 4,
    }


def action_cost_weight(cost: str) -> int:
    return int(COST_WEIGHT.get(str(cost).upper(), COST_WEIGHT["LOW"]))


def budget_exhausted(investigation: dict[str, Any]) -> bool:
    limits = budget_limits(str(investigation.get("budget") or BUDGET_BALANCED))
    if int(investigation.get("actions_spent") or 0) >= limits["max_actions"]:
        return True
    if int(investigation.get("cost_spent") or 0) >= limits["max_cost"]:
        return True
    return False
