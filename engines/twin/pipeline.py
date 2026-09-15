"""Security Twin pipeline orchestration."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from engines.twin.blast_radius import entity_blast_radius
from engines.twin.build import build_security_twin
from engines.twin.controls import control_effectiveness
from engines.twin.counterfactual import run_counterfactual
from engines.twin.regression import twin_regression
from engines.twin.report import write_twin_report
from engines.twin.simulate import simulate_attack


def run_twin(
    target: Path,
    *,
    attack_graph: dict[str, Any] | None = None,
    application_model: dict[str, Any] | None = None,
    simulate: bool = True,
    controls: bool = True,
    blast_entity: str | None = None,
    attacker_profile: str = "PUBLIC_USER",
    max_paths: int = 20,
    write_report: Path | None = None,
) -> dict[str, Any]:
    """Build a Security Twin and optionally run simulate/controls/blast."""
    twin = build_security_twin(
        target,
        attack_graph=attack_graph,
        application_model=application_model,
    )

    result: dict[str, Any] = {"twin": twin}

    if simulate:
        result["simulation"] = simulate_attack(
            twin, attacker_profile=attacker_profile, max_paths=max_paths
        )

    if controls:
        result["controls"] = control_effectiveness(twin)

    if blast_entity:
        result["blast_radius"] = entity_blast_radius(twin, blast_entity)

    if write_report:
        write_twin_report(result, write_report)

    return result


def run_twin_what_if(
    target: Path,
    *,
    scenario: str | None = None,
    remove_control: str | None = None,
    grant_agent_tool: str | None = None,
    compromise_entity: str | None = None,
    assumptions: list[str] | None = None,
    twin: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build twin (if needed) and run counterfactual analysis."""
    if twin is None:
        twin = build_security_twin(target)

    cf = run_counterfactual(
        twin,
        scenario=scenario,
        remove_control=remove_control,
        grant_agent_tool=grant_agent_tool,
        compromise_entity=compromise_entity,
        assumptions=assumptions,
    )
    return {"twin": twin, "counterfactual": cf}


def run_twin_compare(
    before: dict[str, Any],
    after: dict[str, Any],
) -> dict[str, Any]:
    """Compare two Security Twins (regression analysis)."""
    return {
        "before": before,
        "after": after,
        "regression": twin_regression(before, after),
    }
