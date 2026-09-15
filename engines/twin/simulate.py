"""Symbolic attack-path simulation over a Security Twin."""

from __future__ import annotations

from typing import Any

from engines.attack_graph import explain as explain_mod
from engines.twin.attacker import virtual_attacker
from engines.twin.schema import (
    AG_STATUS_TO_SIM,
    LAYER_OBSERVED,
    LAYER_SIMULATED,
    SIM_CONFIRMED,
    SIM_POSSIBLE,
    tagged,
)

_DISCLAIMER = (
    "Symbolic simulation only — paths are derived from the attack graph without "
    "network access or exploit execution. SIMULATED paths are not confirmed findings."
)

_STEP_KINDS = ("START", "PRECONDITION", "ACTION", "CONTROL", "TRANSITION", "IMPACT")


def simulate_attack(
    twin: dict[str, Any],
    *,
    attacker_profile: str = "PUBLIC_USER",
    max_paths: int = 20,
) -> dict[str, Any]:
    """Enumerate attack paths from ``twin.attack_graph`` with structured steps."""
    ag = twin.get("attack_graph") or {}
    graph = ag.get("graph") or {"nodes": [], "edges": []}
    paths = list(ag.get("paths") or [])[: max(0, max_paths)]

    attacker = virtual_attacker(attacker_profile, twin)
    observed_paths: list[dict[str, Any]] = []
    simulated_paths: list[dict[str, Any]] = []

    for p in paths:
        status = str(p.get("status") or "UNKNOWN")
        sim_status = AG_STATUS_TO_SIM.get(status, SIM_POSSIBLE)
        layer = LAYER_OBSERVED if sim_status == SIM_CONFIRMED else LAYER_SIMULATED

        explanation = explain_mod.explain_path(p, graph)
        steps = _build_steps(p, explanation, graph, attacker)

        record = {
            "path_id": p.get("id"),
            "status": tagged(sim_status, layer),
            "layer": layer,
            "hops": tagged(list(p.get("hops") or []), layer),
            "entry": tagged(p.get("entry"), layer),
            "target": tagged(p.get("target"), layer),
            "tags": tagged(list(p.get("tags") or []), layer),
            "steps": steps,
            "explanation": explanation,
        }

        if sim_status == SIM_CONFIRMED:
            observed_paths.append(record)
        else:
            simulated_paths.append(record)

    return {
        "attacker": attacker,
        "observed_paths": observed_paths,
        "simulated_paths": simulated_paths,
        "path_count": len(observed_paths) + len(simulated_paths),
        "disclaimer": _DISCLAIMER,
    }


def _build_steps(
    path: dict[str, Any],
    explanation: dict[str, Any],
    graph: dict[str, Any],
    attacker: dict[str, Any],
) -> list[dict[str, Any]]:
    steps: list[dict[str, Any]] = []
    hops = [str(h) for h in path.get("hops") or []]
    if not hops:
        return steps

    steps.append(
        {
            "kind": "START",
            "layer": attacker.get("layer", LAYER_SIMULATED),
            "detail": f"Attacker profile {attacker.get('profile', {}).get('value', 'UNKNOWN')}",
            "node_id": hops[0],
        }
    )

    for ctrl in path.get("controls_encountered") or []:
        steps.append(
            {
                "kind": "CONTROL",
                "layer": LAYER_OBSERVED,
                "detail": f"Control {ctrl.get('id')} effectiveness={ctrl.get('effectiveness')}",
                "control_id": ctrl.get("id"),
            }
        )

    for i, step in enumerate(explanation.get("steps") or [], 1):
        kind = "TRANSITION" if i < len(explanation.get("steps") or []) else "IMPACT"
        steps.append(
            {
                "kind": kind,
                "layer": LAYER_OBSERVED if step.get("evidence") else LAYER_SIMULATED,
                "from": step.get("from"),
                "to": step.get("to"),
                "edge_type": step.get("edge_type"),
                "detail": step.get("evidence") or f"{step.get('from_label')} → {step.get('to_label')}",
            }
        )

    if path.get("status") == "BLOCKED":
        steps.append(
            {
                "kind": "PRECONDITION",
                "layer": LAYER_OBSERVED,
                "detail": "Path blocked by effective control(s)",
            }
        )

    return steps
