"""Counterfactual what-if analysis over a Security Twin."""

from __future__ import annotations

from typing import Any

from engines.attack_graph import whatif
from engines.twin.schema import LAYER_ASSUMED, LAYER_OBSERVED, LAYER_SIMULATED, tagged

_DISCLAIMER = (
    "Counterfactual analysis — SIMULATED paths assume stated changes. "
    "Not confirmed vulnerabilities or exploitable findings."
)

# Map twin-local scenario hints → attack-graph what-if keys
_SCENARIO_MAP = {
    "remove_control": "remove_authz",
    "remove_authz": "remove_authz",
    "tenant_isolation": "tenant_isolation_weakened",
    "tenant_isolation_weakened": "tenant_isolation_weakened",
    "grant_agent_tool": "ai_tool_gains_fs",
    "shell": "ai_tool_gains_fs",
    "ai_tool_gains_fs": "ai_tool_gains_fs",
    "secret_exposure": "secret_leaks",
    "secret_leaks": "secret_leaks",
    "public_endpoint": "publicize_endpoint",
    "publicize_endpoint": "publicize_endpoint",
    "unrestricted_egress": "unrestricted_egress",
}


def run_counterfactual(
    twin: dict[str, Any],
    *,
    scenario: str | None = None,
    remove_control: str | None = None,
    grant_agent_tool: str | None = None,
    compromise_entity: str | None = None,
    assumptions: list[str] | None = None,
) -> dict[str, Any]:
    """Run symbolic counterfactuals; never mutates ``twin``."""
    ag = twin.get("attack_graph")
    if not ag:
        return _empty_result(assumptions, reason="no attack_graph on twin")

    resolved_scenario = _resolve_scenario(
        scenario, remove_control, grant_agent_tool, compromise_entity
    )
    assumption_list = list(assumptions or [])
    if remove_control:
        assumption_list.append(f"Control {remove_control} is removed or bypassed")
    if grant_agent_tool:
        assumption_list.append(f"Agent granted tool: {grant_agent_tool}")
    if compromise_entity:
        assumption_list.append(f"Entity compromised: {compromise_entity}")

    observed_summary = _observed_summary(twin)
    simulated_paths: list[dict[str, Any]] = []
    control_analysis: list[dict[str, Any]] = []

    if resolved_scenario:
        try:
            wi = whatif.run_what_if(ag, resolved_scenario)
            for hp in wi.get("hypothetical_paths") or []:
                simulated_paths.append(_wrap_hypo_path(hp))
        except KeyError:
            pass

    if remove_control:
        control_analysis.extend(_analyze_control_removal(ag, remove_control))
    elif not resolved_scenario:
        control_analysis.extend(_analyze_all_controls(ag))

    return {
        "scenario": tagged(resolved_scenario or "custom", LAYER_ASSUMED),
        "assumptions": [tagged(a, LAYER_ASSUMED) for a in assumption_list],
        "observed_summary": observed_summary,
        "simulated_paths": simulated_paths,
        "control_analysis": control_analysis,
        "disclaimer": _DISCLAIMER,
    }


def _resolve_scenario(
    scenario: str | None,
    remove_control: str | None,
    grant_agent_tool: str | None,
    compromise_entity: str | None,
) -> str | None:
    if scenario:
        key = str(scenario).strip().lower()
        return _SCENARIO_MAP.get(key, key if key in whatif.SCENARIOS else None)
    if remove_control:
        return "remove_authz"
    if grant_agent_tool:
        return "ai_tool_gains_fs"
    if compromise_entity:
        ent = str(compromise_entity).lower()
        if "secret" in ent or "credential" in ent:
            return "secret_leaks"
        if "mcp" in ent or "agent" in ent:
            return "ai_tool_gains_fs"
        if "tenant" in ent:
            return "tenant_isolation_weakened"
    return None


def _observed_summary(twin: dict[str, Any]) -> dict[str, Any]:
    ag = twin.get("attack_graph") or {}
    paths = ag.get("paths") or []
    by_status: dict[str, int] = {}
    for p in paths:
        st = str(p.get("status") or "UNKNOWN")
        by_status[st] = by_status.get(st, 0) + 1
    return {
        "layer": LAYER_OBSERVED,
        "path_count": len(paths),
        "by_status": by_status,
        "entity_count": twin.get("summary", {}).get("entity_count", 0),
    }


def _wrap_hypo_path(hp: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": hp.get("id"),
        "layer": LAYER_SIMULATED,
        "status": tagged("POSSIBLE", LAYER_SIMULATED),
        "scenario": hp.get("scenario"),
        "title": hp.get("title"),
        "premise": tagged(hp.get("premise"), LAYER_ASSUMED),
        "predicted_effect": tagged(hp.get("predicted_effect"), LAYER_SIMULATED),
        "hops": tagged(list(hp.get("hops") or []), LAYER_SIMULATED),
        "disclaimer": hp.get("disclaimer"),
        "hypothetical": True,
    }


def _analyze_control_removal(ag: dict[str, Any], control_id: str) -> list[dict[str, Any]]:
    paths = ag.get("paths") or []
    blocked_with = [
        p for p in paths
        if str(p.get("status")) == "BLOCKED"
        and any(str(c.get("id")) == control_id for c in (p.get("controls_encountered") or []))
    ]
    return [
        {
            "control_id": control_id,
            "layer": LAYER_SIMULATED,
            "blocked_path_count": len(blocked_with),
            "paths_exposed_if_removed": [p.get("id") for p in blocked_with],
            "note": "Paths currently BLOCKED that reference this control",
        }
    ]


def _analyze_all_controls(ag: dict[str, Any]) -> list[dict[str, Any]]:
    graph = ag.get("graph") or {}
    controls = [n for n in graph.get("nodes") or [] if n.get("type") == "control"]
    out: list[dict[str, Any]] = []
    for ctrl in controls[:20]:
        cid = str(ctrl.get("id"))
        analysis = _analyze_control_removal(ag, cid)
        if analysis and analysis[0]["blocked_path_count"]:
            out.append(analysis[0])
    return out


def _empty_result(assumptions: list[str] | None, *, reason: str) -> dict[str, Any]:
    return {
        "scenario": tagged(None, LAYER_ASSUMED),
        "assumptions": [tagged(a, LAYER_ASSUMED) for a in (assumptions or [])],
        "observed_summary": {"layer": LAYER_OBSERVED, "path_count": 0, "reason": reason},
        "simulated_paths": [],
        "control_analysis": [],
        "disclaimer": _DISCLAIMER,
    }
