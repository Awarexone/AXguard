"""Deterministic keyword/intent query interface over a Security Twin."""

from __future__ import annotations

import re
from typing import Any

from engines.attack_graph import api as ag_api
from engines.twin.blast_radius import entity_blast_radius
from engines.twin.controls import control_effectiveness
from engines.twin.counterfactual import run_counterfactual
from engines.twin.schema import LAYER_OBSERVED, LAYER_SIMULATED, tagged

_INTENTS = (
    "blast_radius",
    "controls_protect",
    "cross_tenant",
    "highest_privilege_agent",
    "counterfactual",
    "mcp_compromise",
    "unknown",
)


def answer_query(twin: dict[str, Any], question: str) -> dict[str, Any]:
    """Map ``question`` to a structured answer via deterministic intent matching."""
    q = (question or "").strip().lower()
    intent = _match_intent(q)
    evidence_refs: list[dict[str, Any]] = []

    if intent == "blast_radius":
        entity_id = _extract_entity(q) or _first_agent_id(twin)
        result = entity_blast_radius(twin, entity_id) if entity_id else {}
        answer = {
            "entity_id": entity_id,
            "node_count": (result.get("blast") or {}).get("node_count", 0),
            "max_sensitivity": (result.get("blast") or {}).get("max_sensitivity"),
            "impacts": result.get("impact_classifications") or [],
        }
        evidence_refs = [{"type": "blast_radius", "entity_id": entity_id}]

    elif intent == "controls_protect":
        controls = control_effectiveness(twin)
        top = controls[:5] if controls else []
        answer = {
            "controls": [
                {
                    "id": c["control_id"],
                    "protected": c["protected_path_count"],
                    "exposed_if_removed": c["paths_exposed_if_removed"],
                }
                for c in top
            ]
        }
        evidence_refs = [{"type": "control", "id": c["control_id"]} for c in top]

    elif intent == "cross_tenant":
        ag = twin.get("attack_graph") or {}
        boundaries = ag_api.get_tenant_boundaries(ag)
        answer = {
            "tenants": boundaries.get("tenants") or [],
            "crossing_count": len(boundaries.get("crossing_transitions") or []),
            "crossings": boundaries.get("crossing_transitions") or [],
        }
        evidence_refs = [{"type": "tenant_boundary"}]

    elif intent == "highest_privilege_agent":
        agent = _highest_privilege_agent(twin)
        answer = agent or {"note": "No AI agent entities observed", "layer": LAYER_OBSERVED}
        evidence_refs = [{"type": "ai_agent", "id": agent.get("id")}] if agent else []

    elif intent == "counterfactual":
        scenario = _extract_scenario(q)
        cf = run_counterfactual(twin, scenario=scenario)
        answer = {
            "scenario": cf.get("scenario"),
            "simulated_path_count": len(cf.get("simulated_paths") or []),
            "assumptions": cf.get("assumptions") or [],
            "suggestion": "Use run_counterfactual() with explicit parameters for precise analysis.",
        }
        evidence_refs = [{"type": "counterfactual", "scenario": scenario}]

    elif intent == "mcp_compromise":
        mcp_entities = [
            e for e in (twin.get("entities") or []) if e.get("type") == "MCPServer"
        ]
        cf = run_counterfactual(twin, scenario="ai_tool_gains_fs") if mcp_entities else {}
        answer = {
            "mcp_servers": [{"id": e.get("id"), "name": e.get("name")} for e in mcp_entities],
            "simulated_paths": len(cf.get("simulated_paths") or []) if cf else 0,
            "layer": LAYER_SIMULATED,
        }
        evidence_refs = [{"type": "mcp_server", "id": e.get("id")} for e in mcp_entities]

    else:
        answer = {
            "message": "No matching intent. Supported: blast radius, controls, cross tenant, "
            "highest privilege agent, what if, MCP compromise.",
            "layer": LAYER_OBSERVED,
        }
        intent = "unknown"

    return {
        "question": question,
        "intent": intent,
        "answer": answer,
        "evidence_refs": evidence_refs,
        "layer": LAYER_SIMULATED if intent in {"counterfactual", "mcp_compromise"} else LAYER_OBSERVED,
    }


def _match_intent(q: str) -> str:
    if re.search(r"blast\s*radius|blast radius of", q):
        return "blast_radius"
    if re.search(r"control(s)?\s*(protect|effectiveness|choke)", q):
        return "controls_protect"
    if re.search(r"cross[\s-]?tenant", q):
        return "cross_tenant"
    if re.search(r"highest[\s-]?privilege[\s-]?agent|most[\s-]?privileged[\s-]?agent", q):
        return "highest_privilege_agent"
    if re.search(r"what[\s-]?if|remove|grant|counterfactual", q):
        return "counterfactual"
    if re.search(r"mcp[\s-]?(compromise|supply|server)", q):
        return "mcp_compromise"
    return "unknown"


def _extract_entity(q: str) -> str | None:
    m = re.search(r"(?:blast radius of|for)\s+([a-z0-9_:/.-]+)", q)
    return m.group(1) if m else None


def _extract_scenario(q: str) -> str | None:
    for key in ("remove control", "remove authz", "grant tool", "secret", "public", "tenant", "mcp"):
        if key in q:
            return key.replace(" ", "_")
    return None


def _first_agent_id(twin: dict[str, Any]) -> str | None:
    for ent in twin.get("entities") or []:
        if ent.get("type") in {"AIAgent", "AIModel"}:
            return str(ent.get("id"))
    ag = twin.get("attack_graph") or {}
    for node in (ag.get("graph") or {}).get("nodes") or []:
        if node.get("type") == "ai_component":
            return str(node.get("id"))
    return None


def _highest_privilege_agent(twin: dict[str, Any]) -> dict[str, Any] | None:
    ag = twin.get("attack_graph") or {}
    paths = ag.get("paths") or []
    graph = ag.get("graph") or {}
    nodes = {str(n.get("id")): n for n in graph.get("nodes") or []}

    best: dict[str, Any] | None = None
    best_score = -1
    for ent in twin.get("entities") or []:
        if ent.get("type") not in {"AIAgent", "AIModel", "MCPServer"}:
            continue
        eid = str(ent.get("id"))
        path_touch = sum(1 for p in paths if eid in [str(h) for h in (p.get("hops") or [])])
        tool_count = sum(
            1 for e in (graph.get("edges") or [])
            if str(e.get("from")) == eid and e.get("type") == "invokes"
        )
        score = path_touch * 2 + tool_count
        if score > best_score:
            best_score = score
            best = {
                "id": eid,
                "type": ent.get("type"),
                "label": ent.get("label") or ent.get("name"),
                "path_touch_count": tagged(path_touch, LAYER_OBSERVED),
                "tool_invoke_count": tagged(tool_count, LAYER_OBSERVED),
                "layer": LAYER_OBSERVED,
            }
    return best
