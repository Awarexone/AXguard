"""Public, deterministic query helpers over an attack-graph result (Part 2).

These functions are the stable surface Part 2 exposes to callers (CLI, report,
other agents). They all take the ``run_attack_graph(...)`` result dict (or its
``graph`` / ``paths``) and return plain, JSON-serialisable, deterministic data.
None of them mutate the result, invent graph elements, or introduce a new
confidence scale — they read what Part 1 built and Part 2's analysis modules
derive.
"""

from __future__ import annotations

from typing import Any

from engines.attack_graph import (
    blast,
    choke,
    equivalence,
    explain,
    fix_impact,
    identity as identity_mod,
    modes,
    privilege,
    sensitivity_data,
    state_model,
)
from engines.attack_graph.schema import PRIV_HORIZONTAL


# ---------------------------------------------------------------------------
# internal accessors
# ---------------------------------------------------------------------------
def _graph(result: dict[str, Any]) -> dict[str, Any]:
    return result.get("graph") or {"nodes": [], "edges": []}


def _paths(result: dict[str, Any]) -> list[dict[str, Any]]:
    return result.get("paths") or []


def _find_path(result: dict[str, Any], path_id: str) -> dict[str, Any] | None:
    for p in _paths(result):
        if str(p.get("id")) == str(path_id):
            return p
    return None


# ---------------------------------------------------------------------------
# state / identity
# ---------------------------------------------------------------------------
def get_path_state(result: dict[str, Any], path_id: str) -> str:
    p = _find_path(result, path_id)
    if not p:
        return "UNKNOWN"
    return state_model.get_path_state(p, _graph(result))


def get_path_identities(result: dict[str, Any], path_id: str) -> list[str]:
    p = _find_path(result, path_id)
    if not p:
        return []
    return identity_mod.get_path_identities(p, _graph(result))


def get_state_transitions(result: dict[str, Any], path_id: str | None = None) -> list[dict[str, Any]]:
    if path_id is not None:
        p = _find_path(result, path_id)
        return state_model.path_state_transitions(p, _graph(result)) if p else []
    return state_model.derive_state_transitions(_graph(result), _paths(result))


def get_identity_transitions(result: dict[str, Any], path_id: str | None = None) -> list[dict[str, Any]]:
    if path_id is not None:
        p = _find_path(result, path_id)
        return identity_mod.path_identity_transitions(p, _graph(result)) if p else []
    return identity_mod.derive_identity_transitions(_graph(result), _paths(result))


# ---------------------------------------------------------------------------
# privilege / tenant
# ---------------------------------------------------------------------------
def get_privilege_transitions(result: dict[str, Any], *, pattern: str | None = None) -> list[dict[str, Any]]:
    return privilege.get_privilege_transitions(_graph(result), _paths(result), pattern=pattern)


def get_confused_deputy_paths(result: dict[str, Any]) -> list[str]:
    return privilege.get_confused_deputy_paths(_graph(result), _paths(result))


def get_tenant_boundaries(result: dict[str, Any]) -> dict[str, Any]:
    """Tenant/identity boundaries and the crossings observed on paths."""
    graph = _graph(result)
    tenants = sorted(
        {
            str(n.get("tenant"))
            for n in graph.get("nodes") or []
            if n.get("type") == "identity" and n.get("tenant")
        }
    )
    crossings = get_privilege_transitions(result, pattern=PRIV_HORIZONTAL)
    crossing_edges = [
        {
            "from": str(e.get("from")),
            "to": str(e.get("to")),
            "evidence": list(e.get("evidence") or []),
        }
        for e in graph.get("edges") or []
        if e.get("type") == "crosses_tenant"
    ]
    return {
        "tenants": tenants,
        "crossing_transitions": crossings,
        "crossing_edges": crossing_edges,
        "boundary_count": len(tenants),
    }


# ---------------------------------------------------------------------------
# sensitivity
# ---------------------------------------------------------------------------
def get_sensitive_assets(result: dict[str, Any]) -> list[dict[str, Any]]:
    return sensitivity_data.sensitive_assets(_graph(result))


def analyze_path_sensitivity(result: dict[str, Any], path_id: str) -> dict[str, Any]:
    p = _find_path(result, path_id)
    if not p:
        return {"path_id": path_id, "exists": False}
    out = sensitivity_data.analyze_path_sensitivity(p, _graph(result))
    out["exists"] = True
    return out


# ---------------------------------------------------------------------------
# blast / choke / fix
# ---------------------------------------------------------------------------
def get_blast_radius(result: dict[str, Any], node_id: str, **kwargs: Any) -> dict[str, Any]:
    return blast.get_blast_radius(_graph(result), node_id, **kwargs)


def get_choke_points(result: dict[str, Any], *, limit: int = 10) -> list[dict[str, Any]]:
    return choke.get_choke_points(_graph(result), _paths(result), limit=limit)


def analyze_fix_impact(result: dict[str, Any], finding_or_control: Any) -> dict[str, Any]:
    return fix_impact.analyze_fix_impact(_graph(result), _paths(result), finding_or_control)


# ---------------------------------------------------------------------------
# equivalence / explanation / rejection
# ---------------------------------------------------------------------------
def get_equivalent_paths(result: dict[str, Any]) -> list[dict[str, Any]]:
    return equivalence.get_equivalent_paths(_graph(result), _paths(result))


def explain_path(result: dict[str, Any], path_id: str) -> dict[str, Any]:
    p = _find_path(result, path_id)
    if not p:
        return {"path_id": path_id, "verdict": "REQUIRES_REVIEW", "invented": False, "steps": []}
    return explain.explain_path(p, _graph(result))


def get_rejected_path_reason(result: dict[str, Any], path_id: str) -> dict[str, Any]:
    # prefer the precomputed rejected_paths entry if present
    for r in result.get("rejected_paths") or []:
        if str(r.get("path_id")) == str(path_id):
            return r
    p = _find_path(result, path_id)
    if not p:
        return {"path_id": path_id, "status": "UNKNOWN", "summary": "path not found", "reasons": []}
    return explain.rejected_path_reason(p)


# ---------------------------------------------------------------------------
# AI / temporal
# ---------------------------------------------------------------------------
def get_ai_attack_paths(result: dict[str, Any]) -> list[dict[str, Any]]:
    """Paths that end in autonomous tool execution / touch an AI component."""
    graph = _graph(result)
    nodes_by_id = {str(n.get("id")): n for n in graph.get("nodes") or []}
    out: list[dict[str, Any]] = []
    for p in _paths(result):
        tags = set(p.get("tags") or [])
        touches_ai = any(
            (nodes_by_id.get(str(h)) or {}).get("type") in {"ai_component", "tool"}
            for h in p.get("hops") or []
        )
        if {"ai_chain", "prompt_injection"} & tags or touches_ai:
            out.append(p)
    return out


def get_temporal_dependencies(result: dict[str, Any], path_id: str | None = None) -> list[dict[str, Any]]:
    """Light temporal-ordering model: each hop depends on the completion of the
    hop before it (an attacker cannot reach hop N without first achieving hop
    N-1). This is deliberately thin — a full temporal/timing model is out of
    scope for the Part 2 foundation — but it is real and deterministic, not
    fabricated. Returns per-path ordered prerequisites.
    """
    def _for_path(p: dict[str, Any]) -> dict[str, Any]:
        hops = [str(h) for h in p.get("hops") or []]
        deps = [
            {"step": dst, "requires": src, "order": i}
            for i, (src, dst) in enumerate(zip(hops, hops[1:]), 1)
        ]
        return {"path_id": p.get("id"), "ordered": hops, "dependencies": deps}

    if path_id is not None:
        p = _find_path(result, path_id)
        return [_for_path(p)] if p else []
    return [_for_path(p) for p in _paths(result)]
