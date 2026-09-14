"""Privilege-transition analysis (Phase 6 Part 2).

Builds a privilege-transition graph from the identity transitions on each path
and classifies each transition as one of three well-known patterns:

* ``vertical``        — a lower role becomes a higher one (user → admin).
* ``horizontal``      — same tier, different scope (tenant-A → tenant-B).
* ``confused_deputy`` — a *trusted* component performs a privileged action on
  the attacker's behalf: SSRF (the server fetches an internal resource for the
  attacker) or an agent that invokes a privileged tool from injected
  instructions.

Every detected transition is evidence-backed (it carries the justifying edge's
evidence) and is derived only from edges that already exist in the graph.
"""

from __future__ import annotations

from typing import Any

from engines.attack_graph import identity as identity_mod
from engines.attack_graph.schema import (
    ID_PRIVILEGED_USER,
    IDENTITY_PRIV_RANK,
    PRIV_CONFUSED_DEPUTY,
    PRIV_HORIZONTAL,
    PRIV_VERTICAL,
)


def _edge_index(graph: dict[str, Any]) -> dict[tuple[str, str], dict[str, Any]]:
    idx: dict[tuple[str, str], dict[str, Any]] = {}
    for e in graph.get("edges") or []:
        idx.setdefault((str(e.get("from")), str(e.get("to"))), e)
    return idx


def _path_edges(path: dict[str, Any], graph: dict[str, Any]) -> list[dict[str, Any]]:
    idx: dict[tuple[str, str], dict[str, Any]] = {}
    for e in graph.get("edges") or []:
        idx.setdefault((str(e.get("from")), str(e.get("to"))), e)
    hops = [str(h) for h in path.get("hops") or []]
    out: list[dict[str, Any]] = []
    for a, b in zip(hops, hops[1:]):
        e = idx.get((a, b))
        if e is not None:
            out.append(e)
    return out


def _is_confused_deputy_path(path: dict[str, Any], graph: dict[str, Any]) -> dict[str, Any] | None:
    """Return the deputy edge (with its evidence) if the path routes a
    privileged action through a *trusted* intermediary on the attacker's behalf.

    Two well-known shapes, both detected only from the path's own edges:
    * SSRF — the server is the confused deputy: an ``ssrf_chain`` path where a
      finding ``triggers`` an internal entrypoint the attacker cannot reach
      directly (the server fetches the internal resource for them).
    * Agent — a tool-calling agent ``invokes`` a privileged tool from injected
      instructions (the agent acts on the attacker's behalf).
    """
    nodes_by_id = {str(n.get("id")): n for n in graph.get("nodes") or []}
    tags = set(path.get("tags") or [])
    path_edges = _path_edges(path, graph)

    # Agent invokes a privileged tool from injected instructions.
    for e in path_edges:
        if e.get("type") == "invokes":
            src = nodes_by_id.get(str(e.get("from"))) or {}
            if src.get("type") == "ai_component":
                return {"kind": "agent_tool", "edge": e}

    # SSRF: a finding/seed triggers an internal entrypoint on the same app.
    if {"ssrf_chain"} & tags:
        for e in path_edges:
            src = nodes_by_id.get(str(e.get("from"))) or {}
            dst = nodes_by_id.get(str(e.get("to"))) or {}
            if (
                e.get("type") == "triggers"
                and src.get("type") in {"finding", "candidate_seed"}
                and dst.get("type") == "entrypoint"
            ):
                return {"kind": "ssrf", "edge": e}
    return None


def path_privilege_transitions(path: dict[str, Any], graph: dict[str, Any]) -> list[dict[str, Any]]:
    """Privilege-transition records for one path."""
    out: list[dict[str, Any]] = []
    id_transitions = identity_mod.path_identity_transitions(path, graph)

    for t in id_transitions:
        pattern: str | None = None
        if t["via_edge"] == "crosses_tenant" or t["to_identity"] == "TENANT_USER":
            pattern = PRIV_HORIZONTAL
        elif t["via_edge"] == "escalates_to" or (
            IDENTITY_PRIV_RANK.get(t["to_identity"], 0) > IDENTITY_PRIV_RANK.get(t["from_identity"], 0)
            and t["to_identity"] == ID_PRIVILEGED_USER
        ):
            pattern = PRIV_VERTICAL
        if pattern is None:
            continue
        out.append(
            {
                "path_id": path.get("id"),
                "pattern": pattern,
                "from_identity": t["from_identity"],
                "to_identity": t["to_identity"],
                "via_edge": t["via_edge"],
                "from_node": t["from_node"],
                "to_node": t["to_node"],
                "evidence": t["evidence"],
            }
        )

    deputy = _is_confused_deputy_path(path, graph)
    if deputy:
        e = deputy["edge"]
        out.append(
            {
                "path_id": path.get("id"),
                "pattern": PRIV_CONFUSED_DEPUTY,
                "from_identity": id_transitions[0]["from_identity"] if id_transitions else "ATTACKER",
                "to_identity": "SYSTEM" if deputy["kind"] == "ssrf" else "AI_AGENT",
                "via_edge": e.get("type"),
                "from_node": e.get("from"),
                "to_node": e.get("to"),
                "deputy_kind": deputy["kind"],
                "evidence": list(e.get("evidence") or []),
            }
        )
    return out


def derive_privilege_transitions(graph: dict[str, Any], paths: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """All privilege transitions across all paths (deterministic order)."""
    out: list[dict[str, Any]] = []
    for p in paths:
        out.extend(path_privilege_transitions(p, graph))
    return out


def get_privilege_transitions(
    graph: dict[str, Any], paths: list[dict[str, Any]], *, pattern: str | None = None
) -> list[dict[str, Any]]:
    """Public helper: all privilege transitions, optionally filtered by pattern."""
    transitions = derive_privilege_transitions(graph, paths)
    if pattern is None:
        return transitions
    return [t for t in transitions if t["pattern"] == pattern]


def get_confused_deputy_paths(graph: dict[str, Any], paths: list[dict[str, Any]]) -> list[str]:
    """Path ids that contain a confused-deputy transition (deterministic)."""
    ids: list[str] = []
    for p in paths:
        for t in path_privilege_transitions(p, graph):
            if t["pattern"] == PRIV_CONFUSED_DEPUTY:
                ids.append(str(p.get("id")))
                break
    return sorted(set(ids))


def privilege_graph(graph: dict[str, Any], paths: list[dict[str, Any]]) -> dict[str, Any]:
    """A small graph of identity → identity privilege edges (deduplicated)."""
    transitions = derive_privilege_transitions(graph, paths)
    nodes: set[str] = set()
    edges: dict[tuple[str, str, str], dict[str, Any]] = {}
    for t in transitions:
        nodes.add(t["from_identity"])
        nodes.add(t["to_identity"])
        key = (t["from_identity"], t["to_identity"], t["pattern"])
        edges.setdefault(
            key,
            {
                "from": t["from_identity"],
                "to": t["to_identity"],
                "pattern": t["pattern"],
                "path_ids": [],
            },
        )["path_ids"].append(t["path_id"])
    edge_list = []
    for e in edges.values():
        e["path_ids"] = sorted(set(str(i) for i in e["path_ids"]))
        edge_list.append(e)
    return {
        "nodes": sorted(nodes),
        "edges": sorted(edge_list, key=lambda e: (e["from"], e["to"], e["pattern"])),
    }
