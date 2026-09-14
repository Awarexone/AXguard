"""Blast radius from a compromised node (Phase 6 Part 2).

Given a node that an attacker has reached (a compromised entrypoint, finding,
identity, agent or asset), the *blast radius* is everything else reachable from
it over **evidence-backed, unblocked** edges. This answers "if this one thing
falls, what else is exposed?" using only edges that already exist in the graph
— it never invents a downstream hop for drama.

The result groups the reachable nodes by type and reports the maximum data
sensitivity reachable, so a reader can see the true impact of a single
compromise.
"""

from __future__ import annotations

from typing import Any

from engines.attack_graph import search, sensitivity_data
from engines.attack_graph.schema import MAX_BLAST_NODES, SENS_UNKNOWN, SENSITIVITY_IMPACT


def get_blast_radius(
    graph: dict[str, Any],
    node_id: str,
    *,
    max_depth: int | None = None,
    max_nodes: int = MAX_BLAST_NODES,
) -> dict[str, Any]:
    """Compute the evidence-backed blast radius from ``node_id``.

    Returns the reachable node ids grouped by type, the reachable sensitive
    assets (with categories), the single most-sensitive category reachable, and
    a short list of representative shortest paths to each reachable asset.
    """
    nodes_by_id = {str(n.get("id")): n for n in graph.get("nodes") or []}
    origin = nodes_by_id.get(str(node_id))
    if origin is None:
        return {
            "origin": node_id,
            "exists": False,
            "reachable": [],
            "by_type": {},
            "reachable_assets": [],
            "max_sensitivity": SENS_UNKNOWN,
            "max_impact_weight": 0.0,
            "node_count": 0,
            "paths_to_assets": [],
        }

    depth = max_depth if max_depth is not None else search.MAX_SEARCH_DEPTH
    reachable = search.reachable_from(graph, str(node_id), max_depth=depth, max_nodes=max_nodes)

    by_type: dict[str, list[str]] = {}
    reachable_assets: list[dict[str, Any]] = []
    max_cat = SENS_UNKNOWN
    max_weight = 0.0
    for rid in reachable:
        rnode = nodes_by_id.get(rid) or {}
        rtype = str(rnode.get("type") or "unknown")
        by_type.setdefault(rtype, []).append(rid)
        if rtype in {"asset", "ai_component", "tool"}:
            cat = sensitivity_data.categorize_node(rnode)
            weight = sensitivity_data.impact_weight(cat)
            reachable_assets.append(
                {"id": rid, "label": rnode.get("label"), "category": cat, "impact_weight": weight}
            )
            if weight > max_weight:
                max_weight = weight
                max_cat = cat

    paths_to_assets: list[dict[str, Any]] = []
    for a in sorted(reachable_assets, key=lambda x: (-x["impact_weight"], str(x["id"])))[:10]:
        node_path = search.bfs_shortest_path(graph, str(node_id), str(a["id"]), max_depth=depth)
        if node_path:
            paths_to_assets.append(
                {"asset": a["id"], "category": a["category"], "hops": node_path}
            )

    for t in by_type:
        by_type[t] = sorted(by_type[t])

    return {
        "origin": node_id,
        "exists": True,
        "reachable": reachable,
        "by_type": by_type,
        "reachable_assets": sorted(
            reachable_assets, key=lambda x: (-x["impact_weight"], str(x["id"]))
        ),
        "max_sensitivity": max_cat,
        "max_impact_weight": max_weight,
        "node_count": len(reachable),
        "paths_to_assets": paths_to_assets,
    }


def rank_blast_origins(graph: dict[str, Any], *, limit: int = 10) -> list[dict[str, Any]]:
    """Rank candidate compromise origins (entrypoints / findings / identities)
    by the size + sensitivity of their blast radius. Deterministic.
    """
    out: list[dict[str, Any]] = []
    for n in graph.get("nodes") or []:
        if n.get("type") not in {"entrypoint", "finding", "candidate_seed", "identity", "ai_component"}:
            continue
        radius = get_blast_radius(graph, str(n.get("id")))
        if radius["node_count"] == 0:
            continue
        out.append(
            {
                "origin": n.get("id"),
                "type": n.get("type"),
                "label": n.get("label"),
                "node_count": radius["node_count"],
                "max_sensitivity": radius["max_sensitivity"],
                "max_impact_weight": radius["max_impact_weight"],
            }
        )
    out.sort(key=lambda r: (-r["max_impact_weight"], -r["node_count"], str(r["origin"])))
    return out[:limit]
