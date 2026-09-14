"""Fix-impact analysis (Phase 6 Part 2) — analysis only, no code edits.

``analyze_fix_impact(finding_or_control)`` answers: "if I fix this one finding,
or make this one control effective, which attack paths disappear and which are
merely weakened?" It is a pure, read-only projection over the existing graph +
paths — it never edits source, never re-runs the hunters, and never invents a
path.

* Fixing a **finding** (or candidate seed) removes every path that traverses
  that finding node — those chains no longer exist.
* Making a **control** effective *blocks* every path it gates — those chains
  become ``BLOCKED`` (weakened, not necessarily gone: the finding may still be
  reachable by an already-authenticated actor).
"""

from __future__ import annotations

from typing import Any


def _resolve_node(graph: dict[str, Any], node_or_id: Any) -> dict[str, Any] | None:
    if isinstance(node_or_id, dict):
        nid = node_or_id.get("id")
    else:
        nid = node_or_id
    for n in graph.get("nodes") or []:
        if str(n.get("id")) == str(nid):
            return n
    return None


def _paths_through(paths: list[dict[str, Any]], node_id: str) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for p in paths:
        if str(node_id) in [str(h) for h in p.get("hops") or []]:
            out.append(p)
            continue
        if any(str(c.get("id")) == str(node_id) for c in p.get("controls_encountered") or []):
            out.append(p)
    return out


def analyze_fix_impact(
    graph: dict[str, Any],
    paths: list[dict[str, Any]],
    finding_or_control: Any,
) -> dict[str, Any]:
    """Project the effect of fixing one finding / hardening one control.

    ``finding_or_control`` may be a node id or a node dict for a ``finding`` /
    ``candidate_seed`` / ``control`` node. Returns which paths would be
    *removed* vs *weakened*, plus the residual live-path count.
    """
    node = _resolve_node(graph, finding_or_control)
    if node is None:
        nid = finding_or_control.get("id") if isinstance(finding_or_control, dict) else finding_or_control
        return {
            "target": nid,
            "exists": False,
            "kind": None,
            "paths_removed": [],
            "paths_weakened": [],
            "residual_live_paths": [str(p.get("id")) for p in paths if str(p.get("status")) in {"CONFIRMED", "LIKELY", "UNVERIFIED"}],
            "note": "target node not present in graph; nothing to project",
        }

    nid = str(node.get("id"))
    ntype = str(node.get("type"))
    affected = _paths_through(paths, nid)

    removed: list[str] = []
    weakened: list[str] = []
    if ntype in {"finding", "candidate_seed"}:
        # fixing the vulnerability removes any chain that relies on it
        removed = [str(p.get("id")) for p in affected]
        effect = "remove"
        rationale = (
            f"fixing finding `{node.get('label')}` removes every chain that "
            "traverses it (the vulnerability no longer exists)"
        )
    elif ntype == "control":
        # hardening the control blocks the unauthenticated path(s) it gates
        weakened = [str(p.get("id")) for p in affected]
        effect = "block"
        rationale = (
            f"making control `{node.get('label')}` effective blocks the "
            "unauthenticated path(s) it gates (chain becomes BLOCKED; the "
            "finding may still stand for an already-authorised actor)"
        )
    else:
        effect = "none"
        rationale = f"node type `{ntype}` is not a directly remediable finding/control"

    removed_set = set(removed)
    residual = [
        str(p.get("id"))
        for p in paths
        if str(p.get("status")) in {"CONFIRMED", "LIKELY", "UNVERIFIED"}
        and str(p.get("id")) not in removed_set
        and str(p.get("id")) not in set(weakened)
    ]

    return {
        "target": nid,
        "exists": True,
        "kind": ntype,
        "effect": effect,
        "rationale": rationale,
        "paths_removed": sorted(removed_set),
        "paths_weakened": sorted(set(weakened)),
        "affected_path_count": len(affected),
        "residual_live_paths": sorted(set(residual)),
    }


def rank_fixes(
    graph: dict[str, Any], paths: list[dict[str, Any]], *, limit: int = 10
) -> list[dict[str, Any]]:
    """Rank remediable nodes (findings + controls) by how many paths a fix
    removes or weakens. High-leverage fixes first. Deterministic.
    """
    out: list[dict[str, Any]] = []
    for n in graph.get("nodes") or []:
        if n.get("type") not in {"finding", "candidate_seed", "control"}:
            continue
        impact = analyze_fix_impact(graph, paths, n)
        touched = len(impact["paths_removed"]) + len(impact["paths_weakened"])
        if touched == 0:
            continue
        out.append(
            {
                "target": impact["target"],
                "kind": impact["kind"],
                "label": n.get("label"),
                "effect": impact["effect"],
                "paths_removed": impact["paths_removed"],
                "paths_weakened": impact["paths_weakened"],
                "leverage": touched,
            }
        )
    out.sort(key=lambda r: (-r["leverage"], str(r["target"])))
    return out[:limit]
