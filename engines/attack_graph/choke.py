"""Choke-point / minimal-cut heuristics (Phase 6 Part 2).

A *choke point* is a node (a finding, a control, an identity, an agent, a
shared entrypoint) that sits on many attack paths at once. Fixing a choke point
is high-leverage: one change removes or weakens several paths. This is the dual
of blast radius — instead of "what does one compromise expose," it answers
"what one fix cuts the most paths."

The heuristic is deliberately simple and transparent: count how many distinct
paths each intermediate node appears on (path-betweenness), score controls a
little higher because remediating a control is usually the cheapest fix, and
rank deterministically. It is a *heuristic minimal cut*, not an exact min-cut
solver — advertised as such.
"""

from __future__ import annotations

from typing import Any

# nodes that are not meaningful choke points (endpoints / the internet root)
_SKIP_TYPES = {"trust_boundary"}


def get_choke_points(
    graph: dict[str, Any],
    paths: list[dict[str, Any]],
    *,
    limit: int = 10,
    min_paths: int = 2,
) -> list[dict[str, Any]]:
    """Rank nodes by how many distinct paths they lie on.

    Only nodes that appear on ``min_paths`` or more paths are returned (a node
    on a single path is not a choke point). A ``control``/``finding`` node is
    weighted slightly higher because it is the natural remediation target.
    """
    nodes_by_id = {str(n.get("id")): n for n in graph.get("nodes") or []}
    counts: dict[str, set[str]] = {}

    for p in paths:
        pid = str(p.get("id"))
        seen_in_path: set[str] = set()
        for h in p.get("hops") or []:
            node = nodes_by_id.get(str(h)) or {}
            if node.get("type") in _SKIP_TYPES:
                continue
            seen_in_path.add(str(h))
        # controls that gate a path are also candidates (may not be a hop)
        for c in p.get("controls_encountered") or []:
            if c.get("id"):
                seen_in_path.add(str(c["id"]))
        for nid in seen_in_path:
            counts.setdefault(nid, set()).add(pid)

    scored: list[dict[str, Any]] = []
    for nid, pids in counts.items():
        if len(pids) < min_paths:
            continue
        node = nodes_by_id.get(nid) or {}
        ntype = str(node.get("type") or "unknown")
        # remediation-target weighting: control > finding/seed > everything else
        weight = 1.0
        if ntype == "control":
            weight = 1.5
        elif ntype in {"finding", "candidate_seed"}:
            weight = 1.25
        scored.append(
            {
                "id": nid,
                "type": ntype,
                "label": node.get("label"),
                "path_count": len(pids),
                "path_ids": sorted(pids),
                "choke_score": round(len(pids) * weight, 3),
                "location": node.get("location") or {},
            }
        )

    scored.sort(key=lambda c: (-c["choke_score"], -c["path_count"], str(c["id"])))
    return scored[:limit]


def minimal_cut(graph: dict[str, Any], paths: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Greedy heuristic set-cover: pick choke points that together cover the
    most paths, until all live paths are covered (or no candidate remains).

    Returns the ordered list of nodes forming the heuristic cut. This is a
    greedy approximation, not a guaranteed minimum cut.
    """
    all_path_ids = {str(p.get("id")) for p in paths}
    remaining = set(all_path_ids)
    # consider *every* candidate node (min_paths=1, no top-N truncation) so the
    # greedy cover can always reach a full cover of the live paths.
    candidates = get_choke_points(
        graph, paths, limit=len(graph.get("nodes") or []) + 1, min_paths=1
    )
    cut: list[dict[str, Any]] = []
    # index candidate → covered path ids
    cover = {c["id"]: set(c["path_ids"]) for c in candidates}
    cand_by_id = {c["id"]: c for c in candidates}

    while remaining and cover:
        # pick the candidate covering the most still-uncovered paths; tie-break
        # by remediation-target rank (control first) then id ascending.
        best_id = min(
            cover,
            key=lambda cid: (
                -len(cover[cid] & remaining),
                _type_rank(cand_by_id[cid]),
                str(cid),
            ),
        )
        gained = cover[best_id] & remaining
        if not gained:
            break
        entry = dict(cand_by_id[best_id])
        entry["covers"] = sorted(gained)
        cut.append(entry)
        remaining -= gained
        del cover[best_id]

    return cut


def _type_rank(node: dict[str, Any]) -> int:
    """Prefer cutting controls, then findings, in tie-breaks (lower == better)."""
    t = str(node.get("type"))
    if t == "control":
        return 0
    if t in {"finding", "candidate_seed"}:
        return 1
    return 2
