"""Equivalence grouping — paths that share a root cause (Phase 6 Part 2).

Several enumerated paths often reduce to the *same underlying bug*: different
entrypoints reaching the same vulnerable sink, or the same mass-assignment
finding surfaced via two admin routes. Reporting them as N independent paths
inflates the count and buries the single fix that kills them all.

This module groups paths into equivalence classes. Two paths are equivalent
when they share a finding / candidate-seed node, or when Part 1 already linked
them via ``shares_root_cause_with`` (adversary ``root_cause`` clustering). Each
group names a representative (the highest-status, shortest path) and the shared
finding node(s) — the natural single fix target.
"""

from __future__ import annotations

from typing import Any

from engines.attack_graph.schema import PATH_TIER_RANK


class _UnionFind:
    def __init__(self, items: list[str]) -> None:
        self.parent = {i: i for i in items}

    def find(self, x: str) -> str:
        while self.parent[x] != x:
            self.parent[x] = self.parent[self.parent[x]]
            x = self.parent[x]
        return x

    def union(self, a: str, b: str) -> None:
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            # deterministic: smaller id becomes the root
            root, child = sorted((ra, rb))
            self.parent[child] = root


def _finding_hops(path: dict[str, Any], nodes_by_id: dict[str, dict[str, Any]]) -> list[str]:
    out: list[str] = []
    for h in path.get("hops") or []:
        n = nodes_by_id.get(str(h)) or {}
        if n.get("type") in {"finding", "candidate_seed"}:
            out.append(str(h))
    return out


def get_equivalent_paths(graph: dict[str, Any], paths: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Return equivalence groups of paths sharing a root cause.

    Each group: ``{"root_cause_key", "path_ids", "representative",
    "shared_findings", "size"}``. Deterministic ordering.
    """
    nodes_by_id = {str(n.get("id")): n for n in graph.get("nodes") or []}
    by_id = {str(p.get("id")): p for p in paths}
    ids = sorted(by_id)
    if not ids:
        return []

    uf = _UnionFind(ids)

    # link paths that share a finding node
    finding_to_paths: dict[str, list[str]] = {}
    for pid in ids:
        for fh in _finding_hops(by_id[pid], nodes_by_id):
            finding_to_paths.setdefault(fh, []).append(pid)
    for members in finding_to_paths.values():
        for other in members[1:]:
            uf.union(members[0], other)

    # link paths connected via Part 1 root-cause clustering
    for pid in ids:
        for other in by_id[pid].get("shares_root_cause_with") or []:
            if str(other) in uf.parent:
                uf.union(pid, str(other))

    groups: dict[str, list[str]] = {}
    for pid in ids:
        groups.setdefault(uf.find(pid), []).append(pid)

    out: list[dict[str, Any]] = []
    for root, members in groups.items():
        members = sorted(members)
        shared_findings = sorted(
            {
                fh
                for pid in members
                for fh in _finding_hops(by_id[pid], nodes_by_id)
            }
        )
        representative = _representative(members, by_id)
        out.append(
            {
                "root_cause_key": _root_cause_key(shared_findings, nodes_by_id, root),
                "path_ids": members,
                "representative": representative,
                "shared_findings": shared_findings,
                "size": len(members),
            }
        )

    out.sort(key=lambda g: (-g["size"], str(g["representative"])))
    return out


def _representative(members: list[str], by_id: dict[str, dict[str, Any]]) -> str:
    """Highest-status, then shortest, then lowest id."""
    def key(pid: str) -> tuple[int, int, str]:
        p = by_id[pid]
        return (-PATH_TIER_RANK.get(str(p.get("status")), 0), len(p.get("hops") or []), pid)

    return sorted(members, key=key)[0]


def _root_cause_key(
    shared_findings: list[str], nodes_by_id: dict[str, dict[str, Any]], fallback: str
) -> str:
    """A stable, human-meaningful key for the group's root cause."""
    for fh in shared_findings:
        n = nodes_by_id.get(fh) or {}
        rc = n.get("root_cause")
        if isinstance(rc, dict) and (rc.get("symbol") or rc.get("file")):
            return str(rc.get("symbol") or f"{rc.get('file')}:{rc.get('line')}")
        if n.get("kind"):
            return f"{n.get('kind')}@{(n.get('location') or {}).get('file')}"
    return f"group:{fallback}"
