"""Bounded, deterministic graph search over the attack graph (Phase 6 Part 2).

Part 1 assembles chains from structural detectors. Part 2 adds a *generic*
bounded search over the resulting ``graph.nodes`` / ``graph.edges`` so callers
can ask reachability questions ("is there any evidence-backed path from this
entrypoint to that asset?") without inventing edges.

Guarantees:

* **Bounded** — depth-capped (``MAX_SEARCH_DEPTH``) and result-capped
  (``MAX_SEARCH_RESULTS``); never combinatorially explodes.
* **Evidence-only** — traverses only edges that already exist in the graph.
  It can never create a hop.
* **Prunes impossible / blocked hops** — an edge blocked by an *effective*
  control, or an edge into a ``FALSE_POSITIVE`` / ``INVALID`` finding, is not
  traversed.
* **Deterministic** — neighbours are visited in a stable ``(edge type, to id)``
  order, so results are reproducible.
"""

from __future__ import annotations

from collections import deque
from typing import Any, Callable, Iterable

from engines.attack_graph.schema import (
    EDGE_CONFIRMED,
    EDGE_LIKELY,
    EDGE_UNKNOWN,
    MAX_SEARCH_DEPTH,
    MAX_SEARCH_RESULTS,
)

EdgePredicate = Callable[[dict[str, Any]], bool]

_EDGE_CONF_RANK = {EDGE_UNKNOWN: 0, EDGE_LIKELY: 1, EDGE_CONFIRMED: 2}


def _is_blocked(edge: dict[str, Any]) -> bool:
    """An edge is blocked only when an *effective* (confirmed) control sits on
    it. A named-but-ineffective control does not block traversal.
    """
    blk = edge.get("blocked_by")
    if not blk:
        return False
    return str(blk.get("effectiveness")) == "confirmed" or bool(blk.get("blocks"))


def _node_is_impossible(node: dict[str, Any]) -> bool:
    """A finding node that is FALSE_POSITIVE / INVALID cannot be traversed."""
    if node.get("type") not in {"finding", "candidate_seed"}:
        return False
    return str(node.get("status")) in {"FALSE_POSITIVE", "INVALID"}


class AttackGraphIndex:
    """Adjacency index over a graph dict, with impossible/blocked pruning."""

    def __init__(self, graph: dict[str, Any]) -> None:
        self.nodes: dict[str, dict[str, Any]] = {
            str(n.get("id")): n for n in graph.get("nodes") or []
        }
        self._adj: dict[str, list[dict[str, Any]]] = {}
        for e in graph.get("edges") or []:
            self._adj.setdefault(str(e.get("from")), []).append(e)
        # deterministic neighbour order
        for src in self._adj:
            self._adj[src].sort(key=lambda e: (str(e.get("type")), str(e.get("to"))))

    def neighbors(
        self, node_id: str, *, edge_pred: EdgePredicate | None = None
    ) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        for e in self._adj.get(str(node_id), []):
            if _is_blocked(e):
                continue
            dst = self.nodes.get(str(e.get("to")))
            if dst is not None and _node_is_impossible(dst):
                continue
            if edge_pred is not None and not edge_pred(e):
                continue
            out.append(e)
        return out


def min_confidence_pred(min_conf: str) -> EdgePredicate:
    """Edge predicate: keep edges whose confidence ≥ ``min_conf``."""
    floor = _EDGE_CONF_RANK.get(min_conf, 0)
    return lambda e: _EDGE_CONF_RANK.get(str(e.get("confidence")), 0) >= floor


def bfs_shortest_path(
    graph: dict[str, Any],
    start: str,
    goal: str,
    *,
    max_depth: int = MAX_SEARCH_DEPTH,
    edge_pred: EdgePredicate | None = None,
) -> list[str] | None:
    """Shortest evidence-backed node path from ``start`` to ``goal`` (or None).

    Ties are broken deterministically by neighbour order (stable BFS). Never
    invents an edge; returns ``None`` when no real path exists.
    """
    index = AttackGraphIndex(graph)
    if str(start) == str(goal):
        return [str(start)]
    q: deque[list[str]] = deque([[str(start)]])
    visited: set[str] = {str(start)}
    while q:
        path = q.popleft()
        if len(path) > max_depth:
            continue
        for e in index.neighbors(path[-1], edge_pred=edge_pred):
            nxt = str(e.get("to"))
            if nxt == str(goal):
                return path + [nxt]
            if nxt not in visited:
                visited.add(nxt)
                q.append(path + [nxt])
    return None


def dfs_all_paths(
    graph: dict[str, Any],
    start: str,
    goal: str,
    *,
    max_depth: int = MAX_SEARCH_DEPTH,
    max_results: int = MAX_SEARCH_RESULTS,
    edge_pred: EdgePredicate | None = None,
) -> list[list[str]]:
    """All simple (cycle-free) node paths ``start → goal``, bounded by depth and
    result count. Deterministic order.
    """
    index = AttackGraphIndex(graph)
    results: list[list[str]] = []

    def _walk(path: list[str], visiting: set[str]) -> None:
        if len(results) >= max_results:
            return
        if len(path) > max_depth:
            return
        current = path[-1]
        if current == str(goal) and len(path) > 1:
            results.append(list(path))
            return
        for e in index.neighbors(current, edge_pred=edge_pred):
            nxt = str(e.get("to"))
            if nxt in visiting:
                continue  # no cycles
            visiting.add(nxt)
            _walk(path + [nxt], visiting)
            visiting.discard(nxt)
            if len(results) >= max_results:
                return

    _walk([str(start)], {str(start)})
    return results


def reachable_from(
    graph: dict[str, Any],
    start: str,
    *,
    max_depth: int = MAX_SEARCH_DEPTH,
    max_nodes: int = MAX_SEARCH_RESULTS,
    edge_pred: EdgePredicate | None = None,
) -> list[str]:
    """All node ids reachable from ``start`` via evidence-backed, unblocked
    edges (bounded BFS). Deterministic sorted order. Excludes ``start``.
    """
    index = AttackGraphIndex(graph)
    seen: set[str] = {str(start)}
    q: deque[tuple[str, int]] = deque([(str(start), 0)])
    out: set[str] = set()
    while q and len(out) < max_nodes:
        node, depth = q.popleft()
        if depth >= max_depth:
            continue
        for e in index.neighbors(node, edge_pred=edge_pred):
            nxt = str(e.get("to"))
            if nxt not in seen:
                seen.add(nxt)
                out.add(nxt)
                q.append((nxt, depth + 1))
    return sorted(out)


def edges_on_path(graph: dict[str, Any], node_path: Iterable[str]) -> list[dict[str, Any]]:
    """Resolve the concrete graph edges for a node-id path (only real edges)."""
    idx: dict[tuple[str, str], dict[str, Any]] = {}
    for e in graph.get("edges") or []:
        idx.setdefault((str(e.get("from")), str(e.get("to"))), e)
    hops = list(node_path)
    out: list[dict[str, Any]] = []
    for a, b in zip(hops, hops[1:]):
        e = idx.get((str(a), str(b)))
        if e is not None:
            out.append(e)
    return out
