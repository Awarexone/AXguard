"""Application state model + state transitions (Phase 6 Part 2).

Beyond *who* the attacker is (see ``identity.py``), a path moves the
application through a sequence of **states**: unauthenticated → authenticated →
authorized → privileged / tenant-scoped → (tool execution) → compromised.

State is inferred **lightly** and only from code-visible signals already in the
graph: an authenticated entrypoint, a control node (middleware/guard) sitting
on the path, an ``escalates_to`` / ``crosses_tenant`` / ``invokes`` edge, or a
reached asset. When there is no code-visible guard, the state stays ``UNKNOWN``
rather than being invented. Each transition carries the evidence that justified
it.
"""

from __future__ import annotations

from typing import Any

from engines.attack_graph.schema import (
    STATE_AUTHENTICATED,
    STATE_AUTHORIZED,
    STATE_COMPROMISED,
    STATE_PRIVILEGED,
    STATE_TENANT_SCOPED,
    STATE_TOOL_EXECUTION,
    STATE_UNAUTHENTICATED,
    STATE_UNKNOWN,
)


def entry_state(entry_node: dict[str, Any]) -> str:
    """Initial application state at an entrypoint, from its reachability/auth."""
    if not entry_node:
        return STATE_UNKNOWN
    reach = str(entry_node.get("reachability") or "unknown").lower()
    auth = str(entry_node.get("authentication") or "unknown").lower()
    if reach in {"public", "unauthenticated"}:
        return STATE_UNAUTHENTICATED
    if reach == "authenticated" or auth == "required":
        return STATE_AUTHENTICATED
    return STATE_UNKNOWN


def _edge_index(graph: dict[str, Any]) -> dict[tuple[str, str], dict[str, Any]]:
    idx: dict[tuple[str, str], dict[str, Any]] = {}
    for e in graph.get("edges") or []:
        idx.setdefault((str(e.get("from")), str(e.get("to"))), e)
    return idx


def path_state_transitions(path: dict[str, Any], graph: dict[str, Any]) -> list[dict[str, Any]]:
    """Evidence-backed state transitions for one path."""
    nodes_by_id = {n.get("id"): n for n in graph.get("nodes") or []}
    edges = _edge_index(graph)
    hops = list(path.get("hops") or [])

    current = STATE_UNKNOWN
    for h in hops:
        n = nodes_by_id.get(h) or {}
        if n.get("type") == "entrypoint":
            current = entry_state(n)
            break

    out: list[dict[str, Any]] = []
    for src, dst in zip(hops, hops[1:]):
        edge = edges.get((str(src), str(dst)))
        if not edge:
            continue
        etype = edge.get("type")
        dst_node = nodes_by_id.get(dst) or {}
        dtype = dst_node.get("type")
        to_state: str | None = None

        if etype == "escalates_to":
            to_state = STATE_PRIVILEGED
        elif etype == "crosses_tenant":
            to_state = STATE_TENANT_SCOPED
        elif etype == "invokes":
            to_state = STATE_TOOL_EXECUTION
        elif dtype == "control":
            # a guard on the path establishes an authorization checkpoint
            to_state = STATE_AUTHORIZED
        elif dtype in {"asset"} and etype in {"exposes", "yields", "crosses_tenant"}:
            to_state = STATE_COMPROMISED

        if to_state is None or to_state == current:
            continue
        out.append(
            {
                "path_id": path.get("id"),
                "from_state": current,
                "to_state": to_state,
                "via_edge": etype,
                "from_node": src,
                "to_node": dst,
                "evidence": list(edge.get("evidence") or []),
            }
        )
        current = to_state

    # Terminal: reaching the target asset is a COMPROMISED state even if the
    # last edge type wasn't matched above (evidence = the target node's own).
    target = path.get("target")
    target_node = nodes_by_id.get(target) or {}
    if target_node.get("type") in {"asset", "tool"} and current != STATE_COMPROMISED:
        out.append(
            {
                "path_id": path.get("id"),
                "from_state": current,
                "to_state": STATE_COMPROMISED,
                "via_edge": "reaches_asset",
                "from_node": hops[-2] if len(hops) >= 2 else target,
                "to_node": target,
                "evidence": list(target_node.get("evidence") or []),
            }
        )
    return out


def get_path_state(path: dict[str, Any], graph: dict[str, Any]) -> str:
    """The final application state a path lands in (terminal state)."""
    transitions = path_state_transitions(path, graph)
    if transitions:
        return transitions[-1]["to_state"]
    # no transition — fall back to the entry state
    nodes_by_id = {n.get("id"): n for n in graph.get("nodes") or []}
    for h in path.get("hops") or []:
        n = nodes_by_id.get(h) or {}
        if n.get("type") == "entrypoint":
            return entry_state(n)
    return STATE_UNKNOWN


def derive_state_transitions(graph: dict[str, Any], paths: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """All state transitions across all paths (deterministic order)."""
    out: list[dict[str, Any]] = []
    for p in paths:
        out.extend(path_state_transitions(p, graph))
    return out
