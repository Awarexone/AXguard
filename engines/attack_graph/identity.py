"""Identity model + identity transitions (Phase 6 Part 2).

An attack path is not only a sequence of *findings* — it is also a sequence of
*identities* the attacker occupies: they start as the anonymous internet
(``ATTACKER``), maybe authenticate as a low-priv user, maybe escalate to admin
(``PRIVILEGED_USER``), maybe pivot into another tenant (``TENANT_USER``), maybe
end up executing as an autonomous agent (``AI_AGENT``).

This module classifies the identity nodes/entrypoints already in the graph and
derives **evidence-backed** identity transitions along each path. It invents no
identity: a transition is emitted only when a real edge (``escalates_to`` /
``crosses_tenant`` / ``invokes``) or an authenticated entrypoint justifies it,
and it carries that edge's evidence.
"""

from __future__ import annotations

from typing import Any

from engines.attack_graph.schema import (
    ID_AI_AGENT,
    ID_ANONYMOUS,
    ID_ATTACKER,
    ID_AUTHENTICATED_USER,
    ID_PRIVILEGED_USER,
    ID_SYSTEM,
    ID_TENANT_USER,
    ID_UNKNOWN,
    IDENTITY_PRIV_RANK,
)


# ---------------------------------------------------------------------------
# classification
# ---------------------------------------------------------------------------
def classify_identity_node(node: dict[str, Any]) -> str:
    """Map an ``identity`` graph node onto an identity type."""
    if not node:
        return ID_UNKNOWN
    if node.get("type") == "ai_component":
        return ID_AI_AGENT
    role = str(node.get("role") or "").lower()
    kind = str(node.get("kind") or "").lower()
    if role in {"admin", "administrator", "root", "superuser"}:
        return ID_PRIVILEGED_USER
    if kind == "tenant" or node.get("tenant"):
        return ID_TENANT_USER
    if role in {"user", "member", "customer"}:
        return ID_AUTHENTICATED_USER
    return ID_UNKNOWN


def entry_identity(entry_node: dict[str, Any]) -> str:
    """The identity an attacker holds when they *first* reach an entrypoint,
    based on its reachability (never over-claimed).
    """
    if not entry_node:
        return ID_UNKNOWN
    reach = str(entry_node.get("reachability") or "unknown").lower()
    if reach in {"public", "unauthenticated"}:
        return ID_ATTACKER  # anonymous internet actor
    if reach == "authenticated":
        return ID_AUTHENTICATED_USER  # attacker already holds a low-priv session
    if reach in {"internal", "queue", "requires_prior_compromise"}:
        return ID_SYSTEM
    return ID_UNKNOWN


def elevation(from_id: str, to_id: str) -> str:
    """Describe a transition relative to the privilege ordering."""
    a = IDENTITY_PRIV_RANK.get(from_id, 0)
    b = IDENTITY_PRIV_RANK.get(to_id, 0)
    if b > a:
        return "elevating"
    if b < a:
        return "lowering"
    return "lateral"


# ---------------------------------------------------------------------------
# transitions along a path
# ---------------------------------------------------------------------------
def _edge_index(graph: dict[str, Any]) -> dict[tuple[str, str], dict[str, Any]]:
    idx: dict[tuple[str, str], dict[str, Any]] = {}
    for e in graph.get("edges") or []:
        idx.setdefault((str(e.get("from")), str(e.get("to"))), e)
    return idx


def get_path_identities(path: dict[str, Any], graph: dict[str, Any]) -> list[str]:
    """Ordered, de-duplicated list of identities the attacker occupies along a
    path (starting identity first). Deterministic.
    """
    transitions = path_identity_transitions(path, graph)
    seq: list[str] = []
    for t in transitions:
        for ident in (t["from_identity"], t["to_identity"]):
            if not seq or seq[-1] != ident:
                seq.append(ident)
    return seq


def path_identity_transitions(path: dict[str, Any], graph: dict[str, Any]) -> list[dict[str, Any]]:
    """Evidence-backed identity transitions for a single path."""
    nodes_by_id = {n.get("id"): n for n in graph.get("nodes") or []}
    edges = _edge_index(graph)
    hops = [h for h in (path.get("hops") or [])]

    # starting identity from the first entrypoint on the path
    current = ID_ANONYMOUS
    for h in hops:
        n = nodes_by_id.get(h) or {}
        if n.get("type") == "entrypoint":
            current = entry_identity(n)
            break

    out: list[dict[str, Any]] = []
    for src, dst in zip(hops, hops[1:]):
        edge = edges.get((str(src), str(dst)))
        if not edge:
            continue
        etype = edge.get("type")
        dst_node = nodes_by_id.get(dst) or {}
        to_id: str | None = None

        if dst_node.get("type") in {"identity", "ai_component"}:
            to_id = classify_identity_node(dst_node)
        elif etype == "escalates_to":
            to_id = ID_PRIVILEGED_USER
        elif etype == "crosses_tenant":
            to_id = ID_TENANT_USER
        elif etype == "invokes":
            to_id = ID_AI_AGENT
        elif etype == "yields":
            # a privileged tool executes in the host/system context
            to_id = ID_SYSTEM

        if to_id is None or to_id == current:
            continue
        out.append(
            {
                "path_id": path.get("id"),
                "from_identity": current,
                "to_identity": to_id,
                "via_edge": etype,
                "from_node": src,
                "to_node": dst,
                "elevation": elevation(current, to_id),
                "evidence": list(edge.get("evidence") or []),
            }
        )
        current = to_id
    return out


def derive_identity_transitions(graph: dict[str, Any], paths: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """All identity transitions across all paths (deterministic order)."""
    out: list[dict[str, Any]] = []
    for p in paths:
        out.extend(path_identity_transitions(p, graph))
    return out
