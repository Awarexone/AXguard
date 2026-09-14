"""Plain-language path explanation (Phase 6 Part 2).

Turns an existing attack path into a readable narrative built **only** from
evidence that already lives on its nodes and edges. Like ``llm_stub.py``, this
explainer can never invent a node, edge, credential, impact or reachability
claim — every sentence is anchored to an evidence record's ``description`` and
its ``file:line`` reference. It also renders the *reason a path was rejected*
(BLOCKED / INVALID / filtered by mode) in plain language.
"""

from __future__ import annotations

from typing import Any

from engines.attack_graph.schema import (
    PATH_BLOCKED,
    PATH_INVALID,
    PATH_UNVERIFIED,
)


def _edge_index(graph: dict[str, Any]) -> dict[tuple[str, str], dict[str, Any]]:
    idx: dict[tuple[str, str], dict[str, Any]] = {}
    for e in graph.get("edges") or []:
        idx.setdefault((str(e.get("from")), str(e.get("to"))), e)
    return idx


def _ev_phrase(evidence: list[dict[str, Any]] | None) -> tuple[str, dict[str, Any] | None]:
    """First evidence description + its location ref (or a neutral fallback)."""
    for ev in evidence or []:
        desc = ev.get("description")
        if desc:
            ref = {"file": ev.get("file"), "line": ev.get("line"), "type": ev.get("type")}
            return str(desc), ref
    return "", None


def explain_path(path: dict[str, Any], graph: dict[str, Any]) -> dict[str, Any]:
    """Return a deterministic, evidence-anchored explanation of ``path``.

    The ``steps`` list restates each hop using its edge's evidence; the
    ``narrative`` joins them. Nothing is asserted that is not backed by an
    evidence record already present in the graph.
    """
    nodes_by_id = {str(n.get("id")): n for n in graph.get("nodes") or []}
    edges = _edge_index(graph)
    hops = [str(h) for h in path.get("hops") or []]

    if not hops:
        return {
            "path_id": path.get("id"),
            "verdict": "REQUIRES_REVIEW",
            "narrative": "No hops to explain (nothing invented).",
            "steps": [],
            "invented": False,
        }

    steps: list[dict[str, Any]] = []
    for src, dst in zip(hops, hops[1:]):
        edge = edges.get((src, dst)) or {}
        src_node = nodes_by_id.get(src) or {}
        dst_node = nodes_by_id.get(dst) or {}
        phrase, ref = _ev_phrase(edge.get("evidence"))
        steps.append(
            {
                "from": src,
                "to": dst,
                "from_label": src_node.get("label") or src,
                "to_label": dst_node.get("label") or dst,
                "edge_type": edge.get("type"),
                "confidence": edge.get("confidence"),
                "evidence": phrase,
                "ref": ref,
            }
        )

    sentences: list[str] = []
    for i, s in enumerate(steps, 1):
        verb = _edge_verb(s["edge_type"])
        base = f"{i}. `{s['from_label']}` {verb} `{s['to_label']}`"
        if s["evidence"]:
            base += f": {s['evidence']}"
        if s["ref"] and s["ref"].get("file"):
            base += f" (evidence: {s['ref']['file']}:{s['ref'].get('line')})"
        sentences.append(base)

    return {
        "path_id": path.get("id"),
        "status": path.get("status"),
        "verdict": "EXPLAINED",
        "narrative": "\n".join(sentences),
        "steps": steps,
        "invented": False,
    }


_EDGE_VERBS = {
    "reaches": "is reachable from",
    "triggers": "triggers",
    "exposes": "exposes",
    "escalates_to": "escalates to",
    "crosses_tenant": "crosses tenant into",
    "invokes": "invokes",
    "yields": "yields",
    "blocked_by": "is blocked by",
    "chains_to": "chains to",
}


def _edge_verb(edge_type: str | None) -> str:
    return _EDGE_VERBS.get(str(edge_type), "connects to")


def rejected_path_reason(path: dict[str, Any], mode: str | None = None) -> dict[str, Any]:
    """Plain-language reason a path is not a live attack path.

    Uses the path's own ``status`` + ``status_reasons`` (already computed in
    Part 1) rather than re-deriving anything.
    """
    status = str(path.get("status"))
    reasons = list(path.get("status_reasons") or [])
    if status == PATH_BLOCKED:
        summary = "Blocked: an effective control on a required edge stops the unauthenticated path."
    elif status == PATH_INVALID:
        summary = "Invalid: a hop is FALSE_POSITIVE or the findings are only co-located (no real link)."
    elif status == PATH_UNVERIFIED:
        summary = "Unverified: a hop's reachability or link is unknown — surfaced for review, not asserted."
    else:
        summary = f"Rejected under status `{status}`."

    return {
        "path_id": path.get("id"),
        "status": status,
        "summary": summary,
        "reasons": reasons,
    }


def rejected_paths(
    paths: list[dict[str, Any]],
    *,
    include_unverified: bool = False,
) -> list[dict[str, Any]]:
    """Collect rejected paths (BLOCKED / INVALID, optionally UNVERIFIED) with
    plain-language reasons. Deterministic order (by path id).
    """
    rejected_statuses = {PATH_BLOCKED, PATH_INVALID}
    if include_unverified:
        rejected_statuses = rejected_statuses | {PATH_UNVERIFIED}
    out = [
        rejected_path_reason(p)
        for p in paths
        if str(p.get("status")) in rejected_statuses
    ]
    return sorted(out, key=lambda r: str(r["path_id"]))
