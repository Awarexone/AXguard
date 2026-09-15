"""Auditable investigation graph: Candidate → Question → Action → Evidence → Decision."""

from __future__ import annotations

from typing import Any
from uuid import uuid4


def _node(kind: str, label: str, **extra: Any) -> dict[str, Any]:
    return {
        "id": f"n.{uuid4().hex[:10]}",
        "kind": kind,
        "label": label,
        **extra,
    }


def ensure_candidate_node(investigation: dict[str, Any]) -> str:
    graph = investigation.setdefault("graph", {"nodes": [], "edges": []})
    for n in graph["nodes"]:
        if n.get("kind") == "candidate":
            return str(n["id"])
    node = _node(
        "candidate",
        str(investigation.get("candidate_id") or "candidate"),
        candidate_id=investigation.get("candidate_id"),
    )
    graph["nodes"].append(node)
    return str(node["id"])


def add_edge(
    investigation: dict[str, Any],
    source: str,
    target: str,
    *,
    relation: str,
) -> None:
    graph = investigation.setdefault("graph", {"nodes": [], "edges": []})
    graph["edges"].append(
        {
            "id": f"e.{uuid4().hex[:8]}",
            "source": source,
            "target": target,
            "relation": relation,
        }
    )


def record_question_node(
    investigation: dict[str, Any], question: dict[str, Any], parent_id: str
) -> str:
    graph = investigation.setdefault("graph", {"nodes": [], "edges": []})
    node = _node(
        "question",
        str(question.get("text") or question.get("question_id")),
        question_id=question.get("question_id"),
        status=question.get("status"),
    )
    graph["nodes"].append(node)
    add_edge(investigation, parent_id, node["id"], relation="asks")
    return str(node["id"])


def record_action_node(
    investigation: dict[str, Any], action: dict[str, Any], parent_id: str
) -> str:
    graph = investigation.setdefault("graph", {"nodes": [], "edges": []})
    node = _node(
        "action",
        str(action.get("type")),
        action_id=action.get("action_id"),
        cost=action.get("cost"),
        status=action.get("status"),
    )
    graph["nodes"].append(node)
    add_edge(investigation, parent_id, node["id"], relation="investigates")
    return str(node["id"])


def record_evidence_nodes(
    investigation: dict[str, Any],
    items: list[dict[str, Any]],
    parent_id: str,
    *,
    kind: str,
) -> None:
    graph = investigation.setdefault("graph", {"nodes": [], "edges": []})
    for item in items:
        node = _node(
            kind,
            str(item.get("summary") or item.get("kind")),
            evidence_id=item.get("evidence_id"),
            strength=item.get("strength"),
        )
        graph["nodes"].append(node)
        add_edge(
            investigation,
            parent_id,
            node["id"],
            relation="yields_counter" if kind == "counter_evidence" else "yields_evidence",
        )


def record_decision_node(investigation: dict[str, Any], parent_id: str) -> str:
    graph = investigation.setdefault("graph", {"nodes": [], "edges": []})
    node = _node(
        "decision",
        str(investigation.get("decision") or "UNDECIDED"),
        termination_reason=investigation.get("termination_reason"),
        status=investigation.get("status"),
    )
    graph["nodes"].append(node)
    add_edge(investigation, parent_id, node["id"], relation="decides")
    return str(node["id"])
