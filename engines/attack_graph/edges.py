"""Attack-graph edge factory.

Edges always carry ``confidence`` (Phase 1-5 vocabulary: ``confirmed`` /
``likely`` / ``unknown``) and an ``evidence`` list — never a bare boolean. An
edge annotated with a ``blocked_by`` control also records that control's
effectiveness so a reader can tell "blocked" from "co-located".
"""

from __future__ import annotations

from typing import Any

from engines.attack_graph.schema import (
    EDGE_CONFIRMED,
    EDGE_LIKELY,
    EDGE_TYPES,
    EDGE_UNKNOWN,
)

_STATUS_TO_EDGE_CONF = {
    "CONFIRMED": EDGE_CONFIRMED,
    "LIKELY": EDGE_LIKELY,
    "UNVERIFIED": EDGE_UNKNOWN,
    "REQUIRES_REVIEW": EDGE_UNKNOWN,
    "FALSE_POSITIVE": EDGE_UNKNOWN,
    "INVALID": EDGE_UNKNOWN,
}


def status_to_edge_confidence(status: str | None) -> str:
    return _STATUS_TO_EDGE_CONF.get(str(status or ""), EDGE_UNKNOWN)


def make_edge(
    edge_type: str,
    src: str,
    dst: str,
    *,
    confidence: str = EDGE_UNKNOWN,
    evidence: list[dict[str, Any]] | None = None,
    preconditions: list[dict[str, Any]] | None = None,
    blocked_by: dict[str, Any] | None = None,
) -> dict[str, Any]:
    etype = edge_type if edge_type in EDGE_TYPES else "chains_to"
    conf = confidence if confidence in {EDGE_CONFIRMED, EDGE_LIKELY, EDGE_UNKNOWN} else EDGE_UNKNOWN
    edge: dict[str, Any] = {
        "type": etype,
        "from": src,
        "to": dst,
        "confidence": conf,
        "evidence": evidence or [],
        "preconditions": preconditions or [],
    }
    if blocked_by is not None:
        edge["blocked_by"] = blocked_by
    return edge


def edge_key(edge: dict[str, Any]) -> tuple[str, str, str]:
    return (str(edge.get("type")), str(edge.get("from")), str(edge.get("to")))
