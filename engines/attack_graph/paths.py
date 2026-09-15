"""Path assembly, de-duplication, limits, and selection.

Chains produced by :mod:`chaining` are already ordered, evidence-backed, and
file-scoped. This module turns them into ``paths[]`` records, merges their
nodes/edges into a single deduplicated graph, dedupes equivalent paths (same
ordered set of finding ids), enforces depth/count limits, and selects the
shortest-credible and highest-impact framing per ``(entry, target)`` pair.
"""

from __future__ import annotations

from typing import Any

from engines.attack_graph import confidence as conf_mod
from engines.attack_graph import scoring
from engines.attack_graph.edges import edge_key
from engines.attack_graph.schema import (
    MAX_PATH_DEPTH,
    MAX_PATHS,
    PATH_TIER_RANK,
)


def _finding_signature(chain: dict[str, Any]) -> tuple[str, ...]:
    return tuple(
        n["id"] for n in chain.get("nodes") or [] if n.get("type") in {"finding", "candidate_seed"}
    )


def assemble(chains: list[dict[str, Any]]) -> dict[str, Any]:
    """Build the graph + paths[] + alternate_paths from raw chains."""
    nodes_by_id: dict[str, dict[str, Any]] = {}
    edges_by_key: dict[tuple[str, str, str], dict[str, Any]] = {}

    # dedupe equivalent paths by finding-id signature
    by_signature: dict[tuple[str, ...], dict[str, Any]] = {}
    alternates: list[dict[str, Any]] = []
    order = 0

    for chain in chains:
        hops = [n["id"] for n in chain.get("nodes") or []]
        if len(hops) > MAX_PATH_DEPTH:
            hops = hops[:MAX_PATH_DEPTH]

        # merge nodes / edges into the shared graph
        for n in chain.get("nodes") or []:
            nodes_by_id.setdefault(n["id"], n)
        for e in chain.get("edges") or []:
            edges_by_key.setdefault(edge_key(e), e)

        status, reasons = conf_mod.derive_status(chain)
        level = conf_mod.path_confidence_level(chain)
        sc = scoring.score_path(chain, status)

        sig = _finding_signature(chain)
        record = {
            "status": status,
            "status_reasons": reasons,
            "confidence_level": level,
            "tags": chain.get("tags") or [],
            "entry": chain.get("entry"),
            "target": chain.get("target"),
            "hops": hops,
            "edge_types": [e.get("type") for e in chain.get("edges") or []],
            "controls_encountered": chain.get("controls_encountered") or [],
            "dead_end": False,
            "score": sc["score"],
            "score_factors": sc["factors"],
            "evidence_refs": _evidence_refs(chain),
        }

        if sig in by_signature:
            # same ordered finding-id set → collapse, note the alternate framing
            existing = by_signature[sig]
            existing.setdefault("also_framed_as", []).append(
                {"entry": record["entry"], "target": record["target"]}
            )
            alternates.append(
                {
                    "of": existing["id"],
                    "entry": record["entry"],
                    "target": record["target"],
                    "note": "same finding-id sequence, alternate (entry, target) framing",
                }
            )
            continue

        order += 1
        record["id"] = f"path-{order:04d}"
        by_signature[sig] = record

    paths = list(by_signature.values())
    paths = _select_and_rank(paths)[:MAX_PATHS]

    return {
        "nodes": list(nodes_by_id.values()),
        "edges": list(edges_by_key.values()),
        "paths": paths,
        "alternate_paths": alternates,
    }


def _select_and_rank(paths: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Mark shortest-credible and highest-impact per (entry, target); rank."""
    groups: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for p in paths:
        groups.setdefault((str(p["entry"]), str(p["target"])), []).append(p)

    for group in groups.values():
        shortest = min(group, key=lambda p: (len(p["hops"]), -PATH_TIER_RANK.get(p["status"], 0)))
        shortest["selection"] = sorted(set(shortest.get("selection", []) + ["shortest_credible"]))
        highest = max(
            group,
            key=lambda p: (PATH_TIER_RANK.get(p["status"], 0), p["score"]),
        )
        highest["selection"] = sorted(set(highest.get("selection", []) + ["highest_impact"]))
        for p in group:
            p.setdefault("selection", [])

    # global ranking: status tier, then score, then fewer hops
    return sorted(
        paths,
        key=lambda p: (
            -PATH_TIER_RANK.get(p["status"], 0),
            -p["score"],
            len(p["hops"]),
            p["id"],
        ),
    )


def _evidence_refs(chain: dict[str, Any]) -> list[dict[str, Any]]:
    refs: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for n in chain.get("nodes") or []:
        for r in n.get("refs") or []:
            key = (str(r.get("source")), str(r.get("id")))
            if r.get("id") and key not in seen:
                seen.add(key)
                refs.append(r)
    return refs
