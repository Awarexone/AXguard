"""Sensitive-data categorisation + impact weighting (Phase 6 Part 2).

Classifies the *asset* a path reaches into a sensitivity category
(``PUBLIC … SECRET … AI_CONTEXT … UNKNOWN``) and attaches an impact weight in
``[0, 1]``. This is an **impact** dimension only — it is not a confidence and
not a severity, and it never upgrades a path's status. Categorisation is
evidence-backed: it reads the ``asset.kind`` already established by Phase 1 /
the attack-graph structural detectors, and falls back to ``UNKNOWN`` (low
weight) rather than guessing high.
"""

from __future__ import annotations

from typing import Any

from engines.attack_graph.schema import (
    ASSET_KIND_TO_SENSITIVITY,
    SENS_AI_CONTEXT,
    SENS_UNKNOWN,
    SENSITIVITY_IMPACT,
)


def categorize_kind(kind: str | None) -> str:
    """Map an ``asset.kind`` onto a sensitivity category (UNKNOWN if unmapped)."""
    return ASSET_KIND_TO_SENSITIVITY.get(str(kind or "").lower(), SENS_UNKNOWN)


def impact_weight(category: str) -> float:
    """Impact multiplier in ``[0, 1]`` for a sensitivity category."""
    return SENSITIVITY_IMPACT.get(str(category), SENSITIVITY_IMPACT[SENS_UNKNOWN])


def categorize_node(node: dict[str, Any]) -> str:
    """Sensitivity of a single node. ``ai_component`` / ``tool`` nodes expose
    the model instruction context, categorised as ``AI_CONTEXT``.
    """
    ntype = node.get("type")
    if ntype in {"ai_component", "tool"}:
        return SENS_AI_CONTEXT
    if ntype in {"asset", "candidate_seed"}:
        return categorize_kind(node.get("kind"))
    return categorize_kind(node.get("kind"))


def sensitive_assets(graph: dict[str, Any]) -> list[dict[str, Any]]:
    """List asset-like nodes with their sensitivity category + impact weight,
    deterministically ordered by descending impact then id. Only nodes that
    already exist in the graph are returned (never invented).
    """
    out: list[dict[str, Any]] = []
    for n in graph.get("nodes") or []:
        if n.get("type") not in {"asset", "ai_component", "tool"}:
            continue
        cat = categorize_node(n)
        out.append(
            {
                "id": n.get("id"),
                "label": n.get("label"),
                "type": n.get("type"),
                "kind": n.get("kind"),
                "category": cat,
                "impact_weight": impact_weight(cat),
                "location": n.get("location") or {},
            }
        )
    return sorted(out, key=lambda a: (-a["impact_weight"], str(a["id"])))


def analyze_path_sensitivity(path: dict[str, Any], graph: dict[str, Any]) -> dict[str, Any]:
    """Sensitivity summary for one path: the category of its target asset plus
    the max sensitivity of any node it touches.
    """
    nodes_by_id = {n.get("id"): n for n in graph.get("nodes") or []}
    target = path.get("target")
    target_node = nodes_by_id.get(target) or {}
    target_cat = categorize_node(target_node) if target_node else SENS_UNKNOWN

    touched: list[dict[str, Any]] = []
    for h in path.get("hops") or []:
        n = nodes_by_id.get(h)
        if not n or n.get("type") not in {"asset", "ai_component", "tool"}:
            continue
        cat = categorize_node(n)
        touched.append({"id": h, "category": cat, "impact_weight": impact_weight(cat)})

    max_cat = target_cat
    max_weight = impact_weight(target_cat)
    for t in touched:
        if t["impact_weight"] > max_weight:
            max_weight = t["impact_weight"]
            max_cat = t["category"]

    return {
        "path_id": path.get("id"),
        "target": target,
        "target_category": target_cat,
        "target_impact_weight": impact_weight(target_cat),
        "max_category": max_cat,
        "max_impact_weight": max_weight,
        "sensitive_nodes": touched,
    }
