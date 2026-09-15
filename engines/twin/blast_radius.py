"""Entity blast-radius wrapper with impact classification."""

from __future__ import annotations

from typing import Any

from engines.attack_graph import blast
from engines.twin.schema import (
    IMPACT_DATA,
    IMPACT_DEPENDENCY,
    IMPACT_DIRECT,
    IMPACT_INDIRECT,
    IMPACT_PRIVILEGE,
    IMPACT_TENANT,
    LAYER_INFERRED,
    LAYER_OBSERVED,
    tagged,
)


def entity_blast_radius(twin: dict[str, Any], entity_id: str) -> dict[str, Any]:
    """Wrap ``blast.get_blast_radius`` with twin entity resolution and impact tags."""
    ag = twin.get("attack_graph") or {}
    graph = ag.get("graph") or {"nodes": [], "edges": []}
    resolved_id = resolve_entity_id(twin, entity_id)

    raw = blast.get_blast_radius(graph, resolved_id)
    impacts = _classify_impacts(raw, graph)

    entity = _find_entity(twin, resolved_id)
    return {
        "entity_id": resolved_id,
        "requested_id": entity_id,
        "entity": entity,
        "blast": raw,
        "impact_classifications": impacts,
        "layer": LAYER_OBSERVED if raw.get("exists") else LAYER_INFERRED,
        "evidence_note": (
            "Blast radius computed from evidence-backed edges in attack graph only."
            if raw.get("exists")
            else f"Entity {entity_id!r} not found in graph; alias resolution attempted."
        ),
    }


def resolve_entity_id(twin: dict[str, Any], entity_id: str) -> str:
    """Resolve aliases like ``agent:foo`` to attack-graph node ids."""
    eid = str(entity_id).strip()
    ag = twin.get("attack_graph") or {}
    graph = ag.get("graph") or {}
    nodes_by_id = {str(n.get("id")): n for n in graph.get("nodes") or []}

    if eid in nodes_by_id:
        return eid

    # Search twin entities
    for ent in twin.get("entities") or []:
        if str(ent.get("id")) == eid:
            return eid
        label = ent.get("label") or ent.get("name")
        if isinstance(label, dict):
            label = label.get("value")
        if label and eid.endswith(str(label).split(":")[-1]):
            return str(ent.get("id"))

    # Prefix alias: agent:foo → ai_component nodes
    if ":" in eid:
        prefix, suffix = eid.split(":", 1)
        slug = suffix.lower().replace("-", "_")
        type_hint = {
            "agent": "ai_component",
            "tool": "tool",
            "endpoint": "entrypoint",
            "control": "control",
            "asset": "asset",
        }.get(prefix.lower())

        for nid, node in nodes_by_id.items():
            if type_hint and node.get("type") != type_hint:
                continue
            label = str(node.get("label") or "").lower()
            if slug in label.replace("-", "_") or slug in nid.lower():
                return nid

    return eid


def _find_entity(twin: dict[str, Any], entity_id: str) -> dict[str, Any] | None:
    for ent in twin.get("entities") or []:
        if str(ent.get("id")) == entity_id:
            return ent
    return None


def _classify_impacts(raw: dict[str, Any], graph: dict[str, Any]) -> list[dict[str, Any]]:
    if not raw.get("exists"):
        return []

    nodes_by_id = {str(n.get("id")): n for n in graph.get("nodes") or []}
    impacts: list[dict[str, Any]] = []

    for asset in raw.get("reachable_assets") or []:
        cat = str(asset.get("category") or "UNKNOWN")
        kind = IMPACT_DATA
        if cat in {"CREDENTIAL", "SECRET"}:
            kind = IMPACT_PRIVILEGE
        impacts.append(
            {
                "asset_id": asset.get("id"),
                "impact_kind": tagged(kind, LAYER_OBSERVED),
                "category": tagged(cat, LAYER_OBSERVED),
                "weight": tagged(asset.get("impact_weight"), LAYER_OBSERVED),
            }
        )

    by_type = raw.get("by_type") or {}
    if by_type.get("identity"):
        impacts.append(
            {"impact_kind": tagged(IMPACT_PRIVILEGE, LAYER_INFERRED), "note": "Reachable identities"}
        )
    if by_type.get("external_service"):
        impacts.append(
            {"impact_kind": tagged(IMPACT_DEPENDENCY, LAYER_INFERRED), "note": "External services"}
        )
    if by_type.get("entrypoint"):
        impacts.append(
            {"impact_kind": tagged(IMPACT_INDIRECT, LAYER_INFERRED), "note": "Additional entrypoints"}
        )

    if raw.get("node_count", 0) <= 1:
        impacts.append({"impact_kind": tagged(IMPACT_DIRECT, LAYER_OBSERVED), "note": "Origin only"})

    tenant_nodes = [
        nid for nid in raw.get("reachable") or []
        if (nodes_by_id.get(nid) or {}).get("tenant")
    ]
    if tenant_nodes:
        impacts.append(
            {"impact_kind": tagged(IMPACT_TENANT, LAYER_INFERRED), "tenant_nodes": tenant_nodes}
        )

    return impacts
