"""Build a Security Twin from attack-graph + application-model artifacts."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from engines.twin.schema import (
    AG_EDGE_TO_REL,
    AG_NODE_TO_ENTITY,
    ASSET_KIND_TO_ENTITY,
    ENTITY_AI_AGENT,
    ENTITY_AI_MODEL,
    ENTITY_AI_TOOL,
    ENTITY_APPLICATION,
    ENTITY_DATABASE,
    ENTITY_ENDPOINT,
    ENTITY_EXTERNAL_SERVICE,
    ENTITY_MCP_SERVER,
    ENTITY_REPOSITORY,
    ENTITY_SECURITY_CONTROL,
    ENTITY_SECRET,
    ENTITY_CREDENTIAL,
    LAYER_INFERRED,
    LAYER_OBSERVED,
    PERM_UNKNOWN,
    SECURITY_TWIN_VERSION,
    empty_twin,
    tagged,
)


def build_security_twin(
    target: Path,
    *,
    attack_graph: dict[str, Any] | None = None,
    application_model: dict[str, Any] | None = None,
    dataflow: dict[str, Any] | None = None,
    evidence: dict[str, Any] | None = None,
    adversary: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Construct a symbolic Security Twin for ``target``.

    Reuses ``run_attack_graph`` and ``build_application_model`` — never
    duplicates graph construction or path chaining.
    """
    root = Path(target).resolve()
    twin = empty_twin(root)
    twin["generated_at"] = datetime.now(timezone.utc).isoformat()
    twin["schema_version"] = SECURITY_TWIN_VERSION

    if attack_graph is None:
        from engines.attack_graph import run_attack_graph

        attack_graph = run_attack_graph(root, evidence=evidence)

    if application_model is None:
        application_model = _resolve_application_model(attack_graph, root)

    if dataflow is None:
        dataflow = _resolve_dataflow(attack_graph)

    if evidence is None:
        evidence = attack_graph.get("_evidence")

    if adversary is None and evidence:
        adversary = (evidence.get("_adversary") or {}) if isinstance(evidence, dict) else None

    entities: list[dict[str, Any]] = []
    relationships: list[dict[str, Any]] = []
    seen_entity_ids: set[str] = set()

    if application_model:
        _add_application_entity(application_model, entities, seen_entity_ids)
        _add_repo_entity(root, entities, seen_entity_ids)
        _add_from_app_model(application_model, entities, relationships, seen_entity_ids)

    if attack_graph:
        _add_from_attack_graph(attack_graph, entities, relationships, seen_entity_ids)

    twin["entities"] = entities
    twin["relationships"] = relationships
    twin["attack_graph"] = attack_graph
    twin["application_model"] = application_model
    twin["dataflow"] = dataflow
    twin["evidence"] = evidence
    twin["adversary"] = adversary
    twin["summary"] = _build_summary(entities, relationships, attack_graph)
    twin["meta"] = {
        "attack_graph_version": (attack_graph or {}).get("schema_version"),
        "application_model_present": application_model is not None,
        "dataflow_present": dataflow is not None,
        "evidence_present": evidence is not None,
    }
    return twin


def _resolve_application_model(ag: dict[str, Any], root: Path) -> dict[str, Any] | None:
    meta = ag.get("meta") or {}
    if meta.get("application_model_present"):
        ev = ag.get("_evidence") or {}
        adv = ev.get("_adversary") or {}
        ver = adv.get("_verification") or {}
        model = ver.get("_application_model")
        if model:
            return model
    try:
        from engines.app_model import build_application_model

        return build_application_model(root)
    except Exception:  # noqa: BLE001
        return None


def _resolve_dataflow(ag: dict[str, Any]) -> dict[str, Any] | None:
    ev = ag.get("_evidence") or {}
    adv = ev.get("_adversary") or {}
    ver = adv.get("_verification") or {}
    return ver.get("_dataflow")


def _add_application_entity(model: dict[str, Any], entities: list, seen: set) -> None:
    app = model.get("application") or {}
    eid = "application:root"
    if eid in seen:
        return
    seen.add(eid)
    entities.append(
        {
            "id": eid,
            "type": ENTITY_APPLICATION,
            "name": tagged(app.get("name") or "unknown", LAYER_OBSERVED),
            "frameworks": tagged(app.get("frameworks") or [], LAYER_OBSERVED),
            "languages": tagged(app.get("languages") or [], LAYER_OBSERVED),
            "layer": LAYER_OBSERVED,
        }
    )


def _add_repo_entity(root: Path, entities: list, seen: set) -> None:
    eid = "repository:root"
    if eid in seen:
        return
    seen.add(eid)
    entities.append(
        {
            "id": eid,
            "type": ENTITY_REPOSITORY,
            "path": tagged(str(root), LAYER_OBSERVED),
            "layer": LAYER_OBSERVED,
        }
    )


def _add_from_app_model(
    model: dict[str, Any],
    entities: list,
    relationships: list,
    seen: set,
) -> None:
    for i, ep in enumerate(model.get("entrypoints") or []):
        eid = f"endpoint:app:{i}:{ep.get('method')}:{ep.get('path')}"
        if eid not in seen:
            seen.add(eid)
            entities.append(
                {
                    "id": eid,
                    "type": ENTITY_ENDPOINT,
                    "method": tagged(ep.get("method"), LAYER_OBSERVED, evidence=[ep.get("evidence")]),
                    "path": tagged(ep.get("path"), LAYER_OBSERVED),
                    "authentication": tagged(
                        (ep.get("authentication") or {}).get("status", "unknown"),
                        LAYER_OBSERVED if (ep.get("authentication") or {}).get("status") != "unknown"
                        else LAYER_INFERRED,
                    ),
                    "layer": LAYER_OBSERVED,
                    "source": "application_model",
                }
            )

    for i, ctrl in enumerate(model.get("security_controls") or []):
        eid = f"control:app:{i}:{ctrl.get('name', 'control')}"
        if eid not in seen:
            seen.add(eid)
            entities.append(
                {
                    "id": eid,
                    "type": ENTITY_SECURITY_CONTROL,
                    "name": tagged(ctrl.get("name"), LAYER_OBSERVED),
                    "kind": tagged(ctrl.get("kind"), LAYER_OBSERVED),
                    "layer": LAYER_OBSERVED,
                    "source": "application_model",
                }
            )

    for i, ai in enumerate(model.get("ai_components") or []):
        kind = str(ai.get("kind") or "unknown").lower()
        etype = ENTITY_MCP_SERVER if "mcp" in kind else (
            ENTITY_AI_MODEL if "model" in kind or "llm" in kind else ENTITY_AI_AGENT
        )
        eid = f"ai:app:{i}:{kind}:{ai.get('file')}"
        if eid not in seen:
            seen.add(eid)
            entities.append(
                {
                    "id": eid,
                    "type": etype,
                    "name": tagged(ai.get("name") or kind, LAYER_OBSERVED),
                    "permissions": tagged([], LAYER_INFERRED),
                    "permission_class": tagged(PERM_UNKNOWN, LAYER_INFERRED),
                    "layer": LAYER_OBSERVED,
                    "source": "application_model",
                    "evidence": [ai.get("evidence")] if ai.get("evidence") else [],
                }
            )

    for i, ext in enumerate(model.get("external_services") or []):
        eid = f"external:app:{i}:{ext.get('name', 'service')}"
        if eid not in seen:
            seen.add(eid)
            entities.append(
                {
                    "id": eid,
                    "type": ENTITY_EXTERNAL_SERVICE,
                    "name": tagged(ext.get("name"), LAYER_OBSERVED),
                    "layer": LAYER_OBSERVED,
                    "source": "application_model",
                }
            )

    graph = model.get("graph") or {}
    for edge in graph.get("edges") or []:
        rel = AG_EDGE_TO_REL.get(str(edge.get("type")), edge.get("type"))
        relationships.append(
            {
                "source": edge.get("source"),
                "target": edge.get("target"),
                "name": rel,
                "layer": LAYER_OBSERVED,
                "confidence": edge.get("confidence"),
                "source_artifact": "application_model",
            }
        )


def _add_from_attack_graph(
    ag: dict[str, Any],
    entities: list,
    relationships: list,
    seen: set,
) -> None:
    graph = ag.get("graph") or {}
    for node in graph.get("nodes") or []:
        nid = str(node.get("id"))
        if nid in seen:
            continue
        seen.add(nid)
        ntype = str(node.get("type") or "unknown")
        etype = AG_NODE_TO_ENTITY.get(ntype, ENTITY_APPLICATION)
        if ntype == "asset":
            kind = str(node.get("kind") or "unknown")
            etype = ASSET_KIND_TO_ENTITY.get(kind, etype)
        if ntype == "ai_component":
            label = str(node.get("label") or "").lower()
            if "mcp" in label:
                etype = ENTITY_MCP_SERVER
            elif "model" in label or "llm" in label:
                etype = ENTITY_AI_MODEL

        entity: dict[str, Any] = {
            "id": nid,
            "type": etype,
            "label": tagged(node.get("label"), LAYER_OBSERVED),
            "layer": LAYER_OBSERVED,
            "source": "attack_graph",
            "ag_type": ntype,
        }
        if node.get("kind"):
            entity["kind"] = tagged(node.get("kind"), LAYER_OBSERVED)
        if node.get("reachability"):
            entity["reachability"] = tagged(node.get("reachability"), LAYER_OBSERVED)
        if ntype == "tool":
            entity["permission_class"] = tagged(PERM_UNKNOWN, LAYER_INFERRED)
        entities.append(entity)

    for edge in graph.get("edges") or []:
        rel = AG_EDGE_TO_REL.get(str(edge.get("type")), str(edge.get("type")))
        relationships.append(
            {
                "source": edge.get("from") or edge.get("source"),
                "target": edge.get("to") or edge.get("target"),
                "name": rel,
                "layer": LAYER_OBSERVED,
                "confidence": edge.get("confidence"),
                "source_artifact": "attack_graph",
                "ag_edge_type": edge.get("type"),
            }
        )


def _build_summary(
    entities: list[dict[str, Any]],
    relationships: list[dict[str, Any]],
    ag: dict[str, Any] | None,
) -> dict[str, Any]:
    paths = (ag or {}).get("paths") or []
    observed = sum(1 for p in paths if str(p.get("status")) in {"CONFIRMED", "LIKELY", "UNVERIFIED"})
    blocked = sum(1 for p in paths if str(p.get("status")) == "BLOCKED")
    return {
        "entity_count": len(entities),
        "relationship_count": len(relationships),
        "observed_path_count": observed,
        "simulated_path_count": 0,
        "blocked_path_count": blocked,
        "control_count": sum(1 for e in entities if e.get("type") == ENTITY_SECURITY_CONTROL),
        "ai_agent_count": sum(1 for e in entities if e.get("type") == ENTITY_AI_AGENT),
        "ai_tool_count": sum(1 for e in entities if e.get("type") == ENTITY_AI_TOOL),
        "mcp_server_count": sum(1 for e in entities if e.get("type") == ENTITY_MCP_SERVER),
        "secret_count": sum(1 for e in entities if e.get("type") in {ENTITY_SECRET, ENTITY_CREDENTIAL}),
        "database_count": sum(1 for e in entities if e.get("type") == ENTITY_DATABASE),
        "attack_graph_path_count": len(paths),
    }
