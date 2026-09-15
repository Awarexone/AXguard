"""Attack-surface graph construction and query helpers."""

from __future__ import annotations

from typing import Any

from engines.app_model.schema import CONFIDENCE_LIKELY, CONFIDENCE_UNKNOWN, evidence


def build_graph(model: dict[str, Any]) -> dict[str, Any]:
    """Build nodes/edges from model inventories; link by co-location when no taint."""
    nodes: list[dict[str, Any]] = []
    edges: list[dict[str, Any]] = []
    node_ids: set[str] = set()

    def add_node(nid: str, ntype: str, label: str, extra: dict[str, Any] | None = None) -> None:
        if nid in node_ids:
            return
        node_ids.add(nid)
        node = {"id": nid, "type": ntype, "label": label}
        if extra:
            node.update(extra)
        nodes.append(node)

    def add_edge(
        source: str,
        target: str,
        etype: str,
        *,
        confidence: str = CONFIDENCE_LIKELY,
        ev: dict[str, Any] | None = None,
    ) -> None:
        edges.append(
            {
                "source": source,
                "target": target,
                "type": etype,
                "confidence": confidence,
                "evidence": ev or evidence(reason=etype),
            }
        )

    add_node("boundary:internet", "trust_boundary", "Internet")
    add_node("app:root", "application", model.get("application", {}).get("name") or "application")

    for i, ep in enumerate(model.get("entrypoints") or []):
        nid = f"entrypoint:{i}:{ep.get('method')}:{ep.get('path')}"
        add_node(
            nid,
            "entrypoint",
            f"{ep.get('method')} {ep.get('path')}",
            {
                "file": ep.get("file"),
                "line": ep.get("line"),
                "authentication": ep.get("authentication"),
                "authorization": ep.get("authorization"),
                "confidence": ep.get("confidence"),
                "evidence": ep.get("evidence"),
            },
        )
        auth = (ep.get("authentication") or {}).get("status", "unknown")
        add_edge(
            "boundary:internet",
            nid,
            "reaches",
            confidence=ep.get("confidence", CONFIDENCE_LIKELY),
            ev=ep.get("evidence"),
        )
        add_edge(nid, "app:root", "handled_by", confidence=CONFIDENCE_LIKELY, ev=ep.get("evidence"))
        if auth in {"unknown", "none"}:
            add_edge(
                nid,
                "app:root",
                "unauthenticated_or_unknown",
                confidence=CONFIDENCE_UNKNOWN if auth == "unknown" else CONFIDENCE_LIKELY,
                ev=ep.get("evidence"),
            )

    for i, sink in enumerate(model.get("sinks") or []):
        nid = f"sink:{i}:{sink.get('type')}:{sink.get('file')}:{sink.get('line')}"
        add_node(
            nid,
            "sink",
            f"{sink.get('type')}:{sink.get('symbol')}",
            {
                "sink_type": sink.get("type"),
                "file": sink.get("file"),
                "line": sink.get("line"),
                "confidence": sink.get("confidence"),
                "evidence": sink.get("evidence"),
            },
        )
        # Co-locate with entrypoints in the same file
        for j, ep in enumerate(model.get("entrypoints") or []):
            if ep.get("file") and ep.get("file") == sink.get("file"):
                ep_id = f"entrypoint:{j}:{ep.get('method')}:{ep.get('path')}"
                add_edge(
                    ep_id,
                    nid,
                    "co_located",
                    confidence=CONFIDENCE_LIKELY,
                    ev=evidence(
                        sink.get("file"),
                        sink.get("line"),
                        reason="Entrypoint and sink share file (no full taint)",
                    ),
                )

    for i, asset in enumerate(model.get("assets") or []):
        nid = f"asset:{i}:{asset.get('kind')}:{asset.get('name')}"
        add_node(
            nid,
            "asset",
            str(asset.get("name")),
            {
                "kind": asset.get("kind"),
                "file": asset.get("location"),
                "confidence": asset.get("confidence"),
                "evidence": asset.get("evidence"),
            },
        )
        add_edge("app:root", nid, "holds", confidence=asset.get("confidence", CONFIDENCE_LIKELY), ev=asset.get("evidence"))

    for i, svc in enumerate(model.get("external_services") or []):
        nid = f"external:{i}:{svc.get('name')}"
        add_node(
            nid,
            "external_service",
            str(svc.get("name")),
            {
                "category": svc.get("category"),
                "confidence": svc.get("confidence"),
                "evidence": svc.get("evidence"),
            },
        )
        add_edge(
            "app:root",
            nid,
            "calls",
            confidence=svc.get("confidence", CONFIDENCE_LIKELY),
            ev=svc.get("evidence"),
        )

    for i, ai in enumerate(model.get("ai_components") or []):
        nid = f"ai:{i}:{ai.get('name')}"
        add_node(
            nid,
            "ai_component",
            str(ai.get("name")),
            {
                "kind": ai.get("kind"),
                "file": ai.get("file"),
                "confidence": ai.get("confidence"),
                "evidence": ai.get("evidence"),
            },
        )
        add_edge("app:root", nid, "uses", confidence=ai.get("confidence", CONFIDENCE_LIKELY), ev=ai.get("evidence"))

    for i, ctrl in enumerate(model.get("security_controls") or []):
        nid = f"control:{i}:{ctrl.get('name')}"
        add_node(
            nid,
            "security_control",
            str(ctrl.get("name")),
            {
                "control_type": ctrl.get("type"),
                "confidence": ctrl.get("confidence"),
                "evidence": ctrl.get("evidence"),
            },
        )

    for i, tb in enumerate(model.get("trust_boundaries") or []):
        nid = f"trust:{i}:{tb.get('from')}:{tb.get('to')}"
        add_node(
            nid,
            "trust_boundary",
            f"{tb.get('from')} → {tb.get('to')}",
            {"confidence": tb.get("confidence"), "evidence": tb.get("evidence")},
        )

    return {"nodes": nodes, "edges": edges}


def build_trust_boundaries(model: dict[str, Any]) -> list[dict[str, Any]]:
    """Derive conservative trust boundaries from entrypoints / deps / AI."""
    boundaries: list[dict[str, Any]] = []

    for ep in model.get("entrypoints") or []:
        auth = (ep.get("authentication") or {}).get("status", "unknown")
        if auth in {"unknown", "none"}:
            boundaries.append(
                {
                    "from": "external_user",
                    "to": "internal",
                    "entrypoint": f"{ep.get('method')} {ep.get('path')}",
                    "confidence": CONFIDENCE_UNKNOWN if auth == "unknown" else CONFIDENCE_LIKELY,
                    "evidence": ep.get("evidence")
                    or evidence(ep.get("file"), ep.get("line"), reason="HTTP entrypoint auth unknown/none"),
                }
            )

    if any(a.get("kind") == "database" for a in model.get("assets") or []) or model.get("application", {}).get(
        "databases"
    ):
        boundaries.append(
            {
                "from": "application",
                "to": "database",
                "entrypoint": None,
                "confidence": CONFIDENCE_LIKELY,
                "evidence": evidence(reason="Database dependency or asset present"),
            }
        )

    if model.get("external_services"):
        boundaries.append(
            {
                "from": "application",
                "to": "external",
                "entrypoint": None,
                "confidence": CONFIDENCE_LIKELY,
                "evidence": evidence(reason="External service integrations detected"),
            }
        )

    ai = model.get("ai_components") or []
    if any(str(x.get("kind", "")).startswith("tool") or x.get("kind") in {"mcp", "agent_framework", "tool_calling"} for x in ai):
        boundaries.append(
            {
                "from": "agent",
                "to": "tool",
                "entrypoint": None,
                "confidence": CONFIDENCE_LIKELY,
                "evidence": evidence(reason="AI tool/agent/MCP component detected"),
            }
        )

    return boundaries


def build_data_flows(model: dict[str, Any]) -> list[dict[str, Any]]:
    """Best-effort co-location flows: entrypoint file → sink in same file."""
    flows: list[dict[str, Any]] = []
    for ep in model.get("entrypoints") or []:
        for sink in model.get("sinks") or []:
            if ep.get("file") and ep.get("file") == sink.get("file"):
                flows.append(
                    {
                        "source": {
                            "kind": "entrypoint",
                            "method": ep.get("method"),
                            "path": ep.get("path"),
                            "file": ep.get("file"),
                        },
                        "sink": {
                            "kind": "sink",
                            "type": sink.get("type"),
                            "symbol": sink.get("symbol"),
                            "file": sink.get("file"),
                            "line": sink.get("line"),
                        },
                        "confidence": CONFIDENCE_LIKELY,
                        "evidence": evidence(
                            sink.get("file"),
                            sink.get("line"),
                            reason="Same-file entrypoint→sink co-location (not full taint)",
                        ),
                    }
                )
    return flows


def build_call_graph(model: dict[str, Any]) -> list[dict[str, Any]]:
    """Sparse call graph: entrypoint → handler symbol when known."""
    out: list[dict[str, Any]] = []
    for ep in model.get("entrypoints") or []:
        if not ep.get("handler"):
            continue
        out.append(
            {
                "source": f"{ep.get('method')} {ep.get('path')}",
                "calls": [ep.get("handler")],
                "file": ep.get("file"),
                "line": ep.get("line"),
                "confidence": ep.get("confidence", CONFIDENCE_LIKELY),
                "evidence": ep.get("evidence"),
            }
        )
    return out


def query_graph(model: dict[str, Any], question_key: str) -> list[Any]:
    """
    Best-effort graph queries for future skills.

    Supported keys:
      inputs_to_network_sinks
      endpoints_auth_unknown
      endpoints_unauthenticated
      ai_components
      external_services
      sensitive_assets
    """
    graph = model.get("graph") or {}
    nodes = graph.get("nodes") or []
    edges = graph.get("edges") or []

    if question_key == "endpoints_auth_unknown":
        return [
            n
            for n in nodes
            if n.get("type") == "entrypoint"
            and (n.get("authentication") or {}).get("status", "unknown") == "unknown"
        ]

    if question_key == "endpoints_unauthenticated":
        return [
            n
            for n in nodes
            if n.get("type") == "entrypoint"
            and (n.get("authentication") or {}).get("status") == "none"
        ]

    if question_key == "ai_components":
        return [n for n in nodes if n.get("type") == "ai_component"] or list(
            model.get("ai_components") or []
        )

    if question_key == "external_services":
        return [n for n in nodes if n.get("type") == "external_service"] or list(
            model.get("external_services") or []
        )

    if question_key == "sensitive_assets":
        assets = [
            n
            for n in nodes
            if n.get("type") == "asset"
            and n.get("kind") in {"secret", "database", "credential", "token"}
        ]
        return assets or [
            a
            for a in (model.get("assets") or [])
            if a.get("kind") in {"secret", "database", "credential", "token"}
        ]

    if question_key == "inputs_to_network_sinks":
        results: list[dict[str, Any]] = []
        sink_ids = {
            n["id"]
            for n in nodes
            if n.get("type") == "sink" and n.get("sink_type") in {"http", "sql", "exec", "fs"}
        }
        ep_by_id = {n["id"]: n for n in nodes if n.get("type") == "entrypoint"}
        for edge in edges:
            if edge.get("type") == "co_located" and edge.get("target") in sink_ids:
                src = ep_by_id.get(edge.get("source", ""))
                if src:
                    results.append(
                        {
                            "entrypoint": src,
                            "edge": edge,
                            "sink_id": edge.get("target"),
                            "evidence": edge.get("evidence"),
                        }
                    )
        # Also include data_flows targeting http sinks
        for flow in model.get("data_flows") or []:
            if (flow.get("sink") or {}).get("type") == "http":
                results.append({"flow": flow, "evidence": flow.get("evidence")})
        return results

    return []
