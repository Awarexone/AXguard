"""Attach dataflow / taint results onto the Phase 1 application model graph."""

from __future__ import annotations

from typing import Any

from engines.app_model.schema import CONFIDENCE_LIKELY, evidence as app_evidence


def enrich_application_model(model: dict[str, Any], flow: dict[str, Any]) -> dict[str, Any]:
    """
    Mutate and return ``model`` with richer ``data_flows`` and graph edges from
    Phase 2 taint paths. Does not rebuild call graphs from scratch.
    """
    taint_paths = flow.get("taint_paths") or []
    enriched_flows: list[dict[str, Any]] = []

    for path in taint_paths:
        src = path.get("source") or {}
        sink = path.get("sink") or {}
        enriched_flows.append(
            {
                "source": {
                    "kind": "taint_source",
                    "id": src.get("id"),
                    "source_kind": src.get("kind"),
                    "name": src.get("name"),
                    "trust_level": src.get("trust_level"),
                    "file": src.get("file"),
                    "line": src.get("line"),
                    "endpoint": src.get("endpoint"),
                },
                "sink": {
                    "kind": "sink",
                    "id": sink.get("id"),
                    "type": sink.get("type"),
                    "symbol": sink.get("symbol"),
                    "file": sink.get("file"),
                    "line": sink.get("line"),
                },
                "taint_state": path.get("taint_state"),
                "controls_seen": path.get("controls_seen") or [],
                "confidence": path.get("confidence", CONFIDENCE_LIKELY),
                "evidence": (path.get("evidence") or [None])[0]
                if path.get("evidence")
                else app_evidence(
                    src.get("file"),
                    src.get("line"),
                    reason="Taint path from dataflow engine",
                ),
                "path_id": path.get("id"),
            }
        )

    # Preserve co-location flows that are not superseded by a taint path
    existing = model.get("data_flows") or []
    taint_keys = {
        (
            str((f.get("sink") or {}).get("file")),
            int((f.get("sink") or {}).get("line") or 0),
            str((f.get("sink") or {}).get("type")),
        )
        for f in enriched_flows
    }
    kept = []
    for f in existing:
        sk = f.get("sink") or {}
        key = (str(sk.get("file")), int(sk.get("line") or 0), str(sk.get("type")))
        if key in taint_keys:
            continue
        kept.append(f)

    model["data_flows"] = enriched_flows + kept
    model["taint_paths"] = taint_paths
    model["dataflow_summary"] = dict(flow.get("summary") or {})

    _enrich_graph(model, taint_paths)
    return model


def _enrich_graph(model: dict[str, Any], taint_paths: list[dict[str, Any]]) -> None:
    graph = model.setdefault("graph", {"nodes": [], "edges": []})
    nodes = graph.setdefault("nodes", [])
    edges = graph.setdefault("edges", [])
    node_ids = {n.get("id") for n in nodes}

    def add_node(nid: str, ntype: str, label: str, extra: dict[str, Any] | None = None) -> None:
        if nid in node_ids:
            return
        node_ids.add(nid)
        node = {"id": nid, "type": ntype, "label": label}
        if extra:
            node.update(extra)
        nodes.append(node)

    for i, path in enumerate(taint_paths):
        src = path.get("source") or {}
        sink = path.get("sink") or {}
        src_id = f"taint_source:{src.get('id') or i}"
        sink_id = f"taint_sink:{sink.get('id') or i}"
        add_node(
            src_id,
            "taint_source",
            str(src.get("name") or src.get("kind") or "source"),
            {
                "kind": src.get("kind"),
                "trust_level": src.get("trust_level"),
                "file": src.get("file"),
                "line": src.get("line"),
                "endpoint": src.get("endpoint"),
            },
        )
        add_node(
            sink_id,
            "taint_sink",
            f"{sink.get('type')}:{sink.get('symbol')}",
            {
                "sink_type": sink.get("type"),
                "file": sink.get("file"),
                "line": sink.get("line"),
            },
        )
        edges.append(
            {
                "source": src_id,
                "target": sink_id,
                "type": "taint_flow",
                "confidence": path.get("confidence", CONFIDENCE_LIKELY),
                "taint_state": path.get("taint_state"),
                "path_id": path.get("id"),
                "evidence": app_evidence(
                    src.get("file"),
                    src.get("line"),
                    reason=f"Taint path state={path.get('taint_state')}",
                ),
            }
        )

        # Link to co-located entrypoint node when endpoint known
        ep = src.get("endpoint") or {}
        if ep.get("path") is not None:
            for n in nodes:
                if n.get("type") != "entrypoint":
                    continue
                if n.get("file") == ep.get("file") and str(ep.get("path")) in str(
                    n.get("label") or ""
                ):
                    edges.append(
                        {
                            "source": n["id"],
                            "target": src_id,
                            "type": "exposes_source",
                            "confidence": CONFIDENCE_LIKELY,
                            "evidence": app_evidence(
                                ep.get("file"),
                                ep.get("line"),
                                reason="Entrypoint exposes taint source",
                            ),
                        }
                    )
                    break
