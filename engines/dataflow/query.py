"""Query helpers over dataflow / enriched application model."""

from __future__ import annotations

from typing import Any

from engines.dataflow.schema import SINK_NET, SINK_SQL, TAINTED


def query_taint(model_or_flow: dict[str, Any], key: str) -> list[Any]:
    """
    Best-effort queries for skills / CLI diagnostics.

    Supported keys:
      sources_to_network_sinks
      sources_to_sql
      unsanitized_paths
      sources
      sinks
      controls
    """
    paths = _paths(model_or_flow)
    sources = model_or_flow.get("sources") or []
    sinks = model_or_flow.get("sinks") or []
    controls = model_or_flow.get("controls") or []

    if key == "sources":
        return list(sources)

    if key == "sinks":
        return list(sinks)

    if key == "controls":
        return list(controls)

    if key == "unsanitized_paths":
        return [p for p in paths if p.get("taint_state") == TAINTED]

    if key == "sources_to_network_sinks":
        return [
            p
            for p in paths
            if (p.get("sink") or {}).get("type") in {SINK_NET, "http"}
        ]

    if key == "sources_to_sql":
        return [p for p in paths if (p.get("sink") or {}).get("type") == SINK_SQL]

    return []


def _paths(model_or_flow: dict[str, Any]) -> list[dict[str, Any]]:
    if model_or_flow.get("taint_paths"):
        return list(model_or_flow["taint_paths"])
    # Enriched application model may store them too
    return list(model_or_flow.get("taint_paths") or [])
