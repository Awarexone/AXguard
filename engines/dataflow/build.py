"""Orchestrate dataflow / taint analysis and artifact writes."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from engines.app_model import build_application_model
from engines.app_model.discover import iter_text_files
from engines.dataflow.enrich import enrich_application_model
from engines.dataflow.paths import build_taint_paths
from engines.dataflow.schema import (
    DATAFLOW_VERSION,
    TAINTED,
    empty_dataflow,
    ensure_no_secret_values,
)
from engines.dataflow.sinks import discover_sinks
from engines.dataflow.sources import discover_sources, link_sources_to_endpoints
from engines.dataflow.summarize import render_dataflow_markdown


def analyze_dataflow(
    target: Path,
    application_model: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """
    Deterministic static dataflow / taint analysis for ``target``.

    Consumes Phase 1 ``application_model`` (builds it when omitted). No LLM calls.
    Prefer UNKNOWN / TAINTED over inventing SANITIZED without evidence.
    """
    root = target.resolve()
    model = application_model if application_model is not None else build_application_model(root)
    files = list(iter_text_files(root))

    flow = empty_dataflow(root)
    flow["schema_version"] = DATAFLOW_VERSION

    sources = discover_sources(root, files)
    link_sources_to_endpoints(sources, model.get("entrypoints") or [])
    sinks = discover_sinks(root, files, app_model_sinks=model.get("sinks") or [])

    paths, flows, controls = build_taint_paths(root, files, sources, sinks)

    flow["sources"] = sources
    flow["sinks"] = sinks
    flow["flows"] = flows
    flow["taint_paths"] = paths
    flow["controls"] = controls
    flow["summary"] = {
        "source_count": len(sources),
        "sink_count": len(sinks),
        "path_count": len(paths),
        "unsanitized_path_count": sum(
            1 for p in paths if p.get("taint_state") == TAINTED
        ),
    }

    ensure_no_secret_values(flow)

    # Enrich the shared application model in-place when provided / just built
    enrich_application_model(model, flow)
    flow["application_model_enriched"] = True

    return flow


def write_dataflow_report(flow: dict[str, Any], out_dir: Path) -> dict[str, Any]:
    """Write ``dataflow.json`` and ``dataflow.md`` under ``out_dir``."""
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    json_path = out_dir / "dataflow.json"
    md_path = out_dir / "dataflow.md"

    # Do not dump the whole enriched model into the report artifact
    serializable = {k: v for k, v in flow.items() if k != "application_model"}
    ensure_no_secret_values(serializable)

    json_path.write_text(
        json.dumps(serializable, indent=2, sort_keys=False) + "\n",
        encoding="utf-8",
    )
    md_path.write_text(render_dataflow_markdown(serializable), encoding="utf-8")

    return {
        "json": str(json_path),
        "markdown": str(md_path),
        "files": [str(json_path), str(md_path)],
    }
