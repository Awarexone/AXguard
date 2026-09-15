"""Data Flow + Taint Analysis Engine (Phase 2)."""

from __future__ import annotations

from engines.dataflow.build import analyze_dataflow, write_dataflow_report
from engines.dataflow.enrich import enrich_application_model
from engines.dataflow.query import query_taint
from engines.dataflow.schema import DATAFLOW_VERSION
from engines.dataflow.summarize import render_dataflow_markdown

__all__ = [
    "DATAFLOW_VERSION",
    "analyze_dataflow",
    "write_dataflow_report",
    "enrich_application_model",
    "query_taint",
    "render_dataflow_markdown",
]
