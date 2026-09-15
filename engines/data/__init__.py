"""Training Data Intelligence pipeline (Phase 9)."""

from __future__ import annotations

from engines.data.discover import discover
from engines.data.license_gate import (
    can_approve_for_training,
    evaluate_for_public_training,
    normalize_license,
)
from engines.data.pipeline import run_data_pipeline, write_data_pipeline_report
from engines.data.registry import (
    load_registry,
    save_registry,
    set_status,
)
from engines.data.report import render_data_html, render_data_markdown
from engines.data.schema import DATA_VERSION

__all__ = [
    "DATA_VERSION",
    "discover",
    "run_data_pipeline",
    "write_data_pipeline_report",
    "load_registry",
    "save_registry",
    "set_status",
    "evaluate_for_public_training",
    "can_approve_for_training",
    "normalize_license",
    "render_data_markdown",
    "render_data_html",
]
