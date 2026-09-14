"""Evidence & Confidence Engine (Phase 5)."""

from __future__ import annotations

from engines.evidence.api import (
    get_confidence,
    get_confidence_level,
    get_conflicts,
    get_counter_evidence,
    get_evidence,
    get_evidence_chain,
    get_supporting_evidence,
    get_unknowns,
)
from engines.evidence.pipeline import run_evidence, write_evidence_report
from engines.evidence.schema import EVIDENCE_VERSION
from engines.evidence.summarize import render_evidence_markdown

__all__ = [
    "EVIDENCE_VERSION",
    "run_evidence",
    "write_evidence_report",
    "render_evidence_markdown",
    # query helpers
    "get_evidence",
    "get_supporting_evidence",
    "get_counter_evidence",
    "get_unknowns",
    "get_confidence",
    "get_confidence_level",
    "get_evidence_chain",
    "get_conflicts",
]
