"""Security Twin — symbolic security model over attack-graph artifacts."""

from __future__ import annotations

from engines.twin.attacker import virtual_attacker
from engines.twin.benchmark import path_count_metrics, run_fixture_benchmark
from engines.twin.blast_radius import entity_blast_radius, resolve_entity_id
from engines.twin.build import build_security_twin
from engines.twin.controls import control_effectiveness
from engines.twin.counterfactual import run_counterfactual
from engines.twin.export_dataset import export_twin_examples
from engines.twin.pipeline import run_twin, run_twin_compare, run_twin_what_if
from engines.twin.query import answer_query
from engines.twin.regression import twin_regression
from engines.twin.report import render_twin_html_section, render_twin_markdown, write_twin_report
from engines.twin.scenarios import get_scenario, list_scenarios
from engines.twin.schema import (
    FACT_LAYERS,
    SECURITY_TWIN_VERSION,
    empty_twin,
)
from engines.twin.simulate import simulate_attack

__all__ = [
    "SECURITY_TWIN_VERSION",
    "FACT_LAYERS",
    "answer_query",
    "build_security_twin",
    "control_effectiveness",
    "empty_twin",
    "entity_blast_radius",
    "export_twin_examples",
    "get_scenario",
    "list_scenarios",
    "path_count_metrics",
    "render_twin_html_section",
    "render_twin_markdown",
    "resolve_entity_id",
    "run_counterfactual",
    "run_fixture_benchmark",
    "run_twin",
    "run_twin_compare",
    "run_twin_what_if",
    "simulate_attack",
    "twin_regression",
    "virtual_attacker",
    "write_twin_report",
]
