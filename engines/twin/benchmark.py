"""Benchmark metrics helpers for Security Twin fixtures."""

from __future__ import annotations

from typing import Any


def path_count_metrics(
    twin: dict[str, Any],
    expected: dict[str, Any],
) -> dict[str, Any]:
    """Compare observed path counts against fixture expectations."""
    actual = (twin.get("attack_graph") or {}).get("summary") or twin.get("summary") or {}
    exp_paths = expected.get("path_count") or expected.get("min_paths")
    act_paths = actual.get("path_count") or actual.get("attack_graph_path_count") or 0

    precision_stub = 1.0 if exp_paths is None else _ratio_match(act_paths, exp_paths)

    return {
        "expected_path_count": exp_paths,
        "actual_path_count": act_paths,
        "path_count_match": exp_paths is None or act_paths == exp_paths,
        "precision_stub": precision_stub,
        "by_status_expected": expected.get("by_status"),
        "by_status_actual": actual.get("by_status"),
    }


def control_metrics(twin: dict[str, Any], expected: dict[str, Any]) -> dict[str, Any]:
    summary = twin.get("summary") or {}
    exp_controls = expected.get("control_count")
    act_controls = summary.get("control_count", 0)
    return {
        "expected_control_count": exp_controls,
        "actual_control_count": act_controls,
        "match": exp_controls is None or act_controls == exp_controls,
    }


def run_fixture_benchmark(twin: dict[str, Any], fixture_expected: dict[str, Any]) -> dict[str, Any]:
    """Run all stub metrics against a fixture expected.json."""
    return {
        "paths": path_count_metrics(twin, fixture_expected),
        "controls": control_metrics(twin, fixture_expected),
        "entity_count": twin.get("summary", {}).get("entity_count", 0),
    }


def _ratio_match(actual: int, expected: int) -> float:
    if expected == 0:
        return 1.0 if actual == 0 else 0.0
    return min(actual, expected) / max(actual, expected)
