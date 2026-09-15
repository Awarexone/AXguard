"""Benchmark harness for the attack-graph engine (Phase 6 Part 2).

Runs the attack graph against a fixture directory that ships an
``expected.json`` contract and reports **measured** outcomes only. It does not
invent precision/recall numbers: every count comes from comparing the engine's
real output to the fixture's declared expectations, and precision/recall are
reported as ``None`` when their denominator is zero (rather than a fabricated
``1.0``).

Case contract (``expected.json`` → ``cases[]``), reused from the Phase 6 Part 1
fixture format:

- ``file``: the fixture source file the case concerns.
- ``expect_path_exists``: whether at least one attack path should touch it.
- ``expect_status`` (optional): acceptable path statuses; a found path whose
  status is outside this set is a *status mismatch* (still counted as found).
- ``forbid_status`` (optional): statuses that must NOT appear for this file.

Classification:
- expected & found            → true positive (TP)
- expected & not found        → false negative (FN)
- not expected & found        → false positive (FP)  (e.g. a fabricated chain)
- not expected & not found    → true negative (TN)
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

BENCHMARK_VERSION = "1.0.0"


def _nodes_by_id(result: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {n["id"]: n for n in (result.get("graph") or {}).get("nodes") or []}


def _paths_for_file(result: dict[str, Any], filename: str) -> list[dict[str, Any]]:
    nodes = _nodes_by_id(result)
    out: list[dict[str, Any]] = []
    for p in result.get("paths") or []:
        for hop in p.get("hops") or []:
            loc = (nodes.get(hop) or {}).get("location") or {}
            if Path(str(loc.get("file") or "")).name == filename:
                out.append(p)
                break
    return out


def evaluate(result: dict[str, Any], expected: dict[str, Any]) -> dict[str, Any]:
    """Compare an attack-graph ``result`` to an ``expected.json`` contract.

    Pure function (no I/O, no engine run) so it is trivially testable with
    synthetic inputs.
    """
    tp = fp = fn = tn = 0
    status_mismatches = 0
    forbidden_hits = 0
    case_outcomes: list[dict[str, Any]] = []

    for case in expected.get("cases") or []:
        name = case.get("file")
        paths = _paths_for_file(result, name)
        found = bool(paths)
        statuses = {p.get("status") for p in paths}
        want_exist = bool(case.get("expect_path_exists"))

        outcome: dict[str, Any] = {
            "file": name,
            "expected_path": want_exist,
            "found_path": found,
            "statuses": sorted(str(s) for s in statuses),
        }

        if want_exist and found:
            tp += 1
            outcome["classification"] = "TP"
            want_status = set(case.get("expect_status") or [])
            if want_status and not (statuses & want_status):
                status_mismatches += 1
                outcome["status_mismatch"] = True
        elif want_exist and not found:
            fn += 1
            outcome["classification"] = "FN"
        elif not want_exist and found:
            fp += 1
            outcome["classification"] = "FP"
        else:
            tn += 1
            outcome["classification"] = "TN"

        forbid = set(case.get("forbid_status") or [])
        if forbid and (forbid & statuses):
            forbidden_hits += 1
            outcome["forbidden_status_present"] = sorted(str(s) for s in (forbid & statuses))

        case_outcomes.append(outcome)

    precision = tp / (tp + fp) if (tp + fp) else None
    recall = tp / (tp + fn) if (tp + fn) else None
    f1 = (
        2 * precision * recall / (precision + recall)
        if (precision is not None and recall is not None and (precision + recall))
        else None
    )

    return {
        "counts": {
            "cases": len(case_outcomes),
            "true_positives": tp,
            "false_positives": fp,
            "false_negatives": fn,
            "true_negatives": tn,
            "status_mismatches": status_mismatches,
            "forbidden_status_hits": forbidden_hits,
        },
        # Measured metrics only — None when undefined (never a fabricated 1.0).
        "metrics": {
            "precision": round(precision, 4) if precision is not None else None,
            "recall": round(recall, 4) if recall is not None else None,
            "f1": round(f1, 4) if f1 is not None else None,
        },
        "cases": case_outcomes,
    }


def run_benchmark(fixture_dir: Path | str) -> dict[str, Any]:
    """Run the attack graph on ``fixture_dir`` and evaluate against its
    ``expected.json``. Returns a structured, self-describing benchmark result.
    """
    # Imported lazily so importing this module never triggers a full engine run.
    from engines.attack_graph import run_attack_graph

    fixture = Path(fixture_dir)
    expected_path = fixture / "expected.json"
    expected: dict[str, Any] = {"cases": []}
    if expected_path.is_file():
        expected = json.loads(expected_path.read_text(encoding="utf-8"))

    result = run_attack_graph(fixture)
    evaluation = evaluate(result, expected)

    return {
        "schema_version": BENCHMARK_VERSION,
        "tool": "axguard",
        "kind": "attack_graph_benchmark",
        "fixture": str(fixture.resolve()),
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "has_expected": expected_path.is_file(),
        "engine": {
            "path_count": len(result.get("paths") or []),
            "dead_end_count": len(result.get("dead_ends") or []),
        },
        "evaluation": evaluation,
        "notes": (
            "All counts are measured from a real engine run vs. the fixture "
            "contract. Precision/recall are null when undefined — no numbers are "
            "invented, and there is no CVE or external-benchmark dependency."
        ),
    }


def format_benchmark(benchmark: dict[str, Any]) -> str:
    """Compact text rendering of a benchmark result (measured counts only)."""
    ev = benchmark.get("evaluation") or {}
    counts = ev.get("counts") or {}
    metrics = ev.get("metrics") or {}
    lines = [
        "attack-graph benchmark (measured — no invented numbers)",
        f"  fixture           {benchmark.get('fixture')}",
        f"  has expected      {benchmark.get('has_expected')}",
        f"  cases             {counts.get('cases', 0)}",
        f"  true positives    {counts.get('true_positives', 0)}",
        f"  false positives   {counts.get('false_positives', 0)}",
        f"  false negatives   {counts.get('false_negatives', 0)}",
        f"  true negatives    {counts.get('true_negatives', 0)}",
        f"  status mismatches {counts.get('status_mismatches', 0)}",
        f"  forbidden hits    {counts.get('forbidden_status_hits', 0)}",
        f"  precision         {metrics.get('precision')}",
        f"  recall            {metrics.get('recall')}",
        f"  f1                {metrics.get('f1')}",
    ]
    return "\n".join(lines)
