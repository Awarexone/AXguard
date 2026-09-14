"""Tests for the Phase 6 Part 2 advanced attack-graph intelligence modules.

These cover the *new* self-contained modules (what-if, diff, predictive, SBOM,
temporal, cross-service, benchmark). They lean on synthetic graph dicts where
possible so a test does not depend on the exact chaining output, and use the
`fixtures/attack_paths_intel/` app for the end-to-end honesty checks
(adversarial false relation must not chain; temporal lifecycle must be detected).

Honesty contract under test:
- what-if output is always `hypothetical: true` / status PREDICTIVE.
- predictive language talks about *risk/surface trend*, never "vulnerability".
- SBOM records declared deps with `reachability: unknown` and invents no CVEs.
- temporal chains are evidence-gated (never CONFIRMED).
- an adversarial co-located pair is never fabricated into a chain.
- the benchmark harness reports measured counts and never crashes.
"""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path

from engines.attack_graph import (
    benchmark as benchmark_mod,
    cross_service as cross_service_mod,
    diff as diff_mod,
    predictive as predictive_mod,
    run_attack_graph,
    sbom as sbom_mod,
    temporal as temporal_mod,
    whatif as whatif_mod,
)

ROOT = Path(__file__).resolve().parents[1]
APP_FIXTURE = ROOT / "fixtures" / "attack_paths_app"
INTEL_FIXTURE = ROOT / "fixtures" / "attack_paths_intel"


@lru_cache(maxsize=1)
def _app_result() -> dict:
    return run_attack_graph(APP_FIXTURE)


@lru_cache(maxsize=1)
def _intel_result() -> dict:
    return run_attack_graph(INTEL_FIXTURE)


def _nodes_by_id(result: dict) -> dict[str, dict]:
    return {n["id"]: n for n in (result.get("graph") or {}).get("nodes") or []}


# ---------------------------------------------------------------------------
# synthetic graphs for pure-function tests (independent of chaining output)
# ---------------------------------------------------------------------------
def _synthetic_graph(with_extra_path: bool = False, blocked: bool = False) -> dict:
    nodes = [
        {"id": "entrypoint:get:a", "type": "entrypoint", "label": "GET /a", "reachability": "unauthenticated"},
        {"id": "finding:sqli", "type": "finding", "label": "sql-injection", "status": "CONFIRMED"},
        {"id": "asset:db", "type": "asset", "label": "users table", "kind": "database", "location": {"file": "a.py", "line": 5}},
    ]
    if with_extra_path:
        # The second entry point only exists alongside its path, so diffing the
        # two graphs also exercises NEW_ENTRY_POINT / REMOVED_ENTRY_POINT.
        nodes.append(
            {"id": "entrypoint:get:b", "type": "entrypoint", "label": "GET /b", "reachability": "authenticated"}
        )
    paths = [
        {
            "id": "path-0001",
            "status": "BLOCKED" if blocked else "CONFIRMED",
            "tags": ["direct_chain"],
            "entry": "entrypoint:get:a",
            "target": "asset:db",
            "hops": ["entrypoint:get:a", "finding:sqli", "asset:db"],
            "controls_encountered": (
                [{"id": "control:require_admin", "effectiveness": "confirmed"}] if blocked else []
            ),
        }
    ]
    if with_extra_path:
        paths.append(
            {
                "id": "path-0002",
                "status": "LIKELY",
                "tags": ["priv_esc"],
                "entry": "entrypoint:get:b",
                "target": "asset:db",
                "hops": ["entrypoint:get:b", "finding:sqli", "asset:db"],
                "controls_encountered": [],
            }
        )
    return {"graph": {"nodes": nodes}, "paths": paths, "target": "/tmp/synthetic"}


# ---------------------------------------------------------------------------
# what-if
# ---------------------------------------------------------------------------
def test_what_if_marks_hypothetical_and_predictive():
    result = _intel_result()
    ran_any = False
    for scenario in whatif_mod.available_scenarios():
        out = whatif_mod.run_what_if(result, scenario)
        assert out["status"] == "PREDICTIVE"
        assert out["hypothetical"] is True
        for p in out["hypothetical_paths"]:
            ran_any = ran_any or True
            assert p["hypothetical"] is True
            assert p["status"] == whatif_mod.HYPOTHETICAL_STATUS == "PREDICTIVE"
            # Never claims a current vulnerability.
            blob = json.dumps(p).lower()
            assert "vulnerability" not in blob
            assert p["disclaimer"]
    assert ran_any, "at least one scenario should predict a hypothetical path on this fixture"


def test_what_if_never_fabricates_without_basis():
    empty = {"graph": {"nodes": []}, "paths": [], "target": "/tmp/empty"}
    out = whatif_mod.run_what_if(empty, "secret_leaks")
    assert out["hypothetical_paths"] == []
    assert out["note"]  # explains that nothing matched


def test_what_if_unknown_scenario_raises():
    raised = False
    try:
        whatif_mod.run_what_if(_app_result(), "definitely_not_a_scenario")
    except KeyError:
        raised = True
    assert raised


# ---------------------------------------------------------------------------
# diff
# ---------------------------------------------------------------------------
def test_diff_detects_new_and_removed_paths():
    before = _synthetic_graph(with_extra_path=False)
    after = _synthetic_graph(with_extra_path=True)

    changes = diff_mod.get_attack_path_diff(before, after)
    kinds = {c["change"] for c in changes}
    assert diff_mod.CHANGE_NEW_ATTACK_PATH in kinds

    # Reverse direction: the extra path is now removed + entry point removed.
    changes_rev = diff_mod.get_attack_path_diff(after, before)
    kinds_rev = {c["change"] for c in changes_rev}
    assert diff_mod.CHANGE_REMOVED_ATTACK_PATH in kinds_rev
    assert diff_mod.CHANGE_REMOVED_ENTRY_POINT in kinds_rev


def test_diff_detects_weakened_control():
    before = _synthetic_graph(blocked=True)   # path BLOCKED by effective control
    after = _synthetic_graph(blocked=False)   # control gone → path live
    diff = diff_mod.compare_attack_graphs(before, after)
    kinds = {c["change"] for c in diff["changes"]}
    assert diff_mod.CHANGE_WEAKENED_CONTROL in kinds
    assert diff["summary"]["change_count"] >= 1


def test_diff_accepts_json_paths(tmp_path: Path):
    before = _synthetic_graph(with_extra_path=False)
    after = _synthetic_graph(with_extra_path=True)
    (tmp_path / "a.json").write_text(json.dumps(before), encoding="utf-8")
    (tmp_path / "b.json").write_text(json.dumps(after), encoding="utf-8")
    changes = diff_mod.get_attack_path_diff(tmp_path / "a.json", tmp_path / "b.json")
    assert any(c["change"] == diff_mod.CHANGE_NEW_ATTACK_PATH for c in changes)


# ---------------------------------------------------------------------------
# predictive
# ---------------------------------------------------------------------------
def test_predictive_language_does_not_claim_vulnerabilities():
    before = _synthetic_graph(with_extra_path=False)
    after = _synthetic_graph(with_extra_path=True)
    report = predictive_mod.predictive_report(before, after)

    assert report["status"] == "PREDICTIVE"
    assert report["overall_direction"] in {"increasing", "decreasing", "stable"}
    assert report["signal_count"] >= 1

    blob = json.dumps(report).lower()
    assert "vulnerability" not in blob
    assert "exploitable" not in blob
    # uses risk/surface trend language
    assert ("security risk" in blob) or ("attack surface" in blob)


def test_predictive_surface_report_is_measured():
    report = predictive_mod.surface_report(_app_result())
    assert report["status"] == "PREDICTIVE"
    assert set(report["metrics"]).issuperset(
        {"public_entrypoints", "ai_components", "external_services", "attack_paths"}
    )
    blob = json.dumps(report).lower()
    assert "vulnerability" not in blob


# ---------------------------------------------------------------------------
# sbom
# ---------------------------------------------------------------------------
def test_sbom_parses_requirements_without_cve_invention():
    result = sbom_mod.build_sbom(INTEL_FIXTURE)
    assert result["schema_version"]
    names = {d["name"] for d in result["dependencies"]}
    assert {"flask", "requests", "pyjwt", "boto3"} <= names  # pypi
    assert {"express", "axios", "jest"} <= names  # npm

    for dep in result["dependencies"]:
        # Reachability is unknown unless proven — never assumed reachable.
        assert dep["reachability"] == "unknown"

    # No CVE / advisory invention anywhere in the artifact.
    blob = json.dumps(result).lower()
    assert "cve-" not in blob
    assert "advisory" not in blob

    # Edge vocabulary is DEPENDS_ON / SUPPLIES only.
    edge_types = {e["type"] for e in result["edges"]}
    assert edge_types <= {sbom_mod.EDGE_DEPENDS_ON, sbom_mod.EDGE_SUPPLIES}


def test_sbom_requirements_parser_strips_comments_and_flags():
    deps = sbom_mod.parse_requirements_txt(
        "# comment\n-r other.txt\nflask==2.3.0\nrequests>=2.28  # inline\n\n"
    )
    by_name = {d["name"]: d for d in deps}
    assert by_name["flask"]["version"] == "==2.3.0"
    assert by_name["requests"]["version"] == ">=2.28"
    assert "other.txt" not in by_name  # pip flag lines skipped


# ---------------------------------------------------------------------------
# temporal
# ---------------------------------------------------------------------------
def test_temporal_chain_detected_when_evidence_exists():
    result = temporal_mod.analyze_temporal(INTEL_FIXTURE)
    seqs = {c["sequence_name"]: c for c in result["chains"]}
    assert "account_recovery" in seqs, "register→verify→reset lifecycle should be detected"
    chain = seqs["account_recovery"]
    assert chain["status"] == temporal_mod.STATUS_LIKELY
    steps = [s["step"] for s in chain["steps"]]
    assert steps == ["register", "verify", "reset"]
    # never CONFIRMED — static analysis can't prove the cross-request transition
    for c in result["chains"]:
        assert c["status"] in {temporal_mod.STATUS_LIKELY, temporal_mod.STATUS_UNKNOWN}
        assert c["previous_state"] and c["resulting_state"]


def test_temporal_expected_intel_contract():
    expected = json.loads((INTEL_FIXTURE / "expected_intel.json").read_text(encoding="utf-8"))
    result = temporal_mod.analyze_temporal(INTEL_FIXTURE)
    by_name = {c["sequence_name"]: c for c in result["chains"]}
    for case in expected.get("temporal") or []:
        chain = by_name.get(case["sequence_name"])
        assert chain is not None, f"expected temporal chain {case['sequence_name']}"
        assert chain["status"] in set(case["expect_status"])
        assert [s["step"] for s in chain["steps"]] == case["expect_steps"]


# ---------------------------------------------------------------------------
# adversarial false relation
# ---------------------------------------------------------------------------
def test_adversarial_false_relation_is_rejected():
    result = _intel_result()
    nodes = _nodes_by_id(result)
    for p in result.get("paths") or []:
        files = {
            Path(str((nodes.get(h) or {}).get("location", {}).get("file") or "")).name
            for h in p.get("hops") or []
        }
        # No path may be composed from the adversarial co-located pair.
        assert "adversarial_false_relation.py" not in files, (
            f"adversarial co-located findings were wrongly chained into {p['id']}"
        )


# ---------------------------------------------------------------------------
# cross-service
# ---------------------------------------------------------------------------
def test_cross_service_untrusted_boundary_for_multi_service():
    app_model = {
        "application": {"name": "billing-api"},
        "entrypoints": [
            {"kind": "http", "handler": "charge", "path": "/charge"},
            {"kind": "queue", "handler": "invoice_worker", "file": "worker.py", "line": 10},
        ],
        "external_services": [{"name": "stripe"}],
    }
    graph = cross_service_mod.build_cross_service_graph(app_model)
    assert graph["summary"]["multi_service"] is True
    assert graph["summary"]["cross_service_edge_count"] >= 1
    for e in graph["edges"]:
        assert e["type"] == cross_service_mod.EDGE_CROSSES_TRUST_BOUNDARY
        # internal != trusted
        assert e["trust"] == cross_service_mod.TRUST_UNTRUSTED


def test_cross_service_single_service_is_empty():
    app_model = {
        "application": {"name": "solo"},
        "entrypoints": [{"kind": "http", "handler": "index", "path": "/"}],
    }
    graph = cross_service_mod.build_cross_service_graph(app_model)
    assert graph["summary"]["multi_service"] is False
    assert graph["edges"] == []


# ---------------------------------------------------------------------------
# benchmark
# ---------------------------------------------------------------------------
def test_benchmark_interface_runs_without_crashing():
    result = benchmark_mod.run_benchmark(APP_FIXTURE)
    assert result["kind"] == "attack_graph_benchmark"
    assert result["has_expected"] is True
    counts = result["evaluation"]["counts"]
    metrics = result["evaluation"]["metrics"]
    # Measured counts present (from a real run, not invented).
    assert counts["cases"] >= 1
    assert counts["true_positives"] + counts["false_negatives"] >= 1
    # precision/recall are either measured floats or explicitly None — never faked.
    for key in ("precision", "recall", "f1"):
        assert metrics[key] is None or isinstance(metrics[key], float)
    # text formatter also must not crash
    text = benchmark_mod.format_benchmark(result)
    assert "benchmark" in text.lower()


def test_benchmark_evaluate_is_pure_and_measured():
    # Synthetic result: one path touching a.py, expected contract wants it.
    result = {
        "graph": {"nodes": [
            {"id": "finding:x", "type": "finding", "location": {"file": "a.py", "line": 1}},
        ]},
        "paths": [{"id": "path-0001", "status": "CONFIRMED", "hops": ["finding:x"]}],
        "dead_ends": [],
    }
    expected = {"cases": [
        {"file": "a.py", "expect_path_exists": True, "expect_status": ["CONFIRMED"]},
        {"file": "missing.py", "expect_path_exists": False},
    ]}
    ev = benchmark_mod.evaluate(result, expected)
    assert ev["counts"]["true_positives"] == 1
    assert ev["counts"]["true_negatives"] == 1
    assert ev["metrics"]["precision"] == 1.0
    assert ev["metrics"]["recall"] == 1.0
