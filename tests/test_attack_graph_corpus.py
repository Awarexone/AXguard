"""Phase 6 Part 2 — regression corpus + risk aggregation / posture tests.

Driven by ``fixtures/attack_paths_corpus/expected.json``. This corpus is
additive to ``fixtures/attack_paths_app/`` (tested by
``tests/test_attack_graph.py``): it exercises additional attack-path shapes —
including two forward-looking patterns (confused deputy, state-dependent /
cross-request chains) that no chaining detector implements yet.

Cases marked ``"soft": true`` in ``expected.json`` are skipped (never
failed) when the engine does not yet produce a matching path, so this suite
stays green while other in-flight work lands the matching detector(s) —
whichever module/engine ends up owning that logic. Once a detector exists,
the same case starts asserting for real with no test changes required.

The aggregate/posture smoke tests use ``pytest.importorskip`` so this file
degrades gracefully if ``engines.attack_graph.aggregate`` /
``engines.attack_graph.posture`` are ever moved or renamed.
"""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path

import pytest

from engines.attack_graph import run_attack_graph
from engines.attack_graph.schema import PATH_STATUSES

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "fixtures" / "attack_paths_corpus"


@lru_cache(maxsize=1)
def _result() -> dict:
    return run_attack_graph(FIXTURE)


@lru_cache(maxsize=1)
def _expected() -> dict:
    return json.loads((FIXTURE / "expected.json").read_text(encoding="utf-8"))


def _nodes_by_id(result: dict) -> dict[str, dict]:
    return {n["id"]: n for n in (result.get("graph") or {}).get("nodes") or []}


def _paths_for_file(result: dict, filename: str) -> list[dict]:
    """Paths that touch at least one node located in ``filename``."""
    nodes = _nodes_by_id(result)
    out = []
    for p in result.get("paths") or []:
        for hop in p.get("hops") or []:
            loc = (nodes.get(hop) or {}).get("location") or {}
            if Path(str(loc.get("file") or "")).name == filename:
                out.append(p)
                break
    return out


# ---------------------------------------------------------------------------
# Corpus shape / smoke
# ---------------------------------------------------------------------------
def test_corpus_fixture_files_exist():
    for case in _expected()["cases"]:
        assert (FIXTURE / case["file"]).exists(), f"missing fixture: {case['file']}"


def test_corpus_requirements_and_expected_present():
    assert (FIXTURE / "requirements.txt").exists()
    assert (FIXTURE / "expected.json").exists()


def test_run_attack_graph_on_corpus_smoke():
    result = _result()
    assert result["schema_version"]
    assert "graph" in result and "nodes" in result["graph"] and "edges" in result["graph"]
    assert "paths" in result and "dead_ends" in result
    for p in result["paths"]:
        assert p["status"] in PATH_STATUSES
        assert p["hops"], "every path must have hops"


def test_edges_carry_confidence_and_evidence_on_corpus():
    result = _result()
    for e in result["graph"]["edges"]:
        assert e["confidence"] in {"confirmed", "likely", "unknown"}
        assert "evidence" in e


# ---------------------------------------------------------------------------
# expected.json cases — hard for shipped patterns, soft-skip for forward-
# looking ones (confused deputy / state-dependent) until a detector lands.
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("case", _expected()["cases"], ids=lambda c: c["file"])
def test_corpus_case(case: dict):
    result = _result()
    name = case["file"]
    paths = _paths_for_file(result, name)

    if not case.get("expect_path_exists"):
        # false_path.py: same-file co-location must never become a chain.
        # This is testable regardless of any future detector landing, since
        # it asserts an absence the baseline engine already guarantees.
        assert not paths, f"{name}: expected NO attack path, got {[p['id'] for p in paths]}"
        return

    if not paths:
        if case.get("soft"):
            pytest.skip(
                f"{name}: no chaining detector produces this pattern yet "
                f"(tags={case.get('tags')}) — soft case, expected until it lands"
            )
        assert paths, f"{name}: expected at least one attack path"

    statuses = {p["status"] for p in paths}
    want = set(case.get("expect_status") or [])
    if want:
        assert statuses & want, f"{name}: got {statuses}, want any of {want}"
    forbid = set(case.get("forbid_status") or [])
    if forbid:
        assert not (forbid & statuses), f"{name}: forbidden status present {forbid & statuses}"


def test_confirmed_path_case():
    paths = _paths_for_file(_result(), "confirmed_path.py")
    assert paths
    assert any(p["status"] in {"CONFIRMED", "LIKELY"} for p in paths)


def test_blocked_path_case_is_blocked_not_confirmed():
    paths = _paths_for_file(_result(), "blocked_path_case.py")
    assert paths
    statuses = {p["status"] for p in paths}
    assert "BLOCKED" in statuses
    assert "CONFIRMED" not in statuses
    blocked = next(p for p in paths if p["status"] == "BLOCKED")
    effs = {c.get("effectiveness") for c in blocked.get("controls_encountered") or []}
    assert "confirmed" in effs


def test_false_path_produces_no_linking_path():
    result = _result()
    paths = _paths_for_file(result, "false_path.py")
    assert not paths, "same-file co-located findings must not be chained"
    nodes = _nodes_by_id(result)
    for p in result["paths"]:
        handlers = {
            (nodes.get(h) or {}).get("handler")
            for h in p["hops"]
            if (nodes.get(h) or {}).get("type") == "entrypoint"
        }
        assert not ({"profile", "read_file"} <= handlers)


def test_unknown_prerequisite_is_unverified():
    paths = _paths_for_file(_result(), "unknown_prerequisite.py")
    assert paths
    statuses = {p["status"] for p in paths}
    assert "UNVERIFIED" in statuses
    assert "CONFIRMED" not in statuses
    assert "BLOCKED" not in statuses
    assert "INVALID" not in statuses


def test_privilege_escalation_case():
    paths = _paths_for_file(_result(), "privilege_escalation.py")
    assert paths
    assert any(p["status"] in {"CONFIRMED", "LIKELY"} for p in paths)
    assert any("priv_esc" in (p.get("tags") or []) for p in paths)


def test_cross_tenant_access_case():
    result = _result()
    paths = _paths_for_file(result, "cross_tenant_access.py")
    assert paths
    assert any(p["status"] in {"CONFIRMED", "LIKELY"} for p in paths)
    ct = next(p for p in paths if "cross_tenant" in (p.get("tags") or []))
    assert "crosses_tenant" in (ct.get("edge_types") or [])


def test_ai_mcp_tool_abuse_case():
    result = _result()
    paths = _paths_for_file(result, "ai_mcp_tool_abuse.py")
    assert paths
    ai = next(p for p in paths if "ai_chain" in (p.get("tags") or []))
    assert ai["status"] in {"CONFIRMED", "LIKELY"}
    assert "invokes" in (ai.get("edge_types") or [])
    assert "yields" in (ai.get("edge_types") or [])
    nodes = _nodes_by_id(result)
    kinds = {nodes[h]["type"] for h in ai["hops"] if h in nodes}
    assert {"ai_component", "tool"} <= kinds


def test_confused_deputy_case_soft():
    """Forward-looking: skip (not fail) until a confused-deputy detector
    exists. If one lands, this must start asserting CONFIRMED/LIKELY."""
    paths = _paths_for_file(_result(), "confused_deputy.py")
    if not paths:
        pytest.skip("no confused-deputy chaining detector yet — soft case")
    assert any(p["status"] in {"CONFIRMED", "LIKELY"} for p in paths)


def test_state_dependent_chain_case_soft():
    """Forward-looking: skip (not fail) until a cross-request / state-
    dependent chaining detector exists."""
    paths = _paths_for_file(_result(), "state_dependent_chain.py")
    if not paths:
        pytest.skip("no state-dependent/cross-request chaining detector yet — soft case")
    assert any(p["status"] in {"CONFIRMED", "LIKELY"} for p in paths)


# ---------------------------------------------------------------------------
# Honesty guarantees (mirrors tests/test_attack_graph.py, corpus-scoped)
# ---------------------------------------------------------------------------
def test_no_false_positive_hop_is_treated_as_confirmed_on_corpus():
    result = _result()
    nodes = _nodes_by_id(result)
    for p in result["paths"]:
        for h in p["hops"]:
            n = nodes.get(h) or {}
            if n.get("type") in {"finding", "candidate_seed"}:
                assert n.get("status") != "FALSE_POSITIVE"


def test_structural_seeds_never_confirmed_on_corpus():
    result = _result()
    for n in result["graph"]["nodes"]:
        if n.get("type") == "candidate_seed":
            assert n.get("status") in {"LIKELY", "UNVERIFIED"}
            assert n.get("origin") == "attack_graph_seed"


def test_no_secrets_in_corpus_dump(tmp_path: Path):
    from engines.attack_graph import write_attack_graph_report

    result = _result()
    paths = write_attack_graph_report(result, tmp_path)
    dump = Path(paths["json"]).read_text(encoding="utf-8")
    assert "Co-authored-by" not in dump
    assert "Made with Cursor" not in dump
    assert "sk_live" not in dump
    assert "AKIA" not in dump
    assert "_evidence" not in dump


# ---------------------------------------------------------------------------
# Risk aggregation (engines/attack_graph/aggregate.py) — soft-imported
# ---------------------------------------------------------------------------
def test_aggregate_risk_summary_smoke():
    aggregate = pytest.importorskip("engines.attack_graph.aggregate")
    result = _result()
    summary = aggregate.build_risk_summary(result)

    assert summary["schema_version"]
    totals = summary["totals"]
    assert totals["path_count"] == len(result.get("paths") or [])
    assert totals["dead_end_count"] == len(result.get("dead_ends") or [])

    # Grouping must never hide an individual finding.
    assert len(summary["findings"]) == totals["finding_count"]
    assert totals["finding_count"] > 0

    for key in ("by_root_cause", "by_asset", "by_privilege", "by_tenant"):
        assert key in summary["grouped"]

    # Every finding referenced by a group must also appear in the full list.
    all_ids = {f["id"] for f in summary["findings"]}
    for g in summary["grouped"]["by_root_cause"]:
        assert set(g["finding_ids"]) <= all_ids


def test_aggregate_blocked_paths_are_predictive_risks():
    aggregate = pytest.importorskip("engines.attack_graph.aggregate")
    result = _result()
    summary = aggregate.build_risk_summary(result)
    blocked_ids = {p["id"] for p in summary["blocked_paths"]}
    predictive_blocked_ids = {
        r["path_id"] for r in summary["predictive_risks"] if r["kind"] == "blocked_control_regression"
    }
    assert blocked_ids <= predictive_blocked_ids or not blocked_ids


def test_aggregate_handles_empty_graph_gracefully():
    aggregate = pytest.importorskip("engines.attack_graph.aggregate")
    minimal = {"graph": {"nodes": [], "edges": []}, "paths": [], "dead_ends": []}
    summary = aggregate.build_risk_summary(minimal)
    assert summary["totals"]["path_count"] == 0
    assert summary["findings"] == []


def test_aggregate_markdown_renders():
    aggregate = pytest.importorskip("engines.attack_graph.aggregate")
    if not hasattr(aggregate, "render_risk_summary_markdown"):
        pytest.skip("render_risk_summary_markdown not present")
    summary = aggregate.build_risk_summary(_result())
    md = aggregate.render_risk_summary_markdown(summary)
    assert "risk aggregation" in md.lower()


# ---------------------------------------------------------------------------
# Security posture (engines/attack_graph/posture.py) — soft-imported
# ---------------------------------------------------------------------------
def test_posture_summary_smoke():
    posture = pytest.importorskip("engines.attack_graph.posture")
    result = _result()
    summary = posture.build_posture_summary(result)

    assert summary["schema_version"]
    for stage in ("entry", "trust", "controls", "weak", "vulns", "priv", "assets", "impact"):
        assert stage in summary["stages"]
        assert "count" in summary["stages"][stage]
    assert summary["posture_rating"]
    assert summary["flow"] == [
        "entry",
        "trust",
        "controls",
        "weak",
        "vulns",
        "priv",
        "assets",
        "impact",
    ]


def test_posture_weak_is_subset_of_controls():
    posture = pytest.importorskip("engines.attack_graph.posture")
    summary = posture.build_posture_summary(_result())
    controls = summary["stages"]["controls"]
    weak = summary["stages"]["weak"]
    assert weak["count"] <= controls["count"]
    assert weak["of_total_controls"] == controls["count"]


def test_posture_handles_empty_graph_gracefully():
    posture = pytest.importorskip("engines.attack_graph.posture")
    minimal = {"graph": {"nodes": [], "edges": []}, "paths": [], "dead_ends": []}
    summary = posture.build_posture_summary(minimal)
    assert summary["counts"]["entry"] == 0
    assert summary["posture_rating"] == "NO_OBSERVED_EXPOSURE"


def test_posture_markdown_renders():
    posture = pytest.importorskip("engines.attack_graph.posture")
    if not hasattr(posture, "render_posture_markdown"):
        pytest.skip("render_posture_markdown not present")
    summary = posture.build_posture_summary(_result())
    md = posture.render_posture_markdown(summary)
    assert "posture" in md.lower()
    assert "Entry" in md and "Impact" in md
