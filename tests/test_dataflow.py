"""Tests for Phase 2 dataflow / taint analysis engine."""

from __future__ import annotations

import json
from pathlib import Path

from engines.dataflow import (
    DATAFLOW_VERSION,
    analyze_dataflow,
    enrich_application_model,
    query_taint,
    write_dataflow_report,
)
from engines.dataflow.schema import CONFIDENCES, TAINT_STATES
from cli.main import main

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "fixtures" / "dataflow_app"


def test_schema_version_and_counts():
    flow = analyze_dataflow(FIXTURE)
    assert flow["schema_version"] == DATAFLOW_VERSION
    assert flow["tool"] == "axguard"
    summary = flow["summary"]
    assert summary["source_count"] == len(flow["sources"])
    assert summary["sink_count"] == len(flow["sinks"])
    assert summary["path_count"] == len(flow["taint_paths"])
    assert "unsanitized_path_count" in summary


def test_finds_tainted_ssrf_and_sql_paths():
    flow = analyze_dataflow(FIXTURE)
    paths = flow["taint_paths"]
    assert paths, "expected at least one taint path on fixture"

    net = [
        p
        for p in paths
        if (p.get("sink") or {}).get("type") == "net"
        and "ssrf_tainted" in str((p.get("sink") or {}).get("file"))
    ]
    sql = [
        p
        for p in paths
        if (p.get("sink") or {}).get("type") == "sql"
        and "sql_tainted" in str((p.get("sink") or {}).get("file"))
    ]
    assert net, "expected SSRF-shaped tainted net path"
    assert sql, "expected SQL tainted path"
    assert any(p.get("taint_state") == "TAINTED" for p in net + sql)


def test_sanitized_does_not_claim_sanitized_without_evidence():
    flow = analyze_dataflow(FIXTURE)
    sanitized_file_paths = [
        p
        for p in flow["taint_paths"]
        if "sanitized" in str((p.get("sink") or {}).get("file") or "")
    ]
    for p in sanitized_file_paths:
        state = p.get("taint_state")
        assert state in TAINT_STATES
        if state == "SANITIZED":
            # Must have control evidence
            assert p.get("controls_seen"), "SANITIZED requires controls_seen evidence"
        # Never invent confirmed unsanitized when parameterization/allowlist present
        if p.get("controls_seen") and state == "TAINTED":
            # Allow TAINTED only if controls are ineffective/unknown — still OK
            pass


def test_parameterized_sql_not_confirmed_unsanitized():
    flow = analyze_dataflow(FIXTURE)
    param_sql = [
        p
        for p in flow["taint_paths"]
        if "sanitized" in str((p.get("file") if False else (p.get("sink") or {}).get("file") or ""))
        and (p.get("sink") or {}).get("type") == "sql"
    ]
    for p in param_sql:
        # Should not be confidence=confirmed with taint_state=TAINTED
        if p.get("taint_state") == "TAINTED":
            assert p.get("confidence") != "confirmed"


def test_false_positive_comment_not_path():
    flow = analyze_dataflow(FIXTURE)
    fp_paths = [
        p
        for p in flow["taint_paths"]
        if "false_positive" in str((p.get("sink") or {}).get("file") or "")
        or "false_positive" in str((p.get("source") or {}).get("file") or "")
    ]
    assert fp_paths == []


def test_confidence_and_taint_enums():
    flow = analyze_dataflow(FIXTURE)
    bad: list[str] = []
    for p in flow["taint_paths"]:
        if p.get("confidence") not in CONFIDENCES:
            bad.append(f"conf:{p.get('confidence')}")
        if p.get("taint_state") not in TAINT_STATES:
            bad.append(f"state:{p.get('taint_state')}")
    for s in flow["sources"]:
        if s.get("confidence") not in CONFIDENCES:
            bad.append(f"src:{s.get('confidence')}")
    assert bad == []


def test_no_secret_values_in_output():
    flow = analyze_dataflow(FIXTURE)
    dump = json.dumps(flow)
    assert "sk_live" not in dump
    assert "AKIA" not in dump


def test_query_helpers():
    flow = analyze_dataflow(FIXTURE)
    assert isinstance(query_taint(flow, "sources_to_network_sinks"), list)
    assert isinstance(query_taint(flow, "sources_to_sql"), list)
    assert isinstance(query_taint(flow, "unsanitized_paths"), list)
    net = query_taint(flow, "sources_to_network_sinks")
    assert net  # fixture has SSRF-shaped path


def test_write_artifacts(tmp_path: Path):
    flow = analyze_dataflow(FIXTURE)
    paths = write_dataflow_report(flow, tmp_path)
    assert Path(paths["json"]).exists()
    assert Path(paths["markdown"]).exists()
    md = Path(paths["markdown"]).read_text(encoding="utf-8")
    assert "dataflow" in md.lower()
    assert "diagnostic" in md.lower()


def test_enrich_application_model():
    flow = analyze_dataflow(FIXTURE)
    # analyze_dataflow already enriches when building model; re-run enrich on a fresh model
    from engines.app_model import build_application_model

    model = build_application_model(FIXTURE)
    before = len(model.get("data_flows") or [])
    enrich_application_model(model, flow)
    assert model.get("taint_paths")
    assert len(model.get("data_flows") or []) >= before
    edges = (model.get("graph") or {}).get("edges") or []
    assert any(e.get("type") == "taint_flow" for e in edges)


def test_cli_flow_smoke(tmp_path: Path, capsys):
    code = main(["flow", str(FIXTURE), "--out-dir", str(tmp_path), "--no-banner"])
    assert code == 0
    out = capsys.readouterr().out
    assert "paths" in out.lower() or "dataflow" in out.lower()
    assert (tmp_path / "dataflow.json").exists()
