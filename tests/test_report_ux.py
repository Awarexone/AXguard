"""Tests for the HTML report interactive approval / consent UX layer."""

from pathlib import Path

import pytest

from engines import report_ux
from engines.audit import AuditOptions, run_audit
from engines.report import render_html, render_markdown

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "fixtures" / "vuln_app"
RULES = ROOT / "rules"


@pytest.fixture(scope="module")
def audit_result(tmp_path_factory) -> dict:
    out = tmp_path_factory.mktemp("axguard-ux")
    return run_audit(AuditOptions(target=FIXTURES, rules_dir=RULES, out_dir=out))


@pytest.fixture(scope="module")
def html_report(audit_result: dict) -> str:
    return render_html(audit_result)


def test_approval_banner_present(html_report: str):
    assert 'id="axguard-approval-banner"' in html_report
    assert "Analysis mode: READ-ONLY" in html_report
    assert "No source files were modified" in html_report
    assert "No external requests were made" in html_report


def test_session_state_read_only(html_report: str):
    assert 'id="axguard-session-state"' in html_report
    assert '"analysis_mode": "read_only"' in html_report
    assert '"approved_actions": []' in html_report
    assert '"activity_log": []' in html_report


def test_embedded_attack_paths_json_when_present(audit_result: dict, html_report: str):
    payload = report_ux.attack_paths_payload(audit_result)
    if payload is None:
        # No paths for this fixture: script must be absent (not empty/broken).
        assert 'id="axguard-attack-paths"' not in html_report
        pytest.skip("fixture produced no attack paths")
    assert 'id="axguard-attack-paths"' in html_report
    assert 'type="application/json"' in html_report
    assert "paths" in payload and isinstance(payload["paths"], list)


def test_js_includes_approval_gate_functions(html_report: str):
    for fn in (
        "function requestApproval",
        "window.axguardRequestApproval",
        "function approve",
        "function logActivity",
        "function openDialog",
    ):
        assert fn in html_report, fn


def test_export_and_expand_are_gated_dialog_markup(html_report: str):
    # Single reusable approval modal exists.
    assert 'id="axguard-modal"' in html_report
    assert 'role="dialog"' in html_report
    # Export + expand route through the approval gate (not a direct runner).
    assert "axguardRequestApproval('export_report')" in html_report
    assert "axguardRequestApproval('show_full_source')" in html_report
    # Export offers Summary / Detailed choices client-side.
    assert "runExport" in html_report


def test_high_risk_actions_never_auto_trigger(html_report: str):
    # High-risk buttons must go through the approval gate, never a direct runner.
    for action in ("apply_fix", "active_verification", "external_share"):
        assert f"axguardRequestApproval('{action}')" in html_report
        # No direct auto-run onclick that executes the action without the gate.
        assert f"onclick=\"{action}()\"" not in html_report
    # High-risk is explicitly stubbed, never executed.
    assert "not available in this report build" in html_report
    assert "HIGH_RISK" in html_report


def test_activity_trail_panel_present(html_report: str):
    assert 'id="axguard-activity-log"' in html_report
    assert "Analysis activity" in html_report


def test_no_dark_patterns_cancel_easy(html_report: str):
    # Cancel is always available and Escape/backdrop also cancel.
    assert "window.axguardCancel" in html_report
    assert 'data-axguard-cancel' in html_report
    # Focus defaults to the safe (Cancel) choice, never the dangerous one.
    assert "cancelBtn.focus()" in html_report


def test_coverage_and_limited_flags(audit_result: dict):
    cov = report_ux.analysis_coverage(audit_result)
    assert cov["total"] == 6
    assert 0 <= cov["present_count"] <= 6
    assert cov["limited"] == bool(cov["missing"])


def test_large_graph_threshold_logic():
    small = {"attack_graph": {"graph": {"edges": [1, 2, 3], "nodes": []}, "paths": [1]}}
    assert report_ux.is_large_graph(small) is False
    big_edges = {"attack_graph": {"graph": {"edges": list(range(200)), "nodes": []}, "paths": [1]}}
    assert report_ux.is_large_graph(big_edges) is True
    big_paths = {
        "attack_graph": {"graph": {"edges": [], "nodes": []}, "paths": list(range(25))}
    }
    assert report_ux.is_large_graph(big_paths) is True


def test_attack_paths_payload_redacts_secrets():
    result = {
        "finished_at": "2026-01-01T00:00:00Z",
        "attack_graph": {
            "graph": {
                "nodes": [
                    {"id": "n1", "label": "entry", "type": "entrypoint", "api_key": "supersecretvalue123"},
                    {"id": "n2", "label": "sink", "type": "asset"},
                ],
                "edges": [{"type": "reaches"}],
            },
            "paths": [
                {
                    "id": "path-0001",
                    "status": "LIKELY",
                    "confidence_level": "MEDIUM",
                    "score": 0.5,
                    "hops": ["n1", "n2"],
                    "evidence_refs": [{"source": "x", "id": "y"}],
                }
            ],
            "summary": {"by_status": {"LIKELY": 1}},
            "dead_ends": [],
        },
    }
    payload = report_ux.attack_paths_payload(result)
    assert payload is not None
    import json as _json

    blob = _json.dumps(payload)
    assert "supersecretvalue123" not in blob
    assert payload["paths"][0]["evidence_ref_count"] == 1


def test_markdown_notes_read_only_mode(audit_result: dict):
    md = render_markdown(audit_result)
    assert "Analysis mode: READ-ONLY" in md
