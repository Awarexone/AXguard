"""Tests for audit + report generation."""

from pathlib import Path

from engines.audit import AuditOptions, run_audit
from engines.report import render_html, render_markdown, write_reports

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "fixtures" / "vuln_app"
RULES = ROOT / "rules"


def test_audit_writes_md_and_html(tmp_path: Path):
    result = run_audit(
        AuditOptions(target=FIXTURES, rules_dir=RULES, out_dir=tmp_path)
    )
    assert result["finding_count"] >= 5
    assert result["severity_counts"]["critical"] >= 1
    phase_ids = {p["id"] for p in result["phases"]}
    assert "sql" in phase_ids
    assert "debug" in phase_ids
    assert "nosql" in phase_ids
    paths = write_reports(result, tmp_path)
    assert paths["md"].exists()
    assert paths["html"].exists()
    assert paths["json"].exists()
    md = paths["md"].read_text(encoding="utf-8")
    html = paths["html"].read_text(encoding="utf-8")
    assert "Severity summary" in md
    assert "Application understanding" in md
    assert "AXguard" in html
    assert "Security audit report" in html
    assert result.get("application_model_summary") is not None
    surface = next(p for p in result["phases"] if p["id"] == "surface")
    assert surface["status"] in {"ok", "error"}
    assert "application_model_summary" in surface
    assert (tmp_path / "application-model.json").exists()
    assert (tmp_path / "application-model.md").exists()


def test_markdown_and_html_renderers(tmp_path: Path):
    result = run_audit(
        AuditOptions(target=FIXTURES, rules_dir=RULES, out_dir=tmp_path)
    )
    md = render_markdown(result)
    html = render_html(result)
    assert "Findings" in md
    assert "<!DOCTYPE html>" in html
    assert "critical" in html.lower()
