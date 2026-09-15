"""Tests for Phase 4 False Positive Adversary."""

from __future__ import annotations

import json
from pathlib import Path

from cli.main import main
from engines.adversary import ADVERSARY_VERSION, run_adversary, write_adversary_report
from engines.adversary.schema import ADVERSARY_STATUSES

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "fixtures" / "adversary_app"
ALLOWED = ADVERSARY_STATUSES


def _by_file(result: dict) -> dict[str, list[dict]]:
    out: dict[str, list[dict]] = {}
    for f in result.get("findings") or []:
        name = Path(str((f.get("location") or {}).get("file") or "")).name
        if name:
            out.setdefault(name, []).append(f)
    return out


def test_run_adversary_statuses_allowed():
    result = run_adversary(FIXTURE)
    assert result["schema_version"] == ADVERSARY_VERSION
    assert result["tool"] == "axguard"
    summary = result["summary"]
    assert summary["finding_count"] == len(result["findings"])
    for f in result["findings"]:
        assert f.get("status") in ALLOWED, f.get("status")


def test_true_positive_not_wiped():
    result = run_adversary(FIXTURE)
    by_file = _by_file(result)
    for name in ("sql_tainted.py", "ssrf_tainted.py"):
        statuses = [f["status"] for f in by_file.get(name, [])]
        assert statuses, f"expected findings for {name}"
        assert any(s in {"CONFIRMED", "LIKELY"} for s in statuses), statuses


def test_parameterized_becomes_false_positive():
    result = run_adversary(FIXTURE)
    by_file = _by_file(result)
    hits = by_file.get("sql_parameterized.py") or []
    assert hits, "expected parameterized SQL finding"
    assert any(f["status"] == "FALSE_POSITIVE" for f in hits)
    for f in hits:
        assert f["status"] != "CONFIRMED"


def test_ignore_instruction_comment_does_not_force_fp():
    result = run_adversary(FIXTURE)
    by_file = _by_file(result)
    hits = by_file.get("ignore_comment_vuln.py") or []
    assert hits, "expected finding next to ignore-instruction comment"
    assert all(f["status"] != "FALSE_POSITIVE" for f in hits)
    assert any(f["status"] in {"CONFIRMED", "LIKELY", "REQUIRES_REVIEW"} for f in hits)


def test_noop_sanitize_not_auto_fp():
    result = run_adversary(FIXTURE)
    by_file = _by_file(result)
    hits = by_file.get("noop_sanitize.py") or []
    assert hits, "expected finding for noop sanitize()"
    assert all(f["status"] != "FALSE_POSITIVE" for f in hits)


def test_ambiguous_requires_review_or_unverified():
    result = run_adversary(FIXTURE)
    by_file = _by_file(result)
    hits = by_file.get("ambiguous.py") or []
    assert hits, "expected ambiguous finding"
    assert all(f["status"] in {"REQUIRES_REVIEW", "UNVERIFIED"} for f in hits)


def test_expected_json_cases():
    expected = json.loads((FIXTURE / "expected.json").read_text(encoding="utf-8"))
    result = run_adversary(FIXTURE)
    by_file = _by_file(result)

    for case in expected["cases"]:
        name = case["file"]
        findings = by_file.get(name, [])
        statuses = [f["status"] for f in findings]
        if case.get("allow_no_candidates") and not statuses:
            continue
        forbid = set(case.get("forbid_status") or [])
        assert not (forbid & set(statuses)), f"{name} has forbidden {statuses}"
        want = set(case["expect_status"])
        if statuses:
            assert set(statuses) & want, f"{name}: got {statuses}, want any of {want}"


def test_no_secrets_in_dump(tmp_path: Path):
    result = run_adversary(FIXTURE)
    paths = write_adversary_report(result, tmp_path)
    dump = Path(paths["json"]).read_text(encoding="utf-8")
    assert "Co-authored-by" not in dump
    assert "Made with Cursor" not in dump
    assert "sk_live" not in dump
    assert "AKIA" not in dump
    assert (tmp_path / "adversary.md").exists()
    md = (tmp_path / "adversary.md").read_text(encoding="utf-8")
    assert "diagnostic" in md.lower()


def test_cli_adversary_smoke(tmp_path: Path, capsys):
    code = main(["adversary", str(FIXTURE), "--out-dir", str(tmp_path), "--no-banner"])
    assert code == 0
    out = capsys.readouterr().out
    assert "findings" in out.lower() or "CONFIRMED" in out
    assert (tmp_path / "adversary.json").exists()
    assert (tmp_path / "adversary.md").exists()
