"""Tests for Phase 3 Hunter → Judge verification engine."""

from __future__ import annotations

import json
from pathlib import Path

from cli.main import main
from engines.verify import VERIFICATION_VERSION, run_verification, write_verification_report
from engines.verify.schema import JUDGMENT_STATUSES

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "fixtures" / "verify_app"
ALLOWED = JUDGMENT_STATUSES


def test_run_verification_statuses_and_counts():
    result = run_verification(FIXTURE)
    assert result["schema_version"] == VERIFICATION_VERSION
    assert result["tool"] == "axguard"
    summary = result["summary"]
    assert summary["candidate_count"] == len(result["candidates"])
    assert summary.get("judgment_count", len(result["judgments"])) == len(
        result["judgments"]
    )

    for j in result["judgments"]:
        assert j.get("status") in ALLOWED, j.get("status")


def test_tainted_unsafe_paths_verified_or_likely():
    result = run_verification(FIXTURE)
    hits = []
    for j in result["judgments"]:
        cand = next(c for c in result["candidates"] if c["id"] == j["candidate_id"])
        file_s = str((cand.get("location") or {}).get("file") or "")
        if "sql_tainted" in file_s or "ssrf_tainted" in file_s:
            hits.append(j["status"])
    assert hits, "expected judgments for tainted fixture files"
    assert any(s in {"VERIFIED", "LIKELY"} for s in hits)


def test_parameterized_sql_not_verified():
    result = run_verification(FIXTURE)
    for j in result["judgments"]:
        cand = next(c for c in result["candidates"] if c["id"] == j["candidate_id"])
        file_s = str((cand.get("location") or {}).get("file") or "")
        if "sql_parameterized" in file_s or "sanitized" in file_s:
            assert j["status"] != "VERIFIED"
            assert j["status"] in {"FALSE_POSITIVE", "UNVERIFIED", "LIKELY"}


def test_comment_only_never_verified():
    result = run_verification(FIXTURE)
    for j in result["judgments"]:
        cand = next(c for c in result["candidates"] if c["id"] == j["candidate_id"])
        file_s = str((cand.get("location") or {}).get("file") or "")
        if "comment_only" in file_s or "false_positive" in file_s:
            assert j["status"] != "VERIFIED"


def test_expected_json_cases():
    expected = json.loads((FIXTURE / "expected.json").read_text(encoding="utf-8"))
    result = run_verification(FIXTURE)
    by_file: dict[str, list[str]] = {}
    for j in result["judgments"]:
        cand = next(c for c in result["candidates"] if c["id"] == j["candidate_id"])
        file_s = str((cand.get("location") or {}).get("file") or "")
        name = Path(file_s).name
        by_file.setdefault(name, []).append(j["status"])

    for case in expected["cases"]:
        name = case["file"]
        statuses = by_file.get(name, [])
        if case.get("allow_no_candidates") and not statuses:
            continue
        forbid = set(case.get("forbid_status") or [])
        assert not (forbid & set(statuses)), f"{name} has forbidden {statuses}"
        want = set(case["expect_status"])
        if statuses:
            assert set(statuses) & want, f"{name}: got {statuses}, want any of {want}"


def test_no_coauthor_or_secrets_in_json_dump(tmp_path: Path):
    result = run_verification(FIXTURE)
    paths = write_verification_report(result, tmp_path)
    dump = Path(paths["json"]).read_text(encoding="utf-8")
    assert "Co-authored-by" not in dump
    assert "Made with Cursor" not in dump
    assert "sk_live" not in dump
    assert "AKIA" not in dump
    assert (tmp_path / "verification.md").exists()
    md = (tmp_path / "verification.md").read_text(encoding="utf-8")
    assert "diagnostic" in md.lower()


def test_cli_verify_smoke(tmp_path: Path, capsys):
    code = main(["verify", str(FIXTURE), "--out-dir", str(tmp_path), "--no-banner"])
    assert code == 0
    out = capsys.readouterr().out
    assert "candidates" in out.lower() or "VERIFIED" in out
    assert (tmp_path / "verification.json").exists()
    assert (tmp_path / "verification.md").exists()
