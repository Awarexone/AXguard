"""Smoke tests for Phase 4 False Positive Adversary."""

from __future__ import annotations

from pathlib import Path

from engines.adversary import ADVERSARY_VERSION, run_adversary, write_adversary_report
from engines.adversary.schema import ADVERSARY_STATUSES

ROOT = Path(__file__).resolve().parents[1]
VERIFY_APP = ROOT / "fixtures" / "verify_app"
DATAFLOW_APP = ROOT / "fixtures" / "dataflow_app"


def test_adversary_verify_app_smoke(tmp_path: Path):
    result = run_adversary(VERIFY_APP)
    assert result["schema_version"] == ADVERSARY_VERSION
    assert result["tool"] == "axguard"
    assert result["summary"]["finding_count"] == len(result["findings"])

    for f in result["findings"]:
        assert f.get("status") in ADVERSARY_STATUSES, f.get("status")

    # True positives must survive
    statuses_by_file: dict[str, list[str]] = {}
    for f in result["findings"]:
        name = Path(str((f.get("location") or {}).get("file") or "")).name
        statuses_by_file.setdefault(name, []).append(str(f["status"]))

    for name in ("sql_tainted.py", "ssrf_tainted.py"):
        hits = statuses_by_file.get(name) or []
        assert hits, f"expected findings for {name}"
        assert any(s in {"CONFIRMED", "LIKELY"} for s in hits), (name, hits)
        assert "FALSE_POSITIVE" not in hits, (name, hits)

    # Parameterized SQL stays FP (Judge FP passthrough or adversary FP)
    param = statuses_by_file.get("sql_parameterized.py") or []
    if param:
        assert all(s != "CONFIRMED" for s in param)
        assert any(s == "FALSE_POSITIVE" for s in param)

    paths = write_adversary_report(result, tmp_path)
    dump = Path(paths["json"]).read_text(encoding="utf-8")
    assert "Co-authored-by" not in dump
    assert (tmp_path / "adversary.md").exists()
    assert (tmp_path / "final-findings.json").exists()


def test_adversary_dataflow_app_smoke():
    result = run_adversary(DATAFLOW_APP)
    assert result["summary"]["finding_count"] == len(result["findings"])
    for f in result["findings"]:
        assert f.get("status") in ADVERSARY_STATUSES

    by_file: dict[str, list[str]] = {}
    for f in result["findings"]:
        name = Path(str((f.get("location") or {}).get("file") or "")).name
        by_file.setdefault(name, []).append(str(f["status"]))

    for name in ("sql_tainted.py", "ssrf_tainted.py"):
        hits = by_file.get(name) or []
        assert hits, f"expected findings for {name}"
        assert any(s in {"CONFIRMED", "LIKELY"} for s in hits), (name, hits)
