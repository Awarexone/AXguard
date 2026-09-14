"""Tests for Phase 5 Evidence & Confidence engine."""

from __future__ import annotations

import json
from pathlib import Path

from cli.main import main
from engines.evidence import (
    EVIDENCE_VERSION,
    get_confidence,
    get_conflicts,
    get_counter_evidence,
    get_evidence,
    get_evidence_chain,
    get_supporting_evidence,
    get_unknowns,
    run_evidence,
    write_evidence_report,
)
from engines.evidence.confidence import compute_confidence, propagate_confidence
from engines.evidence.llm_stub import LLMEvidenceStub
from engines.evidence.schema import (
    CONF_HIGH,
    CONF_MEDIUM,
    EV_DATA_FLOW,
    EV_REACHABILITY,
    EV_SINK,
    EV_SOURCE,
    REL_SUPPORTING,
    UNKNOWN_LOCATION,
    evidence_item,
)
from engines.evidence.store import EvidenceStore

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "fixtures" / "evidence_app"


def _by_file(result: dict) -> dict[str, list[dict]]:
    out: dict[str, list[dict]] = {}
    for e in result.get("findings_evidence") or []:
        name = Path(str((e.get("location") or {}).get("file") or "")).name
        if name:
            out.setdefault(name, []).append(e)
    return out


# ---------------------------------------------------------------------------
# Pipeline / schema
# ---------------------------------------------------------------------------
def test_run_evidence_schema_and_shape():
    result = run_evidence(FIXTURE)
    assert result["schema_version"] == EVIDENCE_VERSION
    assert result["tool"] == "axguard"
    assert "findings_evidence" in result
    assert "evidence_store" in result
    assert "summary" in result
    assert "_adversary" in result  # private ref preserved for callers
    summary = result["summary"]
    assert summary["finding_count"] == len(result["findings_evidence"])
    for entry in result["findings_evidence"]:
        # backward-compat: legacy confidence preserved, new fields added
        assert "legacy_confidence" in entry
        assert entry.get("confidence_level") in {
            "VERY_HIGH",
            "HIGH",
            "MEDIUM",
            "LOW",
            "UNKNOWN",
        }


def test_strong_evidence_high_confidence():
    result = run_evidence(FIXTURE)
    hits = _by_file(result).get("sql_tainted.py") or []
    assert hits, "expected sql_tainted finding"
    assert any(h["confidence_level"] in {"HIGH", "VERY_HIGH"} for h in hits)


def test_parameterized_low_confidence_and_counter_evidence():
    result = run_evidence(FIXTURE)
    hits = _by_file(result).get("sql_parameterized.py") or []
    assert hits
    for h in hits:
        assert h["confidence_level"] in {"LOW", "UNKNOWN"}
        assert h["is_false_positive"] is True


def test_missing_evidence_pulls_to_unknown():
    result = run_evidence(FIXTURE)
    hits = _by_file(result).get("ambiguous.py") or []
    assert hits, "expected ambiguous finding"
    for h in hits:
        assert h["confidence_level"] in {"UNKNOWN", "LOW", "MEDIUM"}
        assert h["unknowns"], "ambiguous case must record unknowns"
        assert h["evidence_confidence"]["capped_by_unknown"] is True


def test_noop_sanitize_not_boosted_and_flagged():
    result = run_evidence(FIXTURE)
    hits = _by_file(result).get("noop_sanitize.py") or []
    assert hits
    for h in hits:
        assert not h["is_false_positive"]
        # name-only control must be recorded as an unknown, never as safety.
        assert any("name-only" in u for u in h["unknowns"])


def test_comment_never_becomes_evidence_of_safety():
    result = run_evidence(FIXTURE)
    hits = _by_file(result).get("ignore_comment_vuln.py") or []
    assert hits
    for h in hits:
        assert not h["is_false_positive"]
        counters = get_counter_evidence(result, h["finding_id"])
        for c in counters:
            assert "ignore" not in str(c.get("description", "")).lower()
            assert c.get("kind") != "ignored_comment"


def test_supporting_and_counter_split():
    result = run_evidence(FIXTURE)
    hits = _by_file(result).get("sql_tainted.py") or []
    fid = hits[0]["finding_id"]
    support = get_supporting_evidence(result, fid)
    assert support, "true positive must have supporting evidence"
    all_ev = get_evidence(result, fid)
    assert len(all_ev) >= len(support)


def test_conflict_detected_and_requires_review():
    result = run_evidence(FIXTURE)
    hits = _by_file(result).get("conflict_case.py") or []
    assert hits, "expected conflict_case finding"
    entry = hits[0]
    conflicts = get_conflicts(result, entry["finding_id"])
    assert conflicts, "auth-missing-locally vs global-middleware must conflict"
    assert any(c["resolution"] == "REQUIRES_REVIEW" for c in conflicts)
    assert entry.get("conflict_handling") == "REQUIRES_REVIEW"


def test_exact_locations_recorded():
    result = run_evidence(FIXTURE)
    hits = _by_file(result).get("sql_tainted.py") or []
    support = get_supporting_evidence(result, hits[0]["finding_id"])
    sinks = [e for e in support if e.get("type") == EV_SINK]
    assert sinks, "expected a SINK evidence item"
    sink = sinks[0]
    assert sink["file"].endswith("sql_tainted.py")
    assert sink["line_start"] and sink["line_start"] > 0


def test_unknown_location_marked_explicitly():
    result = run_evidence(FIXTURE)
    # ambiguous.py has no request source in scope → an UNKNOWN-location item.
    store = result["evidence_store"]
    assert any(v.get("file") == UNKNOWN_LOCATION for v in store.values())


def test_evidence_chain_stages():
    result = run_evidence(FIXTURE)
    hits = _by_file(result).get("sql_tainted.py") or []
    chain = get_evidence_chain(result, hits[0]["finding_id"])
    stages = [c["stage"] for c in chain]
    for expected in ("finding", "source", "flow", "sink", "reachability", "judgment"):
        assert expected in stages
    for step in chain:
        assert "present" in step and isinstance(step["present"], bool)


def test_get_confidence_components_present():
    result = run_evidence(FIXTURE)
    hits = _by_file(result).get("sql_tainted.py") or []
    conf = get_confidence(result, hits[0]["finding_id"])
    assert conf is not None
    for comp in (
        "source_certainty",
        "data_flow_certainty",
        "sink_certainty",
        "reachability",
        "security_control_certainty",
        "control_effectiveness",
        "framework_certainty",
        "configuration_certainty",
        "counter_evidence",
    ):
        assert comp in conf["components"], comp


# ---------------------------------------------------------------------------
# Store: dedupe / reuse / freshness
# ---------------------------------------------------------------------------
def test_store_dedupe_same_item():
    store = EvidenceStore()
    item = evidence_item(
        type=EV_SOURCE, description="req", file="a.py", line_start=3, symbol="q"
    )
    id1 = store.add(dict(item))
    id2 = store.add(dict(item))
    assert id1 == id2
    assert len(store.all()) == 1
    assert store.reuse_count(id1) == 2


def test_store_reuse_across_findings_in_pipeline():
    result = run_evidence(FIXTURE)
    assert result["summary"]["reused_evidence_count"] > 0
    assert result["summary"]["unique_evidence_count"] < result["summary"]["evidence_count"]


def test_store_stale_content_hash_invalidates():
    store = EvidenceStore()
    item = evidence_item(
        type=EV_SOURCE,
        description="same key",
        file="a.py",
        line_start=10,
        symbol="q",
        snippet="old = request.args",
    )
    eid = store.add(dict(item))
    assert not store.is_stale(eid)
    # same dedupe key, different snippet → different content_hash → stale.
    moved = evidence_item(
        type=EV_SOURCE,
        description="same key",
        file="a.py",
        line_start=10,
        symbol="q",
        snippet="old = request.form   # content changed",
    )
    eid2 = store.add(dict(moved))
    assert eid2 == eid  # same logical location
    assert store.is_stale(eid)
    assert store.get(eid)["revision"] == 2
    assert not store.is_fresh(item)  # the original content is no longer current


# ---------------------------------------------------------------------------
# Confidence: reduction + propagation + no-hidden-unknown rule
# ---------------------------------------------------------------------------
def test_one_high_component_cannot_hide_critical_unknown():
    refs = [
        {"id": "1", "type": EV_SOURCE, "quality": "UNKNOWN", "relationship": REL_SUPPORTING},
        {"id": "2", "type": EV_SINK, "quality": "DIRECT", "relationship": REL_SUPPORTING},
        {"id": "3", "type": EV_DATA_FLOW, "quality": "STRONG", "relationship": REL_SUPPORTING},
        {"id": "4", "type": EV_REACHABILITY, "quality": "STRONG", "relationship": REL_SUPPORTING},
    ]
    conf = compute_confidence({"status": "CONFIRMED", "control_analysis": {}}, refs)
    assert conf["capped_by_unknown"] is True
    assert "source_certainty" in conf["critical_unknowns"]
    # A strong SINK/FLOW must not lift this above MEDIUM.
    from engines.evidence.schema import CONFIDENCE_RANK

    assert CONFIDENCE_RANK[conf["level"]] <= CONFIDENCE_RANK[CONF_MEDIUM]


def test_full_strong_confirmed_reaches_very_high():
    refs = [
        {"id": "1", "type": EV_SOURCE, "quality": "STRONG", "relationship": REL_SUPPORTING},
        {"id": "2", "type": EV_SINK, "quality": "DIRECT", "relationship": REL_SUPPORTING},
        {"id": "3", "type": EV_DATA_FLOW, "quality": "STRONG", "relationship": REL_SUPPORTING},
        {"id": "4", "type": EV_REACHABILITY, "quality": "STRONG", "relationship": REL_SUPPORTING},
    ]
    conf = compute_confidence({"status": "CONFIRMED", "control_analysis": {}}, refs)
    assert conf["level"] == "VERY_HIGH"


def test_confidence_propagation_demotes_shared_weak_evidence():
    store = EvidenceStore()
    weak = evidence_item(
        type=EV_SOURCE, description="shared weak", file="s.py", line_start=1, quality="WEAK"
    )
    eid = store.add(dict(weak))
    entries = [
        {
            "finding_id": "f1",
            "supporting_evidence_ids": [eid],
            "confidence_level": CONF_MEDIUM,
            "evidence_confidence": {"level": CONF_MEDIUM, "unknowns": [], "reasons": []},
        },
        {
            "finding_id": "f2",
            "supporting_evidence_ids": [eid],
            "confidence_level": CONF_MEDIUM,
            "evidence_confidence": {"level": CONF_MEDIUM, "unknowns": [], "reasons": []},
        },
    ]
    propagate_confidence(entries, store)
    for e in entries:
        assert e["evidence_confidence"]["propagated"] is True
        assert e["evidence_confidence"]["level"] == "LOW"
        assert any("shared" in u for u in e["evidence_confidence"]["unknowns"])


# ---------------------------------------------------------------------------
# LLM stub — must never invent evidence
# ---------------------------------------------------------------------------
def test_llm_stub_cannot_invent_evidence():
    store = EvidenceStore()
    item = evidence_item(type=EV_SINK, description="sink", file="a.py", line_start=2)
    eid = store.add(dict(item))
    stub = LLMEvidenceStub()

    # No evidence → REQUIRES_REVIEW, nothing invented.
    empty = stub.explain([], store)
    assert empty["verdict"] == "REQUIRES_REVIEW"
    assert empty["invented_evidence"] is False
    assert empty["evidence_ids"] == []

    # Explains only what exists.
    explained = stub.explain([eid], store)
    assert explained["verdict"] == "EXPLAINED"
    assert explained["invented_evidence"] is False
    assert explained["evidence_ids"] == [eid]

    # Inventing is explicitly unsupported.
    try:
        stub.invent()
        raised = False
    except NotImplementedError:
        raised = True
    assert raised


# ---------------------------------------------------------------------------
# expected.json cases
# ---------------------------------------------------------------------------
def test_expected_json_cases():
    expected = json.loads((FIXTURE / "expected.json").read_text(encoding="utf-8"))
    result = run_evidence(FIXTURE)
    by_file = _by_file(result)

    for case in expected["cases"]:
        name = case["file"]
        entries = by_file.get(name, [])
        if case.get("allow_no_candidates") and not entries:
            continue
        assert entries, f"expected evidence for {name}"
        levels = {e["confidence_level"] for e in entries}

        if case.get("expect_confidence"):
            want = set(case["expect_confidence"])
            assert levels & want, f"{name}: got {levels}, want any of {want}"
        if case.get("forbid_confidence"):
            forbid = set(case["forbid_confidence"])
            assert not (forbid & levels), f"{name}: forbidden {levels & forbid}"
        if case.get("expect_false_positive"):
            assert any(e["is_false_positive"] for e in entries), name
        if case.get("forbid_false_positive"):
            assert all(not e["is_false_positive"] for e in entries), name
        if case.get("expect_unknowns"):
            assert any(e["unknowns"] for e in entries), name
        if case.get("expect_name_only_unknown"):
            assert any(
                any("name-only" in u for u in e["unknowns"]) for e in entries
            ), name
        if case.get("expect_conflict"):
            assert any(e["conflicts"] for e in entries), name
            resolutions = {
                c["resolution"] for e in entries for c in e["conflicts"]
            }
            want_res = set(case.get("expect_conflict_resolution") or [])
            if want_res:
                assert resolutions & want_res, f"{name}: {resolutions}"


# ---------------------------------------------------------------------------
# Writers / secrets / CLI
# ---------------------------------------------------------------------------
def test_no_secrets_in_dump(tmp_path: Path):
    result = run_evidence(FIXTURE)
    paths = write_evidence_report(result, tmp_path)
    dump = Path(paths["json"]).read_text(encoding="utf-8")
    assert "Co-authored-by" not in dump
    assert "Made with Cursor" not in dump
    assert "sk_live" not in dump
    assert "AKIA" not in dump
    assert (tmp_path / "evidence.md").exists()
    md = (tmp_path / "evidence.md").read_text(encoding="utf-8")
    assert "diagnostic" in md.lower()


def test_cli_evidence_smoke(tmp_path: Path, capsys):
    code = main(["evidence", str(FIXTURE), "--out-dir", str(tmp_path), "--no-banner"])
    assert code == 0
    out = capsys.readouterr().out
    assert "evidence" in out.lower()
    assert (tmp_path / "evidence.json").exists()
    assert (tmp_path / "evidence.md").exists()


# ---------------------------------------------------------------------------
# Backward compatibility — earlier phases still import & run
# ---------------------------------------------------------------------------
def test_existing_phases_still_importable():
    from engines.adversary import ADVERSARY_VERSION, run_adversary
    from engines.dataflow import DATAFLOW_VERSION  # noqa: F401
    from engines.verify import VERIFICATION_VERSION  # noqa: F401

    assert ADVERSARY_VERSION
    # Evidence reuses the adversary result without breaking its fields.
    adv = run_adversary(FIXTURE)
    ev = run_evidence(FIXTURE, adversary=adv)
    assert ev["summary"]["finding_count"] == len(adv["findings"])
    for f in adv["findings"]:
        assert "status" in f and "confidence" in f  # untouched legacy fields
