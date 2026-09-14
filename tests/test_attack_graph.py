"""Tests for Phase 6 Attack Graph & Vulnerability Chaining engine.

Driven by ``fixtures/attack_paths_app/expected.json``. The attack graph is a
composition layer: these tests assert that findings chain (or correctly refuse
to chain) into the statuses the design contract requires, without inventing a
second confidence system and without fabricating chains from co-location.
"""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path

from cli.main import main
from engines.attack_graph import (
    ATTACK_GRAPH_VERSION,
    render_attack_paths_markdown,
    run_attack_graph,
    write_attack_graph_report,
)
from engines.attack_graph.llm_stub import LLMAttackPathStub
from engines.attack_graph.schema import PATH_STATUSES
from engines.evidence import run_evidence

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "fixtures" / "attack_paths_app"


@lru_cache(maxsize=1)
def _result() -> dict:
    return run_attack_graph(FIXTURE)


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
# Pipeline / schema shape
# ---------------------------------------------------------------------------
def test_run_attack_graph_schema_and_shape():
    result = _result()
    assert result["schema_version"] == ATTACK_GRAPH_VERSION
    assert result["tool"] == "axguard"
    assert "graph" in result and "nodes" in result["graph"] and "edges" in result["graph"]
    assert "paths" in result
    assert "dead_ends" in result
    assert "alternate_paths" in result
    assert "_evidence" in result  # private ref preserved for callers
    for p in result["paths"]:
        assert p["status"] in PATH_STATUSES
        assert p["confidence_level"] in {"VERY_HIGH", "HIGH", "MEDIUM", "LOW", "UNKNOWN"}
        assert p["hops"], "every path must have hops"


def test_edges_carry_confidence_and_evidence():
    result = _result()
    for e in result["graph"]["edges"]:
        assert e["confidence"] in {"confirmed", "likely", "unknown"}
        assert "evidence" in e  # never a bare boolean link


# ---------------------------------------------------------------------------
# expected.json cases
# ---------------------------------------------------------------------------
def test_expected_json_cases():
    expected = json.loads((FIXTURE / "expected.json").read_text(encoding="utf-8"))
    result = _result()

    for case in expected["cases"]:
        name = case["file"]
        paths = _paths_for_file(result, name)

        if case.get("expect_path_exists"):
            assert paths, f"{name}: expected at least one attack path"
            statuses = {p["status"] for p in paths}
            want = set(case.get("expect_status") or [])
            if want:
                assert statuses & want, f"{name}: got {statuses}, want any of {want}"
            forbid = set(case.get("forbid_status") or [])
            if forbid:
                # No path for this file may carry a forbidden status.
                assert not (forbid & statuses), f"{name}: forbidden status present {forbid & statuses}"
        else:
            # false_chain: same-file co-location must not become a chain.
            assert not paths, f"{name}: expected NO attack path, got {[p['id'] for p in paths]}"


def test_simple_chain_confirmed_or_likely():
    paths = _paths_for_file(_result(), "simple_chain.py")
    assert paths
    assert any(p["status"] in {"CONFIRMED", "LIKELY"} for p in paths)


def test_multi_chain_ssrf_to_internal_to_creds():
    paths = _paths_for_file(_result(), "multi_chain.py")
    assert paths
    p = next(pp for pp in paths if "ssrf_chain" in (pp.get("tags") or []))
    assert p["status"] in {"CONFIRMED", "LIKELY"}
    # 3-hop shape: entrypoint -> ssrf -> internal endpoint -> credential asset
    nodes = _nodes_by_id(_result())
    types = [nodes[h]["type"] for h in p["hops"] if h in nodes]
    assert types.count("entrypoint") >= 2, "SSRF chain must cross into a second (internal) entrypoint"
    assert any(nodes[h].get("kind") == "credential" for h in p["hops"] if h in nodes)


def test_blocked_path_is_blocked_not_confirmed_for_unauth():
    paths = _paths_for_file(_result(), "blocked_path.py")
    assert paths
    statuses = {p["status"] for p in paths}
    assert "BLOCKED" in statuses
    assert "CONFIRMED" not in statuses, "unauth attacker path must be BLOCKED, not CONFIRMED"
    # the effective control must be recorded as a barrier on the path
    blocked = next(p for p in paths if p["status"] == "BLOCKED")
    effs = {c.get("effectiveness") for c in blocked.get("controls_encountered") or []}
    assert "confirmed" in effs


def test_unknown_reachability_is_unverified():
    paths = _paths_for_file(_result(), "unknown_reachability.py")
    assert paths
    statuses = {p["status"] for p in paths}
    assert statuses == {"UNVERIFIED"} or "UNVERIFIED" in statuses
    assert "CONFIRMED" not in statuses
    assert "BLOCKED" not in statuses
    assert "INVALID" not in statuses


def test_false_chain_produces_no_linking_path():
    result = _result()
    paths = _paths_for_file(result, "false_chain.py")
    assert not paths, "same-file co-located findings must not be chained"
    # Belt-and-suspenders: no single path may contain BOTH the xss route and the
    # path-traversal route.
    nodes = _nodes_by_id(result)
    for p in result["paths"]:
        files = {Path(str((nodes.get(h) or {}).get("location", {}).get("file") or "")).name for h in p["hops"]}
        handlers = {
            (nodes.get(h) or {}).get("handler")
            for h in p["hops"]
            if (nodes.get(h) or {}).get("type") == "entrypoint"
        }
        if "false_chain.py" in files:
            assert not ({"search", "download_report"} <= handlers)


def test_priv_esc_path_exists():
    paths = _paths_for_file(_result(), "priv_esc.py")
    assert paths
    assert any(p["status"] in {"CONFIRMED", "LIKELY"} for p in paths)
    assert any("priv_esc" in (p.get("tags") or []) for p in paths)


def test_cross_tenant_path_exists():
    paths = _paths_for_file(_result(), "cross_tenant.py")
    assert paths
    assert any(p["status"] in {"CONFIRMED", "LIKELY"} for p in paths)
    # crosses_tenant edge must be present
    result = _result()
    ct = next(p for p in paths if "cross_tenant" in (p.get("tags") or []))
    assert "crosses_tenant" in (ct.get("edge_types") or [])


def test_ai_chain_path_exists():
    result = _result()
    paths = _paths_for_file(result, "ai_chain.py")
    assert paths
    ai = next(p for p in paths if "ai_chain" in (p.get("tags") or []))
    assert ai["status"] in {"CONFIRMED", "LIKELY"}
    # invokes + yields edges (prompt injection -> agent -> tool -> secret)
    assert "invokes" in (ai.get("edge_types") or [])
    assert "yields" in (ai.get("edge_types") or [])
    nodes = _nodes_by_id(result)
    kinds = {nodes[h]["type"] for h in ai["hops"] if h in nodes}
    assert {"ai_component", "tool"} <= kinds


# ---------------------------------------------------------------------------
# Honesty guarantees
# ---------------------------------------------------------------------------
def test_no_false_positive_hop_is_treated_as_confirmed():
    result = _result()
    nodes = _nodes_by_id(result)
    for p in result["paths"]:
        for h in p["hops"]:
            n = nodes.get(h) or {}
            if n.get("type") in {"finding", "candidate_seed"}:
                assert n.get("status") != "FALSE_POSITIVE"


def test_structural_seeds_never_confirmed():
    result = _result()
    for n in result["graph"]["nodes"]:
        if n.get("type") == "candidate_seed":
            assert n.get("status") in {"LIKELY", "UNVERIFIED"}
            assert n.get("origin") == "attack_graph_seed"


def test_llm_stub_cannot_invent():
    result = _result()
    stub = LLMAttackPathStub()

    # No hops → REQUIRES_REVIEW, nothing invented.
    empty = stub.explain({"hops": []}, result["graph"])
    assert empty["verdict"] == "REQUIRES_REVIEW"
    assert empty["invented"] is False
    assert empty["hops"] == []

    # Explains only existing nodes.
    path = result["paths"][0]
    explained = stub.explain(path, result["graph"])
    assert explained["verdict"] == "EXPLAINED"
    assert explained["invented"] is False
    assert explained["hops"], "explains the real hops"

    # Inventing is explicitly unsupported.
    raised = False
    try:
        stub.invent()
    except NotImplementedError:
        raised = True
    assert raised


# ---------------------------------------------------------------------------
# Writers / secrets / CLI
# ---------------------------------------------------------------------------
def test_no_secrets_in_dump(tmp_path: Path):
    result = _result()
    paths = write_attack_graph_report(result, tmp_path)
    dump = Path(paths["json"]).read_text(encoding="utf-8")
    assert "Co-authored-by" not in dump
    assert "Made with Cursor" not in dump
    assert "sk_live" not in dump
    assert "AKIA" not in dump
    assert "_evidence" not in dump  # private ref must not be serialized
    md = (tmp_path / "attack-paths.md").read_text(encoding="utf-8")
    assert "diagnostic" in md.lower()


def test_markdown_renders():
    md = render_attack_paths_markdown(_result())
    assert "attack path" in md.lower()
    assert "Status distribution" in md


def test_cli_paths_smoke(tmp_path: Path, capsys):
    code = main(["paths", str(FIXTURE), "--out-dir", str(tmp_path), "--no-banner"])
    assert code == 0
    out = capsys.readouterr().out
    assert "attack graph" in out.lower()
    assert (tmp_path / "attack-paths.json").exists()
    assert (tmp_path / "attack-paths.md").exists()


def test_cli_paths_alias_smoke(tmp_path: Path):
    code = main(["attack-paths", str(FIXTURE), "--out-dir", str(tmp_path), "--no-banner"])
    assert code == 0
    assert (tmp_path / "attack-paths.json").exists()


# ---------------------------------------------------------------------------
# Backward compatibility — earlier phases still import & run
# ---------------------------------------------------------------------------
def test_existing_phases_still_importable():
    from engines.adversary import ADVERSARY_VERSION, run_adversary
    from engines.dataflow import DATAFLOW_VERSION  # noqa: F401
    from engines.evidence import EVIDENCE_VERSION, run_evidence  # noqa: F401
    from engines.verify import VERIFICATION_VERSION  # noqa: F401

    assert ADVERSARY_VERSION
    # Attack graph reuses the evidence result without breaking its fields.
    ev = run_evidence(FIXTURE)
    ag = run_attack_graph(FIXTURE, evidence=ev)
    assert ag["meta"]["adversary_finding_count"] == len(ev["_adversary"]["findings"])
    for f in ev["_adversary"]["findings"]:
        assert "status" in f and "confidence" in f  # untouched legacy fields


def test_reuses_evidence_without_rebuild():
    ev = run_evidence(FIXTURE)
    ag = run_attack_graph(FIXTURE, evidence=ev)
    # same evidence object is threaded through (not rebuilt)
    assert ag["_evidence"] is ev


