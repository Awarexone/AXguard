"""Tests for AXGuard Security Twin (`engines/twin`).

Driven by ``fixtures/security_twin/expected.json`` against
``fixtures/attack_paths_app``. Library APIs are exercised end-to-end;
CLI ``twin`` is xfailed until wired in ``cli/main.py``.
"""

from __future__ import annotations

import ast
import json
from functools import lru_cache
from pathlib import Path

import pytest

from engines.twin import (
    FACT_LAYERS,
    SECURITY_TWIN_VERSION,
    answer_query,
    build_security_twin,
    control_effectiveness,
    entity_blast_radius,
    export_twin_examples,
    list_scenarios,
    run_counterfactual,
    run_twin,
    run_twin_compare,
    simulate_attack,
    twin_regression,
    virtual_attacker,
    write_twin_report,
)
from engines.twin.schema import (
    LAYER_ASSUMED,
    LAYER_INFERRED,
    LAYER_OBSERVED,
    LAYER_SIMULATED,
    PERM_UNKNOWN,
)

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "fixtures" / "attack_paths_app"
EXPECTED_PATH = ROOT / "fixtures" / "security_twin" / "expected.json"
TWIN_PKG = ROOT / "engines" / "twin"


@lru_cache(maxsize=1)
def _expected() -> dict:
    return json.loads(EXPECTED_PATH.read_text(encoding="utf-8"))


@lru_cache(maxsize=1)
def _twin() -> dict:
    return build_security_twin(FIXTURE)


def _path_status_counts(twin: dict) -> dict[str, int]:
    counts: dict[str, int] = {}
    for p in (twin.get("attack_graph") or {}).get("paths") or []:
        st = str(p.get("status") or "UNKNOWN")
        counts[st] = counts.get(st, 0) + 1
    return counts


# ---------------------------------------------------------------------------
# Build / schema
# ---------------------------------------------------------------------------
def test_build_security_twin_deterministic_schema_version():
    twin_a = build_security_twin(FIXTURE)
    twin_b = build_security_twin(FIXTURE)
    assert twin_a["schema_version"] == SECURITY_TWIN_VERSION
    assert twin_b["schema_version"] == SECURITY_TWIN_VERSION
    assert twin_a["schema_version"] == twin_b["schema_version"]
    assert twin_a["tool"] == "axguard"
    assert twin_a["summary"] == twin_b["summary"]
    assert twin_a["disclaimer"]


def test_expected_json_golden_summary():
    expected = _expected()
    twin = _twin()
    assert twin["schema_version"] == expected["schema_version"]
    assert twin["tool"] == expected["tool"]
    for key, want in expected["summary"].items():
        assert twin["summary"][key] == want, f"summary.{key}: got {twin['summary'][key]}, want {want}"
    assert _path_status_counts(twin) == expected["attack_graph_path_status"]


def test_fact_layers_present_on_entities():
    twin = _twin()
    assert twin["entities"], "twin must have entities"
    for ent in twin["entities"]:
        assert ent.get("layer") in FACT_LAYERS, f"entity {ent.get('id')} missing valid layer"
        for key, val in ent.items():
            if isinstance(val, dict) and "layer" in val:
                assert val["layer"] in FACT_LAYERS, f"{ent.get('id')}.{key} bad layer"


def test_prefer_unknown_tool_permissions_without_evidence():
    twin = _twin()
    tools = [
        e
        for e in twin["entities"]
        if e.get("type") == "AITool" or e.get("ag_type") == "tool"
    ]
    assert tools, "fixture should expose at least one AI tool"
    for tool in tools:
        perm = tool.get("permission_class")
        assert isinstance(perm, dict), f"{tool.get('id')} missing tagged permission_class"
        assert perm.get("value") == PERM_UNKNOWN
        assert perm.get("layer") in {LAYER_INFERRED, LAYER_ASSUMED}


def test_no_network_client_imports_in_twin_package():
    banned = {"urllib", "requests", "httpx"}
    offenders: list[str] = []
    for path in sorted(TWIN_PKG.glob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    root = alias.name.split(".")[0]
                    if root in banned:
                        offenders.append(f"{path.name}: import {alias.name}")
            elif isinstance(node, ast.ImportFrom) and node.module:
                root = node.module.split(".")[0]
                if root in banned:
                    offenders.append(f"{path.name}: from {node.module}")
    assert not offenders, "engines/twin must not import network clients:\n" + "\n".join(offenders)


# ---------------------------------------------------------------------------
# Simulate / attacker / OBSERVED vs SIMULATED
# ---------------------------------------------------------------------------
def test_simulate_attack_separates_observed_and_simulated():
    twin = _twin()
    sim = simulate_attack(twin)
    assert "observed_paths" in sim and "simulated_paths" in sim
    assert "disclaimer" in sim
    exp = _expected()["simulation"]
    assert len(sim["observed_paths"]) >= exp["min_observed_paths"]
    assert len(sim["simulated_paths"]) >= exp["min_simulated_paths"]

    for p in sim["observed_paths"]:
        assert p["layer"] == LAYER_OBSERVED
        status = p["status"]
        assert isinstance(status, dict)
        assert status["layer"] == LAYER_OBSERVED
        assert status["value"] == "CONFIRMED"

    for p in sim["simulated_paths"]:
        assert p["layer"] == LAYER_SIMULATED
        status = p["status"]
        assert isinstance(status, dict)
        assert status["layer"] == LAYER_SIMULATED
        assert status["value"] != "CONFIRMED"

    observed_ids = {p.get("path_id") for p in sim["observed_paths"]}
    simulated_ids = {p.get("path_id") for p in sim["simulated_paths"]}
    assert not (observed_ids & simulated_ids), "path must not appear in both buckets"


def test_virtual_attacker_tagged_assumed():
    twin = _twin()
    attacker = virtual_attacker("PUBLIC_USER", twin)
    assert attacker["profile"]["layer"] == LAYER_ASSUMED
    assert attacker["starting_identity"]["layer"] == LAYER_ASSUMED
    assert attacker["trust_level"]["layer"] == LAYER_ASSUMED
    assert attacker["description"]["layer"] == LAYER_ASSUMED
    assert attacker["layer"] in {LAYER_ASSUMED, LAYER_SIMULATED}
    assert "disclaimer" in attacker

    # Capabilities are hypothetical
    assert attacker["capabilities"]["layer"] in {LAYER_ASSUMED, LAYER_SIMULATED}


# ---------------------------------------------------------------------------
# Counterfactual
# ---------------------------------------------------------------------------
def test_run_counterfactual_remove_authz():
    twin = _twin()
    cf = run_counterfactual(twin, scenario="remove_authz")
    assert cf["scenario"]["value"] == "remove_authz"
    assert cf["scenario"]["layer"] == LAYER_ASSUMED
    assert cf["observed_summary"]["layer"] == LAYER_OBSERVED
    assert isinstance(cf["simulated_paths"], list)
    for p in cf["simulated_paths"]:
        assert p["layer"] == LAYER_SIMULATED
        assert p.get("hypothetical") is True
    assert "disclaimer" in cf


def test_run_counterfactual_tenant_isolation_weakened():
    twin = _twin()
    cf = run_counterfactual(twin, scenario="tenant_isolation_weakened")
    assert cf["scenario"]["value"] == "tenant_isolation_weakened"
    assert cf["scenario"]["layer"] == LAYER_ASSUMED
    assert isinstance(cf["simulated_paths"], list)
    # Observed summary must stay distinct from simulated paths
    assert cf["observed_summary"]["layer"] == LAYER_OBSERVED
    for p in cf["simulated_paths"]:
        assert p["layer"] == LAYER_SIMULATED


def test_counterfactual_does_not_mutate_twin():
    twin = _twin()
    before = json.dumps(twin["summary"], sort_keys=True)
    run_counterfactual(twin, scenario="remove_authz")
    after = json.dumps(twin["summary"], sort_keys=True)
    assert before == after


# ---------------------------------------------------------------------------
# Controls / blast radius
# ---------------------------------------------------------------------------
def test_control_effectiveness_returns_list():
    twin = _twin()
    controls = control_effectiveness(twin)
    assert isinstance(controls, list)
    assert controls, "attack_paths_app should surface control nodes"
    for c in controls:
        assert "control_id" in c
        assert c.get("layer") == LAYER_OBSERVED
        assert isinstance(c["protected_path_count"], dict)
        assert c["protected_path_count"]["layer"] == LAYER_OBSERVED


def test_entity_blast_radius_known_and_missing():
    twin = _twin()
    nodes = ((twin.get("attack_graph") or {}).get("graph") or {}).get("nodes") or []
    assert nodes
    known_id = str(nodes[0]["id"])

    known = entity_blast_radius(twin, known_id)
    assert known["entity_id"] == known_id
    assert known["blast"].get("exists") is True
    assert known["layer"] == LAYER_OBSERVED
    assert isinstance(known["impact_classifications"], list)

    missing = entity_blast_radius(twin, "definitely-missing-node-xyz-99")
    assert missing["blast"].get("exists") is False
    assert missing["layer"] == LAYER_INFERRED
    assert missing["impact_classifications"] == []


# ---------------------------------------------------------------------------
# Query intents
# ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    "question,intent",
    [
        ("What is the blast radius of the primary agent?", "blast_radius"),
        ("Which controls protect the most paths?", "controls_protect"),
        ("Are there cross-tenant attack paths?", "cross_tenant"),
        ("What if authorization control is removed?", "counterfactual"),
    ],
)
def test_answer_query_intents(question: str, intent: str):
    twin = _twin()
    result = answer_query(twin, question)
    assert result["intent"] == intent
    assert result["question"] == question
    assert "answer" in result
    assert "evidence_refs" in result
    if intent == "counterfactual":
        assert result["layer"] == LAYER_SIMULATED
    else:
        assert result["layer"] == LAYER_OBSERVED


# ---------------------------------------------------------------------------
# Regression / compare
# ---------------------------------------------------------------------------
def test_twin_regression_same_fixture_minimal_delta():
    twin_a = build_security_twin(FIXTURE)
    twin_b = build_security_twin(FIXTURE)
    reg = twin_regression(twin_a, twin_b)
    assert reg["observed_change_count"] == 0
    assert reg["changes"] == []
    assert "disclaimer" in reg


def test_run_twin_compare_same_fixture_empty_delta():
    twin_a = build_security_twin(FIXTURE)
    twin_b = build_security_twin(FIXTURE)
    cmp = run_twin_compare(twin_a, twin_b)
    assert "regression" in cmp
    assert cmp["regression"]["changes"] == []
    assert cmp["regression"]["observed_change_count"] == 0


# ---------------------------------------------------------------------------
# Export / scenarios / report
# ---------------------------------------------------------------------------
def test_export_twin_examples_nonempty_qa():
    twin = _twin()
    examples = export_twin_examples(twin)
    assert len(examples) >= _expected()["export_examples_min"]
    for ex in examples:
        assert ex.get("question"), "example must have a question"
        assert "answer" in ex
        assert ex.get("labels", {}).get("status") == "EVALUATION_ONLY"
        assert ex.get("fact_layers")


def test_list_scenarios_nonempty():
    scenarios = list_scenarios()
    assert len(scenarios) >= _expected()["scenarios_min"]
    assert len(scenarios) >= 12
    keys = {s["key"] for s in scenarios}
    assert "authz_regression" in keys
    assert "cross_tenant_agent" in keys
    for s in scenarios:
        assert "title" in s
        assert "description" in s


def test_write_twin_report_creates_json_md_html(tmp_path: Path):
    result = run_twin(FIXTURE)
    paths = write_twin_report(result, tmp_path)
    assert Path(paths["json"]).is_file()
    assert Path(paths["markdown"]).is_file()
    assert Path(paths["html"]).is_file()
    assert (tmp_path / "security-twin.json").exists()
    assert (tmp_path / "security-twin.md").exists()
    assert (tmp_path / "security-twin.html").exists()

    payload = json.loads(Path(paths["json"]).read_text(encoding="utf-8"))
    assert "twin" in payload
    md = Path(paths["markdown"]).read_text(encoding="utf-8")
    assert "Security Twin" in md
    html = Path(paths["html"]).read_text(encoding="utf-8")
    assert "axguard-security-twin" in html


def test_run_twin_pipeline_write_report(tmp_path: Path):
    result = run_twin(FIXTURE, write_report=tmp_path)
    assert "twin" in result
    assert "simulation" in result
    assert "controls" in result
    assert (tmp_path / "security-twin.json").exists()


# ---------------------------------------------------------------------------
# CLI smoke
# ---------------------------------------------------------------------------
def _cli_twin_wired() -> bool:
    try:
        import cli.main as main_mod

        src = Path(main_mod.__file__).read_text(encoding="utf-8")
        return '"twin"' in src or "'twin'" in src
    except Exception:  # noqa: BLE001
        return False


@pytest.mark.xfail(
    not _cli_twin_wired(),
    reason="CLI twin command not wired in cli/main.py yet",
    strict=False,
)
def test_cli_twin_build_smoke(tmp_path: Path):
    from cli.main import main

    code = main(
        ["twin", "build", str(FIXTURE), "--out-dir", str(tmp_path), "--no-banner"]
    )
    assert code == 0
    assert (tmp_path / "security-twin.json").exists()
    assert (tmp_path / "security-twin.md").exists()
    assert (tmp_path / "security-twin.html").exists()
