"""Tests for Phase 6 Part 2 — attack-path INTELLIGENCE foundation.

These cover the new reasoning layers built *over* the Part 1 chains without
rewriting them: bounded graph search, three-valued precondition logic,
identity / state / privilege transitions, sensitivity weighting, search modes,
blast radius, choke points, fix-impact, equivalence, explanation and the public
``api`` surface. The Part 1 suite (``test_attack_graph.py``) must keep passing
unchanged; nothing here mutates the enumerated ``paths[]``.
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from engines.attack_graph import api, run_attack_graph
from engines.attack_graph import logic, modes, search
from engines.attack_graph import blast, choke, equivalence, explain, fix_impact
from engines.attack_graph import identity as identity_mod
from engines.attack_graph import privilege as privilege_mod
from engines.attack_graph import sensitivity_data
from engines.attack_graph.schema import (
    MODE_CONFIRMED_AND_LIKELY,
    MODE_CONFIRMED_ONLY,
    MODE_INCLUDE_UNKNOWN,
    PRIV_CONFUSED_DEPUTY,
    PRIV_HORIZONTAL,
    PRIV_VERTICAL,
    TRUTH_FALSE,
    TRUTH_TRUE,
    TRUTH_UNKNOWN,
)

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "fixtures" / "attack_paths_app"


@lru_cache(maxsize=1)
def _result() -> dict:
    return run_attack_graph(FIXTURE)


def _graph() -> dict:
    return _result()["graph"]


def _path_by_tag(tag: str) -> dict:
    for p in _result()["paths"]:
        if tag in (p.get("tags") or []):
            return p
    raise AssertionError(f"no path tagged {tag!r}")


# ---------------------------------------------------------------------------
# 1. Bounded BFS finds a simple path WITHOUT inventing edges
# ---------------------------------------------------------------------------
def test_bfs_finds_simple_path_without_inventing_edges():
    graph = _graph()
    p = _path_by_tag("sql_injection")
    entry, target = p["entry"], p["target"]

    node_path = search.bfs_shortest_path(graph, entry, target)
    assert node_path, "BFS must find the simple_chain entry→asset path"
    assert node_path[0] == entry and node_path[-1] == target

    # every hop of the returned path must be a REAL edge in the graph
    real_edges = {(str(e["from"]), str(e["to"])) for e in graph["edges"]}
    for a, b in zip(node_path, node_path[1:]):
        assert (str(a), str(b)) in real_edges, f"BFS invented edge {a}->{b}"

    # a target that is not reachable returns None (never a fabricated path)
    assert search.bfs_shortest_path(graph, entry, "asset:does_not_exist") is None


def test_search_prunes_effective_control_edges():
    # blocked_path: the reaches edge is blocked by an effective control, so a
    # search from the internet must NOT reach the gated asset.
    graph = _graph()
    p = _path_by_tag("sql_injection")  # simple chain is reachable
    assert search.bfs_shortest_path(graph, "internet", p["target"]) is not None
    # the blocked revenue_reports asset is not reachable from the internet
    blocked = next(pp for pp in _result()["paths"] if pp["status"] == "BLOCKED")
    assert search.bfs_shortest_path(graph, "internet", blocked["target"]) is None


# ---------------------------------------------------------------------------
# 2. AND/OR three-valued logic — UNKNOWN is never TRUE
# ---------------------------------------------------------------------------
def test_logic_unknown_is_not_true():
    t = logic.atom("x", "a", truth=TRUTH_TRUE)
    u = logic.atom("y", "b", truth=TRUTH_UNKNOWN)
    f = logic.atom("z", "c", truth=TRUTH_FALSE)

    # AND with an unknown operand is UNKNOWN, not TRUE
    assert logic.evaluate(logic.and_(t, u)) == TRUTH_UNKNOWN
    assert not logic.is_satisfied(logic.and_(t, u))
    # AND with a false operand is FALSE
    assert logic.evaluate(logic.and_(t, f)) == TRUTH_FALSE
    # all-true AND is TRUE
    assert logic.evaluate(logic.and_(t, t)) == TRUTH_TRUE
    assert logic.is_satisfied(logic.and_(t, t))

    # OR with only unknown/false operands is never TRUE
    assert logic.evaluate(logic.or_(u, f)) == TRUTH_UNKNOWN
    assert not logic.is_satisfied(logic.or_(u, f))
    # OR with a true operand is TRUE
    assert logic.evaluate(logic.or_(u, t)) == TRUTH_TRUE


def test_authenticated_reaches_precondition_is_unknown_not_true():
    from engines.attack_graph import preconditions

    expr = preconditions.reaches_precondition_expr("authenticated", "required")
    # an attacker holding an authenticated session is UNKNOWN from static
    # evidence — the OR of "self-registered" / "stolen" is not asserted TRUE.
    assert logic.evaluate(expr) == TRUTH_UNKNOWN
    # a public entrypoint IS attacker-satisfied
    pub = preconditions.reaches_precondition_expr("public", "none")
    assert logic.evaluate(pub) == TRUTH_TRUE


# ---------------------------------------------------------------------------
# 3. choke points / blast radius / fix impact
# ---------------------------------------------------------------------------
def test_blast_radius_reaches_sensitive_asset():
    graph = _graph()
    p = _path_by_tag("sql_injection")
    radius = blast.get_blast_radius(graph, p["entry"])
    assert radius["exists"]
    assert p["target"] in radius["reachable"], "asset must be in the blast radius"
    assert radius["node_count"] >= 1
    assert radius["max_impact_weight"] > 0.0
    # a non-existent origin yields an empty, honest result
    missing = blast.get_blast_radius(graph, "node:nope")
    assert missing["exists"] is False and missing["node_count"] == 0


def test_choke_points_detects_shared_node():
    # synthetic 2-path graph sharing finding F — F is the choke point.
    graph = {
        "nodes": [
            {"id": "e1", "type": "entrypoint"},
            {"id": "e2", "type": "entrypoint"},
            {"id": "F", "type": "finding", "status": "CONFIRMED", "label": "shared bug"},
            {"id": "a1", "type": "asset", "kind": "pii"},
        ],
        "edges": [
            {"from": "e1", "to": "F", "type": "triggers"},
            {"from": "e2", "to": "F", "type": "triggers"},
            {"from": "F", "to": "a1", "type": "exposes"},
        ],
    }
    paths = [
        {"id": "p1", "hops": ["e1", "F", "a1"], "controls_encountered": []},
        {"id": "p2", "hops": ["e2", "F", "a1"], "controls_encountered": []},
    ]
    points = choke.get_choke_points(graph, paths)
    ids = [c["id"] for c in points]
    assert "F" in ids
    top = points[0]
    assert top["id"] == "F" and top["path_count"] == 2


def test_minimal_cut_covers_all_paths_on_fixture():
    graph = _graph()
    paths = _result()["paths"]
    cut = choke.minimal_cut(graph, paths)
    covered = {pid for entry in cut for pid in entry["covers"]}
    assert covered == {p["id"] for p in paths}, "greedy cut must cover every path"


def test_fix_impact_finding_removes_paths_control_weakens():
    graph = _graph()
    paths = _result()["paths"]
    nodes_by_id = {n["id"]: n for n in graph["nodes"]}

    # fixing a finding removes the path(s) it is on
    p = _path_by_tag("sql_injection")
    finding_id = next(
        h for h in p["hops"] if nodes_by_id[h]["type"] in {"finding", "candidate_seed"}
    )
    impact = fix_impact.analyze_fix_impact(graph, paths, finding_id)
    assert impact["kind"] in {"finding", "candidate_seed"}
    assert p["id"] in impact["paths_removed"]

    # hardening a control weakens (blocks) the path(s) it gates
    control = next((n for n in graph["nodes"] if n["type"] == "control"), None)
    assert control is not None
    cimpact = fix_impact.analyze_fix_impact(graph, paths, control)
    assert cimpact["kind"] == "control"
    assert cimpact["effect"] == "block"
    assert cimpact["paths_weakened"], "a control fix should weaken at least one path"


# ---------------------------------------------------------------------------
# 4. search modes filter statuses
# ---------------------------------------------------------------------------
def test_search_modes_filter_statuses():
    paths = _result()["paths"]

    confirmed = modes.filter_paths(paths, MODE_CONFIRMED_ONLY)
    assert confirmed and all(p["status"] == "CONFIRMED" for p in confirmed)

    credible = modes.filter_paths(paths, MODE_CONFIRMED_AND_LIKELY)
    assert all(p["status"] in {"CONFIRMED", "LIKELY"} for p in credible)
    assert set(p["id"] for p in confirmed) <= set(p["id"] for p in credible)

    incl = modes.filter_paths(paths, MODE_INCLUDE_UNKNOWN)
    assert all(p["status"] in {"CONFIRMED", "LIKELY", "UNVERIFIED"} for p in incl)

    # BLOCKED / INVALID are never live in any mode
    for mode in (MODE_CONFIRMED_ONLY, MODE_CONFIRMED_AND_LIKELY, MODE_INCLUDE_UNKNOWN):
        assert not any(p["status"] in {"BLOCKED", "INVALID"} for p in modes.filter_paths(paths, mode))

    # the written paths[] artifact itself is never filtered
    assert len(paths) == len(_result()["paths"])


def test_pipeline_records_search_mode_without_filtering_paths():
    full = run_attack_graph(FIXTURE)
    restricted = run_attack_graph(FIXTURE, search_mode=MODE_CONFIRMED_ONLY)
    assert restricted["search_mode"] == MODE_CONFIRMED_ONLY
    # search_mode changes the posture view, NOT the enumerated path set
    assert len(restricted["paths"]) == len(full["paths"])
    assert restricted["posture"]["live_path_count"] <= full["posture"]["live_path_count"]


# ---------------------------------------------------------------------------
# 5. confused deputy / AI paths tagged when present
# ---------------------------------------------------------------------------
def test_confused_deputy_paths_flagged():
    result = _result()
    deputy = api.get_confused_deputy_paths(result)
    ai_path = _path_by_tag("ai_chain")
    ssrf_path = _path_by_tag("ssrf_chain")
    # both the agent-tool chain and the SSRF chain are confused-deputy shapes
    assert ai_path["id"] in deputy
    assert ssrf_path["id"] in deputy
    patterns = {t["pattern"] for t in api.get_privilege_transitions(result)}
    assert PRIV_CONFUSED_DEPUTY in patterns


def test_ai_attack_paths_detected():
    result = _result()
    ai_paths = api.get_ai_attack_paths(result)
    assert ai_paths, "the ai_chain fixture must surface an AI attack path"
    ai = _path_by_tag("ai_chain")
    assert ai["id"] in {p["id"] for p in ai_paths}
    # the AI path reaches AI_CONTEXT-sensitivity components
    sens = api.analyze_path_sensitivity(result, ai["id"])
    assert sens["exists"]


def test_vertical_and_horizontal_privilege_patterns_present():
    result = _result()
    patterns = {t["pattern"] for t in api.get_privilege_transitions(result)}
    assert PRIV_VERTICAL in patterns  # priv_esc: user -> admin
    assert PRIV_HORIZONTAL in patterns  # cross_tenant: tenant A -> B


# ---------------------------------------------------------------------------
# identity / state / sensitivity / equivalence / explain / rejection / api
# ---------------------------------------------------------------------------
def test_identity_and_state_transitions_are_evidence_backed():
    result = _result()
    id_trans = result["identity_transitions"]
    assert id_trans, "expected identity transitions across the fixtures"
    for t in id_trans:
        assert t["from_identity"] != t["to_identity"]
        assert "evidence" in t  # backed by the justifying edge's evidence

    st = result["state_transitions"]
    assert st and all("evidence" in t for t in st)
    # every path lands in some concrete state
    for p in result["paths"]:
        assert api.get_path_state(result, p["id"]) in {
            "UNAUTHENTICATED", "AUTHENTICATED", "AUTHORIZED", "TENANT_SCOPED",
            "PRIVILEGED", "TOOL_EXECUTION", "COMPROMISED", "UNKNOWN",
        }


def test_sensitivity_categorization_and_no_overclaim():
    # a known-secret asset kind maps to SECRET; an unmapped kind stays UNKNOWN
    assert sensitivity_data.categorize_kind("secret") == "SECRET"
    assert sensitivity_data.categorize_kind("credential") == "CREDENTIAL"
    assert sensitivity_data.categorize_kind("mystery-kind") == "UNKNOWN"
    # UNKNOWN must have LOW impact weight, never a high one
    assert sensitivity_data.impact_weight("UNKNOWN") < sensitivity_data.impact_weight("PII")

    assets = api.get_sensitive_assets(_result())
    assert assets
    # sorted by descending impact weight (deterministic)
    weights = [a["impact_weight"] for a in assets]
    assert weights == sorted(weights, reverse=True)


def test_rejected_paths_have_plain_language_reasons():
    result = _result()
    rejected = result["rejected_paths"]
    assert rejected, "the blocked_path fixture must yield a rejected path"
    for r in rejected:
        assert r["status"] in {"BLOCKED", "INVALID"}
        assert r["summary"]
        # api lookup returns the same reason
        assert api.get_rejected_path_reason(result, r["path_id"])["status"] == r["status"]


def test_explain_is_evidence_anchored_and_never_invents():
    result = _result()
    p = result["paths"][0]
    ex = api.explain_path(result, p["id"])
    assert ex["invented"] is False
    assert ex["verdict"] == "EXPLAINED"
    assert ex["steps"], "explanation restates the real hops"
    # unknown path id → REQUIRES_REVIEW, nothing invented
    empty = api.explain_path(result, "path-nope")
    assert empty["invented"] is False


def test_equivalence_groups_cover_all_paths():
    result = _result()
    groups = equivalence.get_equivalent_paths(result["graph"], result["paths"])
    grouped_ids = {pid for g in groups for pid in g["path_ids"]}
    assert grouped_ids == {p["id"] for p in result["paths"]}
    for g in groups:
        assert g["representative"] in g["path_ids"]


def test_temporal_dependencies_are_ordered_and_deterministic():
    result = _result()
    p = result["paths"][0]
    deps = api.get_temporal_dependencies(result, p["id"])
    assert len(deps) == 1
    entry = deps[0]
    assert entry["ordered"] == [str(h) for h in p["hops"]]
    # each step requires its predecessor, in order
    for d in entry["dependencies"]:
        assert d["requires"] and d["step"] and d["order"] >= 1


def test_tenant_boundaries_reported():
    result = _result()
    tb = api.get_tenant_boundaries(result)
    assert tb["crossing_edges"], "cross_tenant fixture must expose a tenant crossing"


# ---------------------------------------------------------------------------
# posture rollup + secrets hygiene on new fields
# ---------------------------------------------------------------------------
def test_posture_rollup_present_and_bounded():
    posture = _result()["posture"]
    assert posture["max_sensitivity_reachable"] in {
        "PUBLIC", "INTERNAL", "CONFIDENTIAL", "AI_CONTEXT", "PII",
        "FINANCIAL", "CREDENTIAL", "SECRET", "UNKNOWN",
    }
    assert posture["live_path_count"] >= 1
    assert isinstance(posture["reachable_identities"], list)


def test_new_fields_carry_no_secrets(tmp_path):
    from engines.attack_graph import write_attack_graph_report

    result = _result()
    paths = write_attack_graph_report(result, tmp_path)
    dump = Path(paths["json"]).read_text(encoding="utf-8")
    for needle in ("sk_live", "AKIA", "Co-authored-by", "Made with Cursor", "_evidence"):
        assert needle not in dump
    # the Part 2 fields are serialized
    import json

    data = json.loads(dump)
    for field in (
        "identity_transitions", "privilege_transitions", "state_transitions",
        "posture", "rejected_paths", "search_mode",
    ):
        assert field in data
