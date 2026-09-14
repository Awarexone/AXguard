"""Security posture graph summary (Phase 6 Part 2).

Rolls the attack-graph node/edge graph into a single eight-stage narrative
pipeline:

    Entry -> Trust -> Controls -> Weak -> Vulns -> Priv -> Assets -> Impact

This is a different lens from ``paths[]`` (which reads "can an attacker get
from A to B") and from ``aggregate.py`` (which reads "how much risk is
there, grouped which ways") — posture reads "what does the whole surface
look like, stage by stage": how many entrypoints, how many trust boundaries
they cross, how many controls exist and how many of those are actually
effective ("Weak" is the subset that is not), how many vulnerabilities feed
into the graph, how much privilege/tenant crossing is possible, what assets
are reachable, and what the aggregate impact picture is.

No new node/edge/status vocabulary is invented here — every count in this
module is read straight off ``schema.py`` node types, ``EFFECT_*`` control
effectiveness, and ``PATH_*`` statuses that Phase 6 already computed.

Standalone by design: nothing in this module is wired into
``engines/attack_graph/pipeline.py``. Callers opt in explicitly, e.g.::

    from engines.attack_graph import run_attack_graph
    from engines.attack_graph.posture import build_posture_summary

    result = run_attack_graph(target)
    posture = build_posture_summary(result)
"""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timezone
from typing import Any

from engines.attack_graph.schema import (
    ASSET_IMPACT_TIER,
    EFFECT_CONFIRMED,
    EFFECT_INEFFECTIVE,
    EFFECT_LIKELY,
    EFFECT_UNKNOWN,
    PATH_CONFIRMED,
    PATH_LIKELY,
)

POSTURE_VERSION = "1.0.0"

STAGE_ORDER = ["entry", "trust", "controls", "weak", "vulns", "priv", "assets", "impact"]

_CREDIBLE_STATUSES = frozenset({PATH_CONFIRMED, PATH_LIKELY})
_WEAK_EFFECTIVENESS = frozenset({EFFECT_INEFFECTIVE, EFFECT_UNKNOWN})
_HIGH_IMPACT_ASSET_KINDS = frozenset(
    kind for kind, weight in ASSET_IMPACT_TIER.items() if weight >= 0.75
)


def build_posture_summary(result: dict[str, Any]) -> dict[str, Any]:
    """Build the eight-stage posture summary for one attack-graph ``result``."""
    graph = result.get("graph") or {}
    nodes: list[dict[str, Any]] = graph.get("nodes") or []
    edges: list[dict[str, Any]] = graph.get("edges") or []
    paths: list[dict[str, Any]] = result.get("paths") or []

    by_type: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for n in nodes:
        by_type[str(n.get("type"))].append(n)

    stages = {
        "entry": _entry_stage(by_type.get("entrypoint", [])),
        "trust": _trust_stage(by_type.get("trust_boundary", []), edges),
        "controls": _controls_stage(by_type.get("control", [])),
        "weak": _weak_stage(by_type.get("control", [])),
        "vulns": _vulns_stage(by_type.get("finding", []) + by_type.get("candidate_seed", [])),
        "priv": _priv_stage(by_type.get("identity", []), edges),
        "assets": _assets_stage(by_type.get("asset", [])),
        "impact": _impact_stage(paths, by_type.get("asset", [])),
    }

    return {
        "schema_version": POSTURE_VERSION,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "target": result.get("target"),
        "flow": STAGE_ORDER,
        "stages": stages,
        "counts": {stage: stages[stage].get("count", 0) for stage in STAGE_ORDER},
        "posture_rating": _posture_rating(stages, paths),
        "narrative": _narrative(stages, paths),
    }


# ---------------------------------------------------------------------------
# Entry — HTTP routes, webhooks, queue consumers, CLI entries
# ---------------------------------------------------------------------------
def _entry_stage(entrypoints: list[dict[str, Any]]) -> dict[str, Any]:
    by_reachability: dict[str, int] = defaultdict(int)
    by_authentication: dict[str, int] = defaultdict(int)
    for e in entrypoints:
        by_reachability[str(e.get("reachability") or "unknown")] += 1
        by_authentication[str(e.get("authentication") or "unknown")] += 1
    return {
        "count": len(entrypoints),
        "by_reachability": dict(sorted(by_reachability.items())),
        "by_authentication": dict(sorted(by_authentication.items())),
        "entries": [
            {
                "id": e.get("id"),
                "label": e.get("label"),
                "reachability": e.get("reachability"),
                "authentication": e.get("authentication"),
            }
            for e in entrypoints
        ],
    }


# ---------------------------------------------------------------------------
# Trust — boundaries crossed (internet<->app, tenant<->tenant, agent<->tool)
# ---------------------------------------------------------------------------
def _trust_stage(boundaries: list[dict[str, Any]], edges: list[dict[str, Any]]) -> dict[str, Any]:
    crossings = [e for e in edges if e.get("type") in {"reaches", "crosses_tenant"}]
    return {
        "count": len(boundaries),
        "crossing_edge_count": len(crossings),
        "reaches_edge_count": sum(1 for e in edges if e.get("type") == "reaches"),
        "crosses_tenant_edge_count": sum(1 for e in edges if e.get("type") == "crosses_tenant"),
        "boundaries": [{"id": b.get("id"), "label": b.get("label")} for b in boundaries],
        "crossings": [
            {"type": e.get("type"), "from": e.get("from"), "to": e.get("to"), "confidence": e.get("confidence")}
            for e in crossings
        ],
    }


# ---------------------------------------------------------------------------
# Controls — every barrier candidate detected, regardless of effectiveness
# ---------------------------------------------------------------------------
def _controls_stage(controls: list[dict[str, Any]]) -> dict[str, Any]:
    by_effectiveness: dict[str, int] = defaultdict(int)
    for c in controls:
        by_effectiveness[str(c.get("effectiveness") or "unknown")] += 1
    return {
        "count": len(controls),
        "by_effectiveness": dict(sorted(by_effectiveness.items())),
        "controls": [
            {
                "id": c.get("id"),
                "label": c.get("label"),
                "kind": c.get("kind"),
                "effectiveness": c.get("effectiveness"),
                "location": c.get("location") or {},
            }
            for c in controls
        ],
    }


# ---------------------------------------------------------------------------
# Weak — the subset of controls that do NOT actually block anything
# ---------------------------------------------------------------------------
def _weak_stage(controls: list[dict[str, Any]]) -> dict[str, Any]:
    weak = [c for c in controls if str(c.get("effectiveness")) in _WEAK_EFFECTIVENESS]
    return {
        "count": len(weak),
        "of_total_controls": len(controls),
        "weak_controls": [
            {
                "id": c.get("id"),
                "label": c.get("label"),
                "effectiveness": c.get("effectiveness"),
                "reason": ((c.get("evidence") or [{}])[0]).get("description"),
            }
            for c in weak
        ],
    }


# ---------------------------------------------------------------------------
# Vulns — finding + candidate_seed nodes feeding the graph
# ---------------------------------------------------------------------------
def _vulns_stage(findings: list[dict[str, Any]]) -> dict[str, Any]:
    by_status: dict[str, int] = defaultdict(int)
    by_kind: dict[str, int] = defaultdict(int)
    for f in findings:
        by_status[str(f.get("status") or "unknown")] += 1
        by_kind[str(f.get("kind") or "unknown")] += 1
    return {
        "count": len(findings),
        "by_status": dict(sorted(by_status.items())),
        "by_kind": dict(sorted(by_kind.items())),
        "findings": [
            {
                "id": f.get("id"),
                "label": f.get("label"),
                "kind": f.get("kind"),
                "status": f.get("status"),
                "origin": f.get("origin", "adversary"),
            }
            for f in findings
        ],
    }


# ---------------------------------------------------------------------------
# Priv — identities, roles, and privilege-escalation edges
# ---------------------------------------------------------------------------
def _priv_stage(identities: list[dict[str, Any]], edges: list[dict[str, Any]]) -> dict[str, Any]:
    escalation_edges = [e for e in edges if e.get("type") == "escalates_to"]
    tenants = sorted({str(i.get("tenant")) for i in identities if i.get("tenant")})
    return {
        "count": len(identities),
        "escalation_edge_count": len(escalation_edges),
        "tenant_count": len(tenants),
        "tenants": tenants,
        "identities": [
            {"id": i.get("id"), "label": i.get("label"), "role": i.get("role"), "tenant": i.get("tenant")}
            for i in identities
        ],
        "escalations": [{"from": e.get("from"), "to": e.get("to")} for e in escalation_edges],
    }


# ---------------------------------------------------------------------------
# Assets — sensitive resources reachable in the graph
# ---------------------------------------------------------------------------
def _assets_stage(assets: list[dict[str, Any]]) -> dict[str, Any]:
    by_kind: dict[str, int] = defaultdict(int)
    high_impact = 0
    for a in assets:
        kind = str(a.get("kind") or "unknown")
        by_kind[kind] += 1
        if kind in _HIGH_IMPACT_ASSET_KINDS:
            high_impact += 1
    return {
        "count": len(assets),
        "high_impact_count": high_impact,
        "by_kind": dict(sorted(by_kind.items())),
        "assets": [
            {"id": a.get("id"), "label": a.get("label"), "kind": a.get("kind")} for a in assets
        ],
    }


# ---------------------------------------------------------------------------
# Impact — what the credible paths actually amount to
# ---------------------------------------------------------------------------
def _impact_stage(paths: list[dict[str, Any]], assets: list[dict[str, Any]]) -> dict[str, Any]:
    asset_kind_by_id = {a.get("id"): a.get("kind") for a in assets}
    credible = [p for p in paths if p.get("status") in _CREDIBLE_STATUSES]
    credible_high_impact = [
        p for p in credible if asset_kind_by_id.get(p.get("target")) in _HIGH_IMPACT_ASSET_KINDS
    ]
    top = sorted(paths, key=lambda p: -(p.get("score") or 0.0))[:5]
    return {
        "count": len(credible_high_impact),
        "credible_path_count": len(credible),
        "credible_high_impact_path_count": len(credible_high_impact),
        "max_score": max((p.get("score") or 0.0) for p in paths) if paths else 0.0,
        "top_paths": [
            {"id": p.get("id"), "status": p.get("status"), "score": p.get("score"), "target": p.get("target")}
            for p in top
        ],
    }


# ---------------------------------------------------------------------------
# posture rating + narrative
# ---------------------------------------------------------------------------
def _posture_rating(stages: dict[str, Any], paths: list[dict[str, Any]]) -> str:
    impact = stages.get("impact") or {}
    if impact.get("credible_high_impact_path_count", 0) > 0:
        return "AT_RISK"
    if not paths:
        return "NO_OBSERVED_EXPOSURE"
    if impact.get("credible_path_count", 0) == 0:
        return "BLOCKED_OR_UNVERIFIED_ONLY"
    return "MIXED"


def _narrative(stages: dict[str, Any], paths: list[dict[str, Any]]) -> list[str]:
    entry = stages["entry"]
    trust = stages["trust"]
    controls = stages["controls"]
    weak = stages["weak"]
    vulns = stages["vulns"]
    priv = stages["priv"]
    assets = stages["assets"]
    impact = stages["impact"]

    lines = [
        f"Entry: {entry['count']} entrypoint(s) observed "
        f"({dict(entry['by_reachability'])}).",
        f"Trust: {trust['count']} trust boundary node(s), "
        f"{trust['crossing_edge_count']} boundary-crossing edge(s) "
        f"({trust['reaches_edge_count']} reaches, {trust['crosses_tenant_edge_count']} crosses_tenant).",
        f"Controls: {controls['count']} control(s) detected "
        f"({dict(controls['by_effectiveness'])}).",
        f"Weak: {weak['count']} of those {weak['of_total_controls']} control(s) are ineffective/unknown "
        "and do not actually block their path.",
        f"Vulns: {vulns['count']} finding/candidate node(s) feed the graph "
        f"({dict(vulns['by_status'])}).",
        f"Priv: {priv['count']} identity node(s), {priv['escalation_edge_count']} escalation edge(s), "
        f"{priv['tenant_count']} tenant(s) referenced.",
        f"Assets: {assets['count']} asset(s) reachable, {assets['high_impact_count']} high-impact "
        "(credential/secret/token/admin/filesystem).",
        f"Impact: {impact['credible_path_count']} CONFIRMED/LIKELY path(s), "
        f"{impact['credible_high_impact_path_count']} of which reach a high-impact asset.",
        f"Overall posture: {_posture_rating(stages, paths)}.",
    ]
    return lines


# ---------------------------------------------------------------------------
# optional markdown rendering (not wired into engines/report.py or writers.py)
# ---------------------------------------------------------------------------
def render_posture_markdown(summary: dict[str, Any]) -> str:
    lines = [
        "# AXguard security posture (diagnostic)",
        "",
        "`" + " -> ".join(s.capitalize() for s in summary.get("flow") or []) + "`",
        "",
        f"**Posture rating:** `{summary.get('posture_rating')}`",
        "",
        "## Narrative",
        "",
    ]
    for n in summary.get("narrative") or []:
        lines.append(f"- {n}")
    lines.append("")

    lines.extend(["## Stage counts", "", "| Stage | Count |", "| --- | ---: |"])
    for stage in summary.get("flow") or []:
        lines.append(f"| {stage.capitalize()} | {(summary.get('counts') or {}).get(stage, 0)} |")
    lines.append("")
    return "\n".join(lines)
