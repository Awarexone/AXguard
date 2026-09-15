"""Risk aggregation summary (Phase 6 Part 2).

Rolls an attack-graph result (the dict returned by
``engines.attack_graph.run_attack_graph``, or an ``attack-paths.json`` loaded
back from disk) up into a decision-ready risk summary: how many findings
exist, what root causes they share, which paths are credible *right now*,
which chains are the highest priority, which paths are currently blocked
(and therefore worth watching), which risks are only "predictive" (blocked
or unverified today, live tomorrow if a control regresses or a prerequisite
resolves), and where the graph's choke points are (nodes many paths pass
through — fix one node, break many chains at once).

This module invents no new confidence/severity/status vocabulary: it only
counts, groups, and cross-references fields Phase 6 already computed
(``schema.py`` / ``confidence.py`` / ``scoring.py`` / ``paths.py``). Grouping
never hides an individual finding — ``findings`` in the returned summary
always lists every finding/candidate_seed node the graph contains, and the
groupings underneath ``grouped`` are lenses on top of that same full list,
not a replacement for it.

Standalone by design: nothing in this module is wired into
``engines/attack_graph/pipeline.py``. Callers opt in explicitly, e.g.::

    from engines.attack_graph import run_attack_graph
    from engines.attack_graph.aggregate import build_risk_summary

    result = run_attack_graph(target)
    risk = build_risk_summary(result)
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from engines.attack_graph.schema import (
    ASSET_IMPACT_TIER,
    PATH_BLOCKED,
    PATH_CONFIRMED,
    PATH_LIKELY,
    PATH_UNVERIFIED,
)

AGGREGATE_VERSION = "1.0.0"

_CREDIBLE_STATUSES = frozenset({PATH_CONFIRMED, PATH_LIKELY})
_FINDING_NODE_TYPES = frozenset({"finding", "candidate_seed"})
# Asset kinds whose ASSET_IMPACT_TIER weight marks them "high impact"
# (credentials/secrets/tokens/admin/filesystem) — mirrors scoring.py's own
# reuse of ASSET_IMPACT_TIER rather than inventing a second tiering scheme.
_HIGH_IMPACT_ASSET_KINDS = frozenset(
    kind for kind, weight in ASSET_IMPACT_TIER.items() if weight >= 0.75
)

# Bound on how many choke points to surface — a ranking aid, not a hard cap
# on anything that would hide data (every finding is still listed in full).
_MAX_CHOKE_POINTS = 25


def build_risk_summary(result: dict[str, Any]) -> dict[str, Any]:
    """Build the risk aggregation summary for one attack-graph ``result``."""
    graph = result.get("graph") or {}
    nodes_by_id: dict[str, dict[str, Any]] = {
        n.get("id"): n for n in graph.get("nodes") or [] if n.get("id")
    }
    paths: list[dict[str, Any]] = result.get("paths") or []
    dead_ends: list[dict[str, Any]] = result.get("dead_ends") or []

    findings = _collect_findings(nodes_by_id, paths, dead_ends)
    credible_paths = [p for p in paths if p.get("status") in _CREDIBLE_STATUSES]
    critical_chains = _critical_chains(paths, nodes_by_id)
    blocked_paths = [p for p in paths if p.get("status") == PATH_BLOCKED]
    predictive_risks = _predictive_risks(paths)
    choke_points = _choke_points(paths, nodes_by_id)

    grouped = {
        "by_root_cause": _group_by_root_cause(findings, paths),
        "by_asset": _group_by_asset(paths, nodes_by_id),
        "by_privilege": _group_by_privilege(paths, nodes_by_id),
        "by_tenant": _group_by_tenant(paths, nodes_by_id),
    }

    return {
        "schema_version": AGGREGATE_VERSION,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "target": result.get("target"),
        "totals": {
            "finding_count": len(findings),
            "path_count": len(paths),
            "dead_end_count": len(dead_ends),
            "credible_path_count": len(credible_paths),
            "critical_chain_count": len(critical_chains),
            "blocked_path_count": len(blocked_paths),
            "predictive_risk_count": len(predictive_risks),
            "choke_point_count": len(choke_points),
        },
        # Never hidden: every finding/candidate_seed node the graph contains,
        # whether or not it made it into a path.
        "findings": findings,
        "credible_paths": [_path_ref(p) for p in credible_paths],
        "critical_chains": critical_chains,
        "blocked_paths": [_path_ref(p) for p in blocked_paths],
        "predictive_risks": predictive_risks,
        "choke_points": choke_points,
        "grouped": grouped,
    }


# ---------------------------------------------------------------------------
# findings (full, ungrouped list — the honesty backstop)
# ---------------------------------------------------------------------------
def _collect_findings(
    nodes_by_id: dict[str, dict[str, Any]],
    paths: list[dict[str, Any]],
    dead_ends: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    path_ids_by_node: dict[str, list[str]] = {}
    for p in paths:
        for hop in p.get("hops") or []:
            path_ids_by_node.setdefault(hop, []).append(p.get("id"))

    findings: dict[str, dict[str, Any]] = {}
    for node_id, n in nodes_by_id.items():
        if n.get("type") not in _FINDING_NODE_TYPES:
            continue
        findings[node_id] = {
            "id": node_id,
            "label": n.get("label"),
            "vulnerability_type": n.get("kind"),
            "status": n.get("status"),
            "confidence_level": n.get("confidence_level"),
            "severity": n.get("severity"),
            "location": n.get("location") or {},
            "root_cause": n.get("root_cause"),
            "origin": n.get("origin", "adversary"),
            "in_path_ids": sorted(set(path_ids_by_node.get(node_id, []))),
            "dead_end": not path_ids_by_node.get(node_id),
        }

    # Dead ends may reference findings that never became graph nodes (no
    # chainable edge at all) — surface them too so nothing is hidden.
    for d in dead_ends:
        fid = d.get("finding")
        if fid and fid not in findings:
            findings[fid] = {
                "id": fid,
                "label": d.get("vulnerability_type"),
                "vulnerability_type": d.get("vulnerability_type"),
                "status": d.get("status"),
                "confidence_level": None,
                "severity": None,
                "location": d.get("location") or {},
                "root_cause": None,
                "origin": "adversary",
                "in_path_ids": [],
                "dead_end": True,
            }

    return sorted(findings.values(), key=lambda f: str(f["id"]))


# ---------------------------------------------------------------------------
# credible / critical / blocked / predictive / choke points
# ---------------------------------------------------------------------------
def _path_ref(p: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": p.get("id"),
        "status": p.get("status"),
        "confidence_level": p.get("confidence_level"),
        "score": p.get("score"),
        "tags": p.get("tags") or [],
        "entry": p.get("entry"),
        "target": p.get("target"),
        "hops": p.get("hops") or [],
    }


def _target_asset_kind(p: dict[str, Any], nodes_by_id: dict[str, dict[str, Any]]) -> str | None:
    target = nodes_by_id.get(p.get("target"))
    if target and target.get("type") == "asset":
        return target.get("kind")
    return None


def _critical_chains(
    paths: list[dict[str, Any]], nodes_by_id: dict[str, dict[str, Any]]
) -> list[dict[str, Any]]:
    """Credible paths that end at a high-impact asset or run through an
    autonomous AI/agent tool call (score_factors.ai_agent_multiplier > 1)."""
    out: list[dict[str, Any]] = []
    for p in paths:
        if p.get("status") not in _CREDIBLE_STATUSES:
            continue
        kind = _target_asset_kind(p, nodes_by_id)
        ai_multiplied = (p.get("score_factors") or {}).get("ai_agent_multiplier", 1.0) > 1.0
        high_impact = kind in _HIGH_IMPACT_ASSET_KINDS
        if not (high_impact or ai_multiplied):
            continue
        reasons = []
        if high_impact:
            reasons.append(f"reaches high-impact asset (kind={kind})")
        if ai_multiplied:
            reasons.append("ends in autonomous AI/agent tool execution")
        out.append({**_path_ref(p), "asset_kind": kind, "reasons": reasons})
    # highest score first — this is a triage-order aid, not a new severity.
    return sorted(out, key=lambda r: -(r.get("score") or 0.0))


def _predictive_risks(paths: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Forward-looking risk: paths that are safe *today* only because of a
    control or an unresolved prerequisite — worth watching, not worth
    ignoring. Never asserts these are currently exploitable."""
    out: list[dict[str, Any]] = []
    for p in paths:
        status = p.get("status")
        if status == PATH_BLOCKED:
            controls = [
                c.get("id")
                for c in p.get("controls_encountered") or []
                if c.get("effectiveness") == "confirmed"
            ]
            out.append(
                {
                    "path_id": p.get("id"),
                    "kind": "blocked_control_regression",
                    "reason": (
                        "currently BLOCKED by an effective control; would resurface "
                        "at its underlying finding status if that control regresses"
                        + (f" ({', '.join(controls)})" if controls else "")
                    ),
                    "watch": controls,
                }
            )
        elif status == PATH_UNVERIFIED:
            out.append(
                {
                    "path_id": p.get("id"),
                    "kind": "unresolved_prerequisite",
                    "reason": (
                        "reachability/prerequisite is unknown; would become live if it "
                        "resolves to attacker-reachable — do not assume safe"
                    ),
                    "watch": [],
                }
            )
    return out


def _choke_points(
    paths: list[dict[str, Any]], nodes_by_id: dict[str, dict[str, Any]]
) -> list[dict[str, Any]]:
    """Nodes shared by more than one path — fixing/hardening one choke point
    can break multiple chains at once. Ranked by how many distinct paths
    pass through the node, ties broken by node id for determinism."""
    counts: dict[str, set[str]] = {}
    for p in paths:
        for hop in set(p.get("hops") or []):
            counts.setdefault(hop, set()).add(p.get("id"))

    points = [
        {
            "node_id": node_id,
            "label": (nodes_by_id.get(node_id) or {}).get("label", node_id),
            "type": (nodes_by_id.get(node_id) or {}).get("type"),
            "path_count": len(path_ids),
            "path_ids": sorted(path_ids),
        }
        for node_id, path_ids in counts.items()
        if len(path_ids) > 1
    ]
    points.sort(key=lambda c: (-c["path_count"], str(c["node_id"])))
    return points[:_MAX_CHOKE_POINTS]


# ---------------------------------------------------------------------------
# grouping — lenses over the full findings/paths lists, never a filter
# ---------------------------------------------------------------------------
def _root_cause_key(rc: Any) -> str:
    if isinstance(rc, dict):
        return str(rc.get("symbol") or f"{rc.get('file')}:{rc.get('line')}")
    return str(rc) if rc else "unknown"


def _group_by_root_cause(
    findings: list[dict[str, Any]], paths: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    groups: dict[str, dict[str, Any]] = {}
    for f in findings:
        key = _root_cause_key(f.get("root_cause"))
        g = groups.setdefault(key, {"root_cause": key, "finding_ids": [], "path_ids": set()})
        g["finding_ids"].append(f["id"])
        g["path_ids"].update(f.get("in_path_ids") or [])
    out = []
    for g in groups.values():
        out.append(
            {
                "root_cause": g["root_cause"],
                "finding_count": len(g["finding_ids"]),
                "finding_ids": sorted(g["finding_ids"]),
                "path_ids": sorted(g["path_ids"]),
            }
        )
    return sorted(out, key=lambda g: (-g["finding_count"], g["root_cause"]))


def _group_by_asset(
    paths: list[dict[str, Any]], nodes_by_id: dict[str, dict[str, Any]]
) -> list[dict[str, Any]]:
    groups: dict[str, dict[str, Any]] = {}
    for p in paths:
        target = nodes_by_id.get(p.get("target")) or {}
        key = str(p.get("target") or "unknown")
        g = groups.setdefault(
            key,
            {
                "asset_id": key,
                "label": target.get("label", key),
                "kind": target.get("kind"),
                "path_ids": [],
                "statuses": set(),
            },
        )
        g["path_ids"].append(p.get("id"))
        g["statuses"].add(p.get("status"))
    out = []
    for g in groups.values():
        out.append(
            {
                "asset_id": g["asset_id"],
                "label": g["label"],
                "kind": g["kind"],
                "path_count": len(g["path_ids"]),
                "path_ids": sorted(g["path_ids"]),
                "statuses": sorted(s for s in g["statuses"] if s),
            }
        )
    return sorted(out, key=lambda g: (-g["path_count"], g["asset_id"]))


def _group_by_privilege(
    paths: list[dict[str, Any]], nodes_by_id: dict[str, dict[str, Any]]
) -> list[dict[str, Any]]:
    """Group by the privilege level required to *enter* the path: an
    identity role hop if present, else the entry node's reachability tier as
    a proxy for privilege required."""
    groups: dict[str, dict[str, Any]] = {}
    for p in paths:
        role = None
        for hop in p.get("hops") or []:
            n = nodes_by_id.get(hop) or {}
            if n.get("type") == "identity" and n.get("role"):
                role = str(n["role"])
                break
        if role is None:
            entry = nodes_by_id.get(p.get("entry")) or {}
            role = str(entry.get("reachability") or "unknown")
        g = groups.setdefault(role, {"privilege": role, "path_ids": []})
        g["path_ids"].append(p.get("id"))
    out = [
        {"privilege": g["privilege"], "path_count": len(g["path_ids"]), "path_ids": sorted(g["path_ids"])}
        for g in groups.values()
    ]
    return sorted(out, key=lambda g: (-g["path_count"], g["privilege"]))


def _group_by_tenant(
    paths: list[dict[str, Any]], nodes_by_id: dict[str, dict[str, Any]]
) -> list[dict[str, Any]]:
    """Group paths by the tenant(s) their identity hops reference. Paths
    with no tenant-scoped identity hop are grouped under "n/a" — this is
    never used to hide a finding, only to answer "which tenants does this
    graph even talk about."""
    groups: dict[str, dict[str, Any]] = {}
    for p in paths:
        tenants = sorted(
            {
                str((nodes_by_id.get(h) or {}).get("tenant"))
                for h in p.get("hops") or []
                if (nodes_by_id.get(h) or {}).get("type") == "identity"
                and (nodes_by_id.get(h) or {}).get("tenant")
            }
        )
        key = ",".join(tenants) if tenants else "n/a"
        g = groups.setdefault(key, {"tenant": key, "crosses_tenant": "crosses_tenant" in (p.get("edge_types") or []), "path_ids": []})
        g["path_ids"].append(p.get("id"))
        if "crosses_tenant" in (p.get("edge_types") or []):
            g["crosses_tenant"] = True
    out = [
        {
            "tenant": g["tenant"],
            "crosses_tenant": g["crosses_tenant"],
            "path_count": len(g["path_ids"]),
            "path_ids": sorted(g["path_ids"]),
        }
        for g in groups.values()
    ]
    return sorted(out, key=lambda g: (-g["path_count"], g["tenant"]))


# ---------------------------------------------------------------------------
# optional markdown rendering (not wired into engines/report.py or writers.py)
# ---------------------------------------------------------------------------
def render_risk_summary_markdown(summary: dict[str, Any]) -> str:
    totals = summary.get("totals") or {}
    lines = [
        "# AXguard risk aggregation (diagnostic)",
        "",
        "Rolls up attack-graph findings and paths — grouping is a lens, not a filter;",
        "every individual finding is still listed under `findings`.",
        "",
        f"- **Findings:** {totals.get('finding_count', 0)} · **Paths:** {totals.get('path_count', 0)} "
        f"· **Dead ends:** {totals.get('dead_end_count', 0)}",
        f"- **Credible (CONFIRMED/LIKELY):** {totals.get('credible_path_count', 0)} "
        f"· **Critical chains:** {totals.get('critical_chain_count', 0)}",
        f"- **Blocked:** {totals.get('blocked_path_count', 0)} "
        f"· **Predictive risks:** {totals.get('predictive_risk_count', 0)} "
        f"· **Choke points:** {totals.get('choke_point_count', 0)}",
        "",
        "## Root causes",
        "",
        "| Root cause | Findings | Paths |",
        "| --- | ---: | ---: |",
    ]
    for g in (summary.get("grouped") or {}).get("by_root_cause") or []:
        lines.append(f"| `{g['root_cause']}` | {g['finding_count']} | {len(g['path_ids'])} |")
    lines.append("")

    if summary.get("critical_chains"):
        lines.extend(["## Critical chains", ""])
        for c in summary["critical_chains"]:
            lines.append(f"- `{c['id']}` — {c['status']} (score {c['score']}) — {', '.join(c['reasons'])}")
        lines.append("")

    if summary.get("choke_points"):
        lines.extend(["## Choke points", "", "| Node | Type | Paths through it |", "| --- | --- | ---: |"])
        for c in summary["choke_points"]:
            lines.append(f"| `{c['label']}` | {c['type']} | {c['path_count']} |")
        lines.append("")

    if summary.get("predictive_risks"):
        lines.extend(["## Predictive risks (watch, don't ignore)", ""])
        for r in summary["predictive_risks"]:
            lines.append(f"- `{r['path_id']}` ({r['kind']}): {r['reason']}")
        lines.append("")

    return "\n".join(lines)
