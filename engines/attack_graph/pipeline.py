"""Attack Graph pipeline (Phase 6).

``run_attack_graph(target, evidence=None)`` composes existing Phase 1-5 output
into multi-hop attack paths. It never rebuilds graphs that already exist:

1. If ``evidence`` is ``None`` → run the Phase 5 evidence engine (which itself
   runs the adversary / verification / app_model / dataflow as needed).
2. Reuse the ``_adversary`` / ``_verification`` / ``_application_model`` /
   ``_dataflow`` private refs embedded by the earlier phases.
3. Build nodes + evidence-backed edges (``chaining``).
4. Enumerate bounded paths, dedupe equivalent finding-id sequences (``paths``).
5. Apply barriers → BLOCKED; INVALID for false chains; UNVERIFIED for unknown
   reachability (handled in ``confidence`` / ``barriers``).
6. Score + select shortest-credible and highest-impact per (entry, target).
7. Link root causes across paths sharing the same adversary ``root_cause``.
8. Emit the schema-1.0.0 artifact with a private ``_evidence`` ref.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from engines.dataflow.schema import ensure_no_secret_values
from engines.attack_graph.chaining import ChainingContext, build_chains
from engines.attack_graph.paths import assemble
from engines.attack_graph.schema import (
    ATTACK_GRAPH_VERSION,
    DEFAULT_SEARCH_MODE,
    empty_attack_graph,
)
from engines.attack_graph.summarize import build_summary
from engines.attack_graph import (
    blast as blast_mod,
    choke as choke_mod,
    explain as explain_mod,
    identity as identity_mod,
    modes as modes_mod,
    privilege as privilege_mod,
    sensitivity_data,
    state_model,
)


def run_attack_graph(
    target: Path,
    evidence: dict[str, Any] | None = None,
    *,
    search_mode: str = DEFAULT_SEARCH_MODE,
) -> dict[str, Any]:
    root = Path(target).resolve()

    if evidence is None:
        from engines.evidence import run_evidence

        evidence = run_evidence(root)

    adversary = evidence.get("_adversary") or {}
    verification = adversary.get("_verification") or {}
    application_model = verification.get("_application_model")
    dataflow = verification.get("_dataflow")

    result = empty_attack_graph(root)
    result["schema_version"] = ATTACK_GRAPH_VERSION
    result["generated_at"] = datetime.now(timezone.utc).isoformat()

    ctx = ChainingContext(root, application_model, adversary)
    chains, dead_ends = build_chains(ctx)
    assembled = assemble(chains)

    _link_root_causes(assembled.get("paths") or [], adversary)

    graph = {"nodes": assembled["nodes"], "edges": assembled["edges"]}
    paths = assembled["paths"]
    result["graph"] = graph
    result["paths"] = paths
    result["alternate_paths"] = assembled["alternate_paths"]
    result["dead_ends"] = dead_ends
    result["summary"] = build_summary(assembled, dead_ends)

    # -- Phase 6 Part 2 intelligence layers (additive; never mutate paths[]) --
    result["search_mode"] = modes_mod.normalize_mode(search_mode)
    result["identity_transitions"] = identity_mod.derive_identity_transitions(graph, paths)
    result["privilege_transitions"] = privilege_mod.derive_privilege_transitions(graph, paths)
    result["state_transitions"] = state_model.derive_state_transitions(graph, paths)
    result["rejected_paths"] = explain_mod.rejected_paths(paths)
    result["posture"] = _build_posture(graph, paths, result["search_mode"])

    # Soft Part 2 advanced layers — never fail the core attack-graph run.
    try:
        from engines.attack_graph import sbom as sbom_mod

        result["sbom"] = sbom_mod.build_sbom(root)
    except Exception as exc:  # noqa: BLE001
        result["sbom_status"] = "error"
        result["sbom_error"] = str(exc)
    try:
        from engines.attack_graph import temporal as temporal_mod

        result["temporal_chains"] = temporal_mod.analyze_temporal(root)
    except Exception as exc:  # noqa: BLE001
        result["temporal_status"] = "error"
        result["temporal_error"] = str(exc)
    try:
        from engines.attack_graph import cross_service as cross_mod

        result["cross_service"] = cross_mod.build_cross_service_graph(application_model)
    except Exception as exc:  # noqa: BLE001
        result["cross_service_status"] = "error"
        result["cross_service_error"] = str(exc)
    try:
        from engines.attack_graph import aggregate as aggregate_mod

        result["risk_summary"] = aggregate_mod.build_risk_summary(result)
    except Exception as exc:  # noqa: BLE001
        result["risk_summary_status"] = "error"
        result["risk_summary_error"] = str(exc)

    result["meta"] = {
        "adversary": (adversary.get("meta") or {}).get("adversary", "deterministic"),
        "adversary_finding_count": len(adversary.get("findings") or []),
        "application_model_present": application_model is not None,
        "dataflow_present": dataflow is not None,
        "evidence_present": bool(evidence),
        "seed_note": (
            "Where upstream hunters miss/drop a pattern, attack_graph emits "
            "deterministic, evidence-gated candidate_seed nodes (LIKELY at best)."
        ),
    }
    result["_evidence"] = evidence

    ensure_no_secret_values(result)
    return result


def _build_posture(
    graph: dict[str, Any],
    paths: list[dict[str, Any]],
    search_mode: str,
) -> dict[str, Any]:
    """A compact security-posture rollup for the whole target (Part 2).

    Summarises which identities/states an attacker can reach, the most
    sensitive data exposed by any live path, high-leverage choke points, and
    the live-vs-rejected split under the active search mode. Pure summary — it
    reads only what the analysis modules derived from evidence-backed nodes.
    """
    live, filtered = modes_mod.partition_paths(paths, search_mode)

    reachable_identities: set[str] = set()
    reachable_states: set[str] = set()
    for p in live:
        reachable_identities.update(identity_mod.get_path_identities(p, graph))
        reachable_states.add(state_model.get_path_state(p, graph))

    max_cat = "UNKNOWN"
    max_weight = 0.0
    for p in live:
        s = sensitivity_data.analyze_path_sensitivity(p, graph)
        if s["max_impact_weight"] > max_weight:
            max_weight = s["max_impact_weight"]
            max_cat = s["max_category"]

    priv = privilege_mod.derive_privilege_transitions(graph, paths)
    pattern_counts: dict[str, int] = {}
    for t in priv:
        pattern_counts[t["pattern"]] = pattern_counts.get(t["pattern"], 0) + 1

    return {
        "search_mode": search_mode,
        "live_path_count": len(live),
        "filtered_out_count": len(filtered),
        "rejected_path_count": sum(
            1 for p in paths if str(p.get("status")) in {"BLOCKED", "INVALID"}
        ),
        "reachable_identities": sorted(reachable_identities),
        "reachable_states": sorted(reachable_states),
        "max_sensitivity_reachable": max_cat,
        "max_impact_weight": max_weight,
        "privilege_pattern_counts": {k: pattern_counts[k] for k in sorted(pattern_counts)},
        "confused_deputy_paths": privilege_mod.get_confused_deputy_paths(graph, paths),
        "top_choke_points": choke_mod.get_choke_points(graph, paths, limit=5),
        "top_blast_origins": blast_mod.rank_blast_origins(graph, limit=5),
    }


def write_attack_graph_report(result: dict[str, Any], out_dir: Path) -> dict[str, Any]:
    """Write ``attack-paths.json`` + ``attack-paths.md`` under ``out_dir``."""
    from engines.attack_graph.writers import write_attack_graph_artifacts

    return write_attack_graph_artifacts(result, out_dir)


def _link_root_causes(paths: list[dict[str, Any]], adversary: dict[str, Any]) -> None:
    """Group paths whose finding hops share an adversary ``root_cause``."""
    rc_by_finding: dict[str, str] = {}
    for f in adversary.get("findings") or []:
        rc = f.get("root_cause") or {}
        key = None
        if isinstance(rc, dict):
            key = rc.get("symbol") or f"{rc.get('file')}:{rc.get('line')}"
        if key:
            from engines.attack_graph.nodes import finding_id

            rc_by_finding[finding_id(f.get("id") or "")] = str(key)

    clusters: dict[str, list[str]] = {}
    for p in paths:
        for h in p.get("hops") or []:
            if h in rc_by_finding:
                clusters.setdefault(rc_by_finding[h], []).append(p["id"])
    shared = {k: sorted(set(v)) for k, v in clusters.items() if len(set(v)) > 1}
    for p in paths:
        related: list[str] = []
        for rc, ids in shared.items():
            if p["id"] in ids:
                related.extend([i for i in ids if i != p["id"]])
        if related:
            p["shares_root_cause_with"] = sorted(set(related))
