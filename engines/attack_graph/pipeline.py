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
    empty_attack_graph,
)
from engines.attack_graph.summarize import build_summary


def run_attack_graph(
    target: Path,
    evidence: dict[str, Any] | None = None,
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

    result["graph"] = {"nodes": assembled["nodes"], "edges": assembled["edges"]}
    result["paths"] = assembled["paths"]
    result["alternate_paths"] = assembled["alternate_paths"]
    result["dead_ends"] = dead_ends
    result["summary"] = build_summary(assembled, dead_ends)
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
