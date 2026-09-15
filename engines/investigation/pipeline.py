"""Investigation pipeline — orchestrate candidates from target or payloads."""

from __future__ import annotations

import json
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any

from engines.dataflow.schema import ensure_no_secret_values
from engines.investigation.loop import investigate_candidate
from engines.investigation.memory_bridge import lookup_memory_for_candidate
from engines.investigation.report import write_investigation_report
from engines.investigation.schema import BUDGET_BALANCED, UNKNOWN, utc_now
from engines.investigation.twin_bridge import load_or_build_twin

SEVERITY_SCORE = {
    "critical": 100,
    "high": 80,
    "medium": 50,
    "low": 20,
    "info": 5,
}
CONFIDENCE_SCORE = {
    "confirmed": 30,
    "high": 25,
    "likely": 15,
    "medium": 10,
    "low": 5,
    "unknown": 0,
}


def prioritize_candidates(candidates: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Priority: severity, confidence, exploitability signals, evidence gaps."""

    def score(c: dict[str, Any]) -> int:
        sev = SEVERITY_SCORE.get(str(c.get("severity") or "info").lower(), 5)
        conf = CONFIDENCE_SCORE.get(str(c.get("confidence") or "unknown").lower(), 0)
        kind = str(c.get("vulnerability_type") or c.get("type") or "").lower()
        bonus = 0
        if any(k in kind for k in ("sql", "ssrf", "idor", "rce", "agent", "mcp")):
            bonus += 10
        if c.get("status") in {"CONFIRMED", "LIKELY", "UNVERIFIED", "REQUIRES_REVIEW"}:
            bonus += 5
        if c.get("status") == "FALSE_POSITIVE":
            bonus -= 20  # still investigate lightly for validation
        # Evidence gaps encourage investigation
        if not (c.get("surviving_evidence") or c.get("counter_evidence")):
            bonus += 8
        return sev + conf + bonus

    return sorted(candidates, key=score, reverse=True)


def extract_candidates(
    *,
    adversary: dict[str, Any] | None = None,
    audit: dict[str, Any] | None = None,
    findings: list[dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    if findings:
        return list(findings)
    if adversary and isinstance(adversary.get("findings"), list):
        return list(adversary["findings"])
    if audit:
        if isinstance(audit.get("adversary"), dict) and audit["adversary"].get("findings"):
            return list(audit["adversary"]["findings"])
        if isinstance(audit.get("findings"), list):
            return list(audit["findings"])
    return []


def build_context(
    target: Path | None,
    *,
    adversary: dict[str, Any] | None = None,
    attack_graph: dict[str, Any] | None = None,
    dataflow: dict[str, Any] | None = None,
    twin: dict[str, Any] | None = None,
    memory_dir: Path | str | None = None,
    with_twin: bool = True,
) -> dict[str, Any]:
    ctx: dict[str, Any] = {
        "adversary": adversary or {},
        "attack_graph": attack_graph or {},
        "dataflow": dataflow or {},
        "memory_dir": str(memory_dir) if memory_dir else None,
    }
    if with_twin:
        twin_pack = load_or_build_twin(
            target,
            attack_graph=attack_graph,
            twin=twin,
            simulate=True,
        )
        if twin_pack.get("twin"):
            ctx["twin"] = twin_pack["twin"]
            ctx["twin_summary"] = (twin_pack["twin"] or {}).get("summary")
        if twin_pack.get("simulation"):
            ctx["twin_simulation"] = twin_pack["simulation"]
    return ctx


def run_investigation(
    target: Path | str | dict[str, Any] | None = None,
    *,
    finding_id: str | None = None,
    budget: str = BUDGET_BALANCED,
    adversary: dict[str, Any] | None = None,
    attack_graph: dict[str, Any] | None = None,
    dataflow: dict[str, Any] | None = None,
    twin: dict[str, Any] | None = None,
    memory_dir: Path | str | None = None,
    out_dir: Path | str | None = None,
    write_report: bool = True,
    parallel: bool = True,
    max_candidates: int | None = None,
    with_twin: bool = True,
) -> dict[str, Any]:
    """Investigate suspicious candidates from a target path or structured payload.

    Soft-orchestrates existing engines. Never exploits or contacts the network.
    """
    path: Path | None = None
    audit_payload: dict[str, Any] | None = None

    if isinstance(target, dict):
        audit_payload = target
    elif target is not None:
        path = Path(target)
        if path.is_file() and path.suffix.lower() == ".json":
            audit_payload = json.loads(path.read_text(encoding="utf-8"))
            path = None
        else:
            path = path.resolve()

    # Gather upstream artifacts when we have a directory target
    if path is not None and path.exists() and path.is_dir():
        if adversary is None:
            try:
                from engines.adversary import run_adversary

                adversary = run_adversary(path)
            except Exception:  # noqa: BLE001
                adversary = None
        if attack_graph is None:
            try:
                from engines.attack_graph import run_attack_graph

                attack_graph = run_attack_graph(path, evidence=None)
            except Exception:  # noqa: BLE001
                attack_graph = None
        if dataflow is None:
            try:
                from engines.app_model import build_application_model
                from engines.dataflow import analyze_dataflow

                model = build_application_model(path)
                dataflow = analyze_dataflow(path, application_model=model)
            except Exception:  # noqa: BLE001
                dataflow = None

    if audit_payload and adversary is None:
        adversary = audit_payload.get("adversary") if isinstance(
            audit_payload.get("adversary"), dict
        ) else audit_payload
    if audit_payload and attack_graph is None:
        attack_graph = audit_payload.get("attack_graph")

    candidates = extract_candidates(adversary=adversary, audit=audit_payload)
    if finding_id:
        candidates = [
            c
            for c in candidates
            if finding_id in str(c.get("id") or "")
            or finding_id == str(c.get("from_judgment_id") or "")
            or finding_id in str(c.get("vulnerability_type") or "")
        ]

    candidates = prioritize_candidates(candidates)
    if max_candidates is not None:
        candidates = candidates[: max(0, int(max_candidates))]

    # Budget-based candidate cap
    if budget.upper() == "FAST":
        candidates = candidates[:5]
    elif budget.upper() == "BALANCED":
        candidates = candidates[:12]
    else:
        candidates = candidates[:25]

    base_ctx = build_context(
        path,
        adversary=adversary,
        attack_graph=attack_graph,
        dataflow=dataflow,
        twin=twin,
        memory_dir=memory_dir,
        with_twin=with_twin and budget.upper() != "FAST",
    )

    investigations: list[dict[str, Any]] = []

    def _one(cand: dict[str, Any]) -> dict[str, Any]:
        ctx = dict(base_ctx)
        ctx["memory_hit"] = lookup_memory_for_candidate(cand, memory_dir=memory_dir)
        return investigate_candidate(cand, context=ctx, budget=budget)

    # Parallelize independent candidates (no shared memory writes here)
    if parallel and len(candidates) > 1:
        with ThreadPoolExecutor(max_workers=min(4, len(candidates))) as pool:
            futures = {pool.submit(_one, c): c for c in candidates}
            for fut in as_completed(futures):
                try:
                    investigations.append(fut.result())
                except Exception as exc:  # noqa: BLE001
                    investigations.append(
                        {
                            "kind": "security_investigation",
                            "status": "FAILED",
                            "decision": "UNVERIFIED",
                            "candidate_id": str((futures[fut] or {}).get("id")),
                            "reasoning_summary": str(exc),
                            "unknowns": [{"topic": "parallel_error", "detail": str(exc)}],
                        }
                    )
    else:
        for c in candidates:
            investigations.append(_one(c))

    # Stable order by candidate_id for determinism in reports
    investigations.sort(key=lambda i: str(i.get("candidate_id") or ""))

    summary = _summarize(investigations)
    result: dict[str, Any] = {
        "kind": "security_investigation_run",
        "schema_version": "1.0.0",
        "tool": "axguard",
        "target": str(path) if path else (audit_payload or {}).get("target") or UNKNOWN,
        "budget": budget,
        "generated_at": utc_now(),
        "summary": summary,
        "investigations": investigations,
        "disclaimer": (
            "Symbolic investigation only — orchestration over existing AXGuard "
            "engines; no exploitation or network."
        ),
    }
    ensure_no_secret_values(result)

    if write_report and out_dir is not None:
        result["report"] = write_investigation_report(result, Path(out_dir))
    elif write_report and path is not None:
        default_out = Path(".findings/axguard/investigation")
        result["report"] = write_investigation_report(result, default_out)

    return result


def investigate_finding(
    finding_id: str,
    target: Path | str | dict[str, Any],
    *,
    budget: str = BUDGET_BALANCED,
    out_dir: Path | str | None = None,
) -> dict[str, Any]:
    return run_investigation(
        target,
        finding_id=finding_id,
        budget=budget,
        out_dir=out_dir,
        write_report=out_dir is not None,
        parallel=False,
        max_candidates=1,
    )


def _summarize(investigations: list[dict[str, Any]]) -> dict[str, Any]:
    by_decision: dict[str, int] = {}
    by_status: dict[str, int] = {}
    for inv in investigations:
        d = str(inv.get("decision") or UNKNOWN)
        s = str(inv.get("status") or UNKNOWN)
        by_decision[d] = by_decision.get(d, 0) + 1
        by_status[s] = by_status.get(s, 0) + 1
    return {
        "investigation_count": len(investigations),
        "by_decision": by_decision,
        "by_status": by_status,
        "verified": by_decision.get("VERIFIED", 0),
        "likely": by_decision.get("LIKELY", 0),
        "false_positive": by_decision.get("FALSE_POSITIVE", 0),
        "unverified": by_decision.get("UNVERIFIED", 0),
        "requires_review": by_decision.get("REQUIRES_REVIEW", 0),
    }
