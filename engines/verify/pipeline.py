"""Hunter → Judge verification pipeline."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from engines.app_model import build_application_model
from engines.dataflow import analyze_dataflow
from engines.dataflow.schema import ensure_no_secret_values
from engines.verify.hunters import default_hunters
from engines.verify.judge import SecurityJudge, default_judge
from engines.verify.merge import merge_candidates
from engines.verify.schema import (
    JUDGMENT_STATUSES,
    VERIFICATION_VERSION,
    empty_verification,
)


def run_verification(
    target: Path,
    application_model: dict[str, Any] | None = None,
    dataflow: dict[str, Any] | None = None,
    *,
    judge: SecurityJudge | None = None,
    hunters: list[Any] | None = None,
) -> dict[str, Any]:
    """
    Build / reuse Phase 1–2 models, run hunters, merge, and deterministic Judge.

    Prefer UNVERIFIED over inventing VERIFIED. Never emits secret values.
    LLM Judge is not invoked (DeterministicJudge by default).
    """
    root = Path(target).resolve()
    model = (
        application_model
        if application_model is not None
        else build_application_model(root)
    )
    flow = (
        dataflow
        if dataflow is not None
        else analyze_dataflow(root, application_model=model)
    )

    result = empty_verification(root)
    result["schema_version"] = VERIFICATION_VERSION
    result["generated_at"] = datetime.now(timezone.utc).isoformat()

    hunter_list = hunters if hunters is not None else default_hunters()
    raw_candidates: list[dict[str, Any]] = []
    for hunter in hunter_list:
        found = hunter.hunt(
            root,
            application_model=model,
            dataflow=flow,
        )
        for cand in found:
            # Enforce candidate status — never auto-VERIFIED
            cand["status"] = "candidate"
            raw_candidates.append(cand)

    candidates = merge_candidates(raw_candidates)

    active_judge: SecurityJudge = judge if judge is not None else default_judge()
    judgments: list[dict[str, Any]] = []
    for cand in candidates:
        judgment = active_judge.judge(
            cand,
            application_model=model,
            dataflow=flow,
        )
        judgments.append(judgment)

    result["candidates"] = candidates
    result["judgments"] = judgments
    result["summary"] = _build_summary(candidates, judgments)
    result["meta"] = {
        "hunter_count": len(hunter_list),
        "hunters": [getattr(h, "name", type(h).__name__) for h in hunter_list],
        "judge": getattr(active_judge, "name", type(active_judge).__name__),
        "application_model_present": True,
        "dataflow_present": True,
        "taint_path_count": len(flow.get("taint_paths") or []),
    }

    # Soft references for callers that already hold models (not written to disk by default)
    result["_application_model"] = model
    result["_dataflow"] = flow

    ensure_no_secret_values(result)
    return result


def write_verification_report(result: dict[str, Any], out_dir: Path) -> dict[str, Any]:
    """Write ``verification.json`` + ``verification.md`` under ``out_dir``."""
    from engines.verify.writers import write_verification_artifacts

    return write_verification_artifacts(result, out_dir)


def _build_summary(
    candidates: list[dict[str, Any]], judgments: list[dict[str, Any]]
) -> dict[str, Any]:
    counts = {s: 0 for s in sorted(JUDGMENT_STATUSES)}
    by_type: dict[str, dict[str, int]] = {}

    for j in judgments:
        status = str(j.get("status") or "")
        if status in counts:
            counts[status] += 1
        vtype = str(j.get("vulnerability_type") or "unknown")
        bucket = by_type.setdefault(
            vtype, {s: 0 for s in sorted(JUDGMENT_STATUSES)}
        )
        if status in bucket:
            bucket[status] += 1

    return {
        "candidate_count": len(candidates),
        "judgment_count": len(judgments),
        **counts,
        "by_type": by_type,
    }
