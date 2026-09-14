"""False Positive Adversary pipeline."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from engines.adversary.adversary import (
    FalsePositiveAdversary,
    default_adversary,
    should_challenge,
)
from engines.adversary.refine import attach_root_cause, finding_id, map_judge_status
from engines.adversary.schema import (
    ADVERSARY_STATUSES,
    ADVERSARY_VERSION,
    empty_adversary,
)
from engines.dataflow.schema import ensure_no_secret_values


def run_adversary(
    target: Path,
    verification: dict[str, Any] | None = None,
    *,
    adversary: FalsePositiveAdversary | None = None,
    include_unverified: bool = True,
    include_false_positives: bool = True,
) -> dict[str, Any]:
    """
    Challenge Phase 3 judgments and emit refined final findings.

    If ``verification`` is None, calls ``run_verification(target)`` first.
    Reuses embedded ``_application_model`` / ``_dataflow`` when present —
    does not rebuild call/dataflow graphs.
    """
    root = Path(target).resolve()
    if verification is None:
        from engines.verify import run_verification

        verification = run_verification(root)

    model = verification.get("_application_model")
    flow = verification.get("_dataflow")

    result = empty_adversary(root)
    result["schema_version"] = ADVERSARY_VERSION
    result["generated_at"] = datetime.now(timezone.utc).isoformat()

    candidates_by_id = {
        c.get("id"): c for c in (verification.get("candidates") or []) if c.get("id")
    }
    judgments = list(verification.get("judgments") or [])

    active = adversary if adversary is not None else default_adversary()
    findings: list[dict[str, Any]] = []
    challenged = 0

    # First pass without sibling linking
    pending: list[tuple[dict[str, Any], dict[str, Any] | None, bool]] = []

    for judgment in judgments:
        status = str(judgment.get("status") or "")
        cand = candidates_by_id.get(judgment.get("candidate_id"))

        do_challenge, light = should_challenge(
            status, include_unverified=include_unverified
        )

        if status == "FALSE_POSITIVE" and include_false_positives and not do_challenge:
            findings.append(_passthrough_fp(judgment, cand))
            continue

        if not do_challenge:
            # Carry through other statuses without adversarial rewrite
            findings.append(_passthrough(judgment, cand))
            continue

        challenged += 1
        pending.append((judgment, cand, light))

    for judgment, cand, light in pending:
        ctx = {
            "target": root,
            "candidate": cand,
            "application_model": model,
            "dataflow": flow,
            "light": light,
            "sibling_findings": findings,
        }
        finding = active.challenge(judgment, ctx)
        findings.append(finding)

    # Second pass: root-cause linking among confirmed/likely siblings
    for finding in findings:
        cid = finding.get("from_judgment_id")
        cand = candidates_by_id.get(cid)
        attach_root_cause(finding, cand, siblings=findings)

    result["findings"] = findings
    result["summary"] = _build_summary(findings, challenged_count=challenged)
    result["meta"] = {
        "adversary": getattr(active, "name", type(active).__name__),
        "verification_target": verification.get("target"),
        "judgment_count": len(judgments),
        "challenged_count": challenged,
        "application_model_present": model is not None,
        "dataflow_present": flow is not None,
        "include_unverified": include_unverified,
    }
    result["_verification"] = verification

    ensure_no_secret_values(result)
    return result


def challenge_findings(
    target: Path,
    judgments: list[dict[str, Any]],
    *,
    candidates: list[dict[str, Any]] | None = None,
    application_model: dict[str, Any] | None = None,
    dataflow: dict[str, Any] | None = None,
    adversary: FalsePositiveAdversary | None = None,
    include_unverified: bool = True,
) -> list[dict[str, Any]]:
    """Challenge a list of judgments; convenience wrapper around the adversary."""
    root = Path(target).resolve()
    active = adversary if adversary is not None else default_adversary()
    by_id = {c.get("id"): c for c in (candidates or []) if c.get("id")}
    out: list[dict[str, Any]] = []
    for judgment in judgments:
        status = str(judgment.get("status") or "")
        do_challenge, light = should_challenge(
            status, include_unverified=include_unverified
        )
        cand = by_id.get(judgment.get("candidate_id"))
        if not do_challenge:
            out.append(_passthrough(judgment, cand))
            continue
        out.append(
            active.challenge(
                judgment,
                {
                    "target": root,
                    "candidate": cand,
                    "application_model": application_model,
                    "dataflow": dataflow,
                    "light": light,
                    "sibling_findings": out,
                },
            )
        )
    return out


def write_adversary_report(result: dict[str, Any], out_dir: Path) -> dict[str, Any]:
    """Write ``adversary.json`` + ``adversary.md`` (and ``final-findings.json``)."""
    from engines.adversary.writers import write_adversary_artifacts

    return write_adversary_artifacts(result, out_dir)


def _passthrough(
    judgment: dict[str, Any], candidate: dict[str, Any] | None
) -> dict[str, Any]:
    status = map_judge_status(str(judgment.get("status") or "UNVERIFIED"))
    return {
        "id": finding_id(judgment, candidate),
        "from_judgment_id": judgment.get("candidate_id") or judgment.get("id"),
        "vulnerability_type": judgment.get("vulnerability_type")
        or (candidate or {}).get("vulnerability_type"),
        "status": status,
        "severity": judgment.get("severity") or (candidate or {}).get("severity"),
        "confidence": judgment.get("confidence") or "unknown",
        "false_positive_reasons": list(judgment.get("false_positive_reasons") or []),
        "counter_evidence": [],
        "surviving_evidence": list(judgment.get("evidence") or []),
        "root_cause": None,
        "affected_paths": [],
        "reasoning": judgment.get("reasoning")
        or "Passthrough — not selected for adversarial challenge.",
        "challenges": {},
        "adversary": "passthrough",
        "prior_judge_status": judgment.get("status"),
        "location": dict((candidate or {}).get("location") or {}),
    }


def _passthrough_fp(
    judgment: dict[str, Any], candidate: dict[str, Any] | None
) -> dict[str, Any]:
    finding = _passthrough(judgment, candidate)
    finding["status"] = "FALSE_POSITIVE"
    finding["reasoning"] = (
        judgment.get("reasoning")
        or "Judge already marked FALSE_POSITIVE — carried through."
    )
    return finding


def _build_summary(
    findings: list[dict[str, Any]], *, challenged_count: int
) -> dict[str, Any]:
    counts = {s: 0 for s in sorted(ADVERSARY_STATUSES)}
    by_type: dict[str, dict[str, int]] = {}
    for f in findings:
        status = str(f.get("status") or "")
        if status in counts:
            counts[status] += 1
        vtype = str(f.get("vulnerability_type") or "unknown")
        bucket = by_type.setdefault(
            vtype, {s: 0 for s in sorted(ADVERSARY_STATUSES)}
        )
        if status in bucket:
            bucket[status] += 1
    return {
        "finding_count": len(findings),
        "challenged_count": challenged_count,
        **counts,
        "by_type": by_type,
    }
