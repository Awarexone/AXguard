"""GitHub Check Runs + annotations for AXGuard Security Review."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from engines.github.client import GitHubClient
from engines.github.models import FindingView, PipelineResult, PolicyVerdict
from engines.github.privacy import redact_text

CHECK_NAME = "AXGuard Security Review"

# GitHub check conclusions we emit
_CONCLUSION_MAP = {
    PolicyVerdict.PASS: "success",
    PolicyVerdict.PASS_WITH_NOTES: "neutral",
    PolicyVerdict.REVIEW_REQUIRED: "neutral",
    PolicyVerdict.FAIL: "failure",
}


@dataclass
class CheckRunResult:
    check_run_id: int | None
    name: str
    conclusion: str
    html_url: str = ""
    raw: dict[str, Any] = field(default_factory=dict)


def github_conclusion(verdict: PolicyVerdict, *, analysis_failed: bool = False) -> str:
    """Map AXGuard policy verdict → GitHub check conclusion.

    Analysis failures default to ``neutral`` (do not fail the PR). When the
    configured policy maps the failure to ``FAIL`` (``fail_on_analysis_error``),
    honor that verdict instead of forcing neutral.
    """
    if analysis_failed and verdict != PolicyVerdict.FAIL:
        return "neutral"
    return _CONCLUSION_MAP.get(verdict, "neutral")


def annotations_from_findings(
    findings: list[FindingView],
    *,
    max_annotations: int = 50,
) -> list[dict[str, Any]]:
    """Build Check Run annotations for verified / strong findings only."""
    out: list[dict[str, Any]] = []
    for f in findings:
        if not f.annotate:
            continue
        if not f.file:
            continue
        level = "warning"
        sev = (f.severity or "").lower()
        status = (f.status or "").upper()
        if status in ("CONFIRMED", "VERIFIED") and sev in ("critical", "high"):
            level = "failure"
        elif status in ("FALSE_POSITIVE",):
            continue
        msg = redact_text(
            f"{f.title}\n"
            f"Severity: {f.severity} · Status: {f.status} · Confidence: {f.confidence}\n"
            f"{f.message or f.evidence}\n"
            f"{('Action: ' + f.recommended_action) if f.recommended_action else ''}"
        ).strip()
        if len(msg) > 600:
            msg = msg[:597] + "..."
        ann: dict[str, Any] = {
            "path": f.file,
            "annotation_level": level,
            "title": redact_text(f.title)[:255],
            "message": msg or "AXGuard finding",
        }
        if f.line and int(f.line) > 0:
            ann["start_line"] = int(f.line)
            ann["end_line"] = int(f.line)
        out.append(ann)
        if len(out) >= max_annotations:
            break
    return out


def create_or_update_check_run(
    client: GitHubClient,
    *,
    repo_slug: str,
    head_sha: str,
    result: PipelineResult,
    token: str,
    name: str | None = None,
    check_run_id: int | None = None,
    max_annotations: int = 50,
) -> CheckRunResult:
    """Create or update the AXGuard check run for ``head_sha``."""
    check_name = name or result.check_output_title or CHECK_NAME
    conclusion = github_conclusion(
        result.verdict, analysis_failed=result.analysis_failed
    )
    annotations = annotations_from_findings(
        result.findings, max_annotations=max_annotations
    )
    output = {
        "title": redact_text(result.check_output_title or check_name)[:255],
        "summary": redact_text(result.check_output_summary or result.verdict.value)[:65535],
        "text": redact_text(result.check_output_text or "")[:65535],
        "annotations": annotations[:50],  # GitHub create limit per request
    }
    body: dict[str, Any] = {
        "name": check_name,
        "head_sha": head_sha,
        "status": "completed",
        "conclusion": conclusion,
        "output": output,
    }
    if check_run_id:
        data = client.patch_json(
            f"/repos/{repo_slug}/check-runs/{check_run_id}",
            body,
            token=token,
        )
    else:
        data = client.post_json(
            f"/repos/{repo_slug}/check-runs",
            body,
            token=token,
        )
    data = data if isinstance(data, dict) else {}
    return CheckRunResult(
        check_run_id=int(data["id"]) if data.get("id") is not None else check_run_id,
        name=check_name,
        conclusion=conclusion,
        html_url=str(data.get("html_url") or ""),
        raw=data,
    )


def start_in_progress_check(
    client: GitHubClient,
    *,
    repo_slug: str,
    head_sha: str,
    token: str,
    name: str = CHECK_NAME,
) -> CheckRunResult:
    """Optional: mark check as queued/in_progress before analysis."""
    data = client.post_json(
        f"/repos/{repo_slug}/check-runs",
        {
            "name": name,
            "head_sha": head_sha,
            "status": "in_progress",
            "output": {
                "title": name,
                "summary": "AXGuard analysis in progress…",
            },
        },
        token=token,
    )
    data = data if isinstance(data, dict) else {}
    return CheckRunResult(
        check_run_id=int(data["id"]) if data.get("id") is not None else None,
        name=name,
        conclusion="",
        html_url=str(data.get("html_url") or ""),
        raw=data,
    )
