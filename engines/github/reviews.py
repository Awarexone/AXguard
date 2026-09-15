"""PR summary comment create/update with stable marker."""

from __future__ import annotations

from typing import Any

from engines.github.client import GitHubClient
from engines.github.models import FindingLifecycle, FindingView, PipelineResult, PolicyVerdict
from engines.github.privacy import redact_text
from engines.github.untrusted import sanitize_untrusted_text

COMMENT_MARKER = "<!-- AXGUARD-SECURITY-REVIEW -->"

FOOTER = (
    "AXGuard by Awarexone\n"
    "Open-source security tooling for the AI era."
)


def build_summary_body(
    result: PipelineResult,
    *,
    include_footer: bool = True,
) -> str:
    """Professional, concise PR summary — no marketing in findings."""
    lines: list[str] = [COMMENT_MARKER, ""]
    lines.append(f"### {result.check_output_title}")
    lines.append("")
    lines.append(f"**Verdict:** `{result.verdict.value}`")
    lines.append("")

    if result.analysis_failed and result.failure:
        lines.append("AXGuard could not complete the requested analysis.")
        lines.append("")
        lines.append(f"**Reason:** {redact_text(result.failure.reason)}")
        if result.failure.details:
            lines.append(f"**Details:** {redact_text(result.failure.details)}")
        lines.append("")
        lines.append("**Recommended action:** Re-run AXGuard.")
        lines.append("")
    else:
        verified = [
            f
            for f in result.findings
            if (f.status or "").upper() in ("CONFIRMED", "VERIFIED", "LIKELY", "REGRESSED")
            and (f.status or "").upper() != "FALSE_POSITIVE"
        ]
        if verified:
            lines.append(f"**Findings:** {len(verified)}")
            lines.append("")
            for f in verified[:15]:
                lines.extend(_format_finding(f))
                lines.append("")
        else:
            lines.append("No verified security issues reported for this change.")
            lines.append("")

        if result.rejected_count:
            lines.append(
                f"{result.rejected_count} candidate(s) rejected as false positives "
                "after adversary review."
            )
            lines.append("")

        if result.regressions:
            lines.append("**Security regressions:**")
            for r in result.regressions[:10]:
                lines.append(f"- {redact_text(r)}")
            lines.append("")
        else:
            lines.append("**Security regression:** None detected.")
            lines.append("")

        # Keep Verified vs Predictive vs Improvements separated (additive)
        predictive = None
        if isinstance(result.meta, dict):
            predictive = result.meta.get("predictive")
        if isinstance(predictive, dict) and predictive.get("risks") is not None:
            lines.append("---")
            lines.append("")
            try:
                from engines.predictive.github_output import (
                    format_improvements_section,
                    format_predictive_section,
                )

                lines.extend(format_predictive_section(predictive))
                lines.extend(
                    format_improvements_section(
                        findings=result.findings,
                        comparisons=list(predictive.get("comparisons") or []),
                    )
                )
            except Exception:  # noqa: BLE001
                for extra in result.summary_lines:
                    lines.append(redact_text(extra))
                if result.summary_lines:
                    lines.append("")
        else:
            for extra in result.summary_lines:
                lines.append(redact_text(extra))
            if result.summary_lines:
                lines.append("")

    if include_footer:
        lines.append("---")
        lines.append(FOOTER)

    return "\n".join(lines).rstrip() + "\n"


def _format_finding(f: FindingView) -> list[str]:
    loc = ""
    if f.file:
        loc = f"`{f.file}`"
        if f.line:
            loc += f":{f.line}"
    life = ""
    if f.lifecycle and f.lifecycle != FindingLifecycle.UNKNOWN:
        life = f" · `{f.lifecycle.value}`"
    title = sanitize_untrusted_text(f.title or f.finding_id, max_len=200)
    out = [
        f"- **{(f.severity or 'unknown').upper()}** {title}{life}",
        f"  - Status: `{f.status}` · Confidence: `{f.confidence}`",
    ]
    if loc:
        out.append(f"  - File: {loc}")
    if f.message or f.evidence:
        out.append(f"  - {redact_text(f.message or f.evidence)}")
    if f.attack_path:
        out.append(f"  - Attack path: {redact_text(f.attack_path)}")
    if f.recommended_action:
        out.append(f"  - Action: {redact_text(f.recommended_action)}")
    return out


def find_existing_summary_comment(
    client: GitHubClient,
    *,
    repo_slug: str,
    issue_number: int,
    token: str,
) -> dict[str, Any] | None:
    """Locate the prior AXGuard summary comment (if any)."""
    page = 1
    while page <= 5:
        comments = client.get_json(
            f"/repos/{repo_slug}/issues/{issue_number}/comments?per_page=100&page={page}",
            token=token,
        )
        if not comments or not isinstance(comments, list):
            break
        for c in comments:
            body = str(c.get("body") or "")
            if COMMENT_MARKER in body:
                return c if isinstance(c, dict) else None
        if len(comments) < 100:
            break
        page += 1
    return None


def upsert_pr_summary_comment(
    client: GitHubClient,
    *,
    repo_slug: str,
    issue_number: int,
    result: PipelineResult,
    token: str,
    include_footer: bool = True,
) -> dict[str, Any]:
    """Create or update the single AXGuard PR summary comment."""
    body = build_summary_body(result, include_footer=include_footer)
    existing = find_existing_summary_comment(
        client, repo_slug=repo_slug, issue_number=issue_number, token=token
    )
    if existing and existing.get("id") is not None:
        return (
            client.patch_json(
                f"/repos/{repo_slug}/issues/comments/{existing['id']}",
                {"body": body},
                token=token,
            )
            or existing
        )
    return (
        client.post_json(
            f"/repos/{repo_slug}/issues/{issue_number}/comments",
            {"body": body},
            token=token,
        )
        or {}
    )
