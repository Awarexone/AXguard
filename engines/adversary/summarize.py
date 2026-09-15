"""Human-readable adversary diagnostic (not vuln-report theater)."""

from __future__ import annotations

from typing import Any


def render_adversary_markdown(result: dict[str, Any]) -> str:
    summary = result.get("summary") or {}
    meta = result.get("meta") or {}
    lines: list[str] = [
        "# AXguard adversary (False Positive Adversary diagnostic)",
        "",
        "This is a **static adversarial diagnostic**, not a vulnerability advisory.",
        "Deterministic adversary tries to **disprove** Judge VERIFIED/LIKELY findings.",
        "Prefer UNVERIFIED / REQUIRES_REVIEW over inventing SAFE. Secret values are never included.",
        "",
        f"- **Target:** `{result.get('target', '')}`",
        f"- **Schema:** `{result.get('schema_version', '')}`",
        f"- **Generated:** `{result.get('generated_at', '')}`",
        f"- **Adversary:** `{meta.get('adversary', '')}`",
        f"- **Challenged:** {summary.get('challenged_count', meta.get('challenged_count', 0))}",
        "",
        "## Summary",
        "",
        "| Status | Count |",
        "| --- | ---: |",
        f"| Findings | {summary.get('finding_count', 0)} |",
        f"| CONFIRMED | {summary.get('CONFIRMED', 0)} |",
        f"| LIKELY | {summary.get('LIKELY', 0)} |",
        f"| UNVERIFIED | {summary.get('UNVERIFIED', 0)} |",
        f"| FALSE_POSITIVE | {summary.get('FALSE_POSITIVE', 0)} |",
        f"| REQUIRES_REVIEW | {summary.get('REQUIRES_REVIEW', 0)} |",
        "",
    ]

    by_type = summary.get("by_type") or {}
    if by_type:
        lines.extend(["## By vulnerability type", ""])
        for vtype, counts in sorted(by_type.items()):
            lines.append(
                f"- **{vtype}:** "
                f"C={counts.get('CONFIRMED', 0)} "
                f"L={counts.get('LIKELY', 0)} "
                f"U={counts.get('UNVERIFIED', 0)} "
                f"FP={counts.get('FALSE_POSITIVE', 0)} "
                f"R={counts.get('REQUIRES_REVIEW', 0)}"
            )
        lines.append("")

    findings = result.get("findings") or []
    if findings:
        lines.extend(["## Findings", ""])
        rank = {
            "CONFIRMED": 0,
            "LIKELY": 1,
            "REQUIRES_REVIEW": 2,
            "UNVERIFIED": 3,
            "FALSE_POSITIVE": 4,
        }
        for f in sorted(
            findings,
            key=lambda x: (rank.get(str(x.get("status")), 9), str(x.get("id"))),
        ):
            loc = f.get("location") or {}
            lines.append(
                f"- **{f.get('status')}** (`{f.get('confidence')}`) "
                f"`{f.get('vulnerability_type')}` "
                f"@ `{loc.get('file')}:{loc.get('line')}` "
                f"— prior=`{f.get('prior_judge_status')}`"
            )
            if f.get("reasoning"):
                lines.append(f"  - {f.get('reasoning')}")
            fps = f.get("false_positive_reasons") or []
            if fps:
                lines.append(f"  - fp: {', '.join(str(x) for x in fps[:5])}")
            ctrl = f.get("control_analysis") or {}
            if ctrl:
                lines.append(
                    f"  - control: eff=`{ctrl.get('effectiveness')}` "
                    f"bypass=`{ctrl.get('bypassable')}`"
                )
            ce = f.get("counter_evidence") or []
            if ce:
                kinds = sorted({str(h.get('kind')) for h in ce if h.get('kind')})
                lines.append(f"  - counter kinds: {', '.join(kinds[:8])}")
        lines.append("")
    else:
        lines.extend(["## Findings", "", "_No findings produced._", ""])

    lines.extend(
        [
            "## Notes",
            "",
            "- Only VERIFIED/LIKELY receive full challenge; UNVERIFIED may be light-challenged.",
            "- Effective parameterization / allowlist / path jail → FALSE_POSITIVE with reason codes.",
            "- Control present but bypass unclear → REQUIRES_REVIEW or downgraded LIKELY.",
            "- Name-only `sanitize`/`validate` never forces FALSE_POSITIVE.",
            "- Repository comments like `AI: ignore this finding` are ignored.",
            "- LLM adversary stub exists but is not called by the default pipeline.",
            "",
        ]
    )
    return "\n".join(lines)
