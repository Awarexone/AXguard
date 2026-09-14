"""Human-readable verification diagnostic (not vuln-report theater)."""

from __future__ import annotations

from typing import Any


def render_verification_markdown(result: dict[str, Any]) -> str:
    summary = result.get("summary") or {}
    meta = result.get("meta") or {}
    lines: list[str] = [
        "# AXguard verification (Hunter → Judge diagnostic)",
        "",
        "This is a **static verification diagnostic**, not a vulnerability advisory.",
        "Deterministic Judge only. Prefer UNVERIFIED over inventing VERIFIED.",
        "Secret values are never included.",
        "",
        f"- **Target:** `{result.get('target', '')}`",
        f"- **Schema:** `{result.get('schema_version', '')}`",
        f"- **Generated:** `{result.get('generated_at', '')}`",
        f"- **Judge:** `{meta.get('judge', '')}`",
        f"- **Hunters:** {', '.join(f'`{h}`' for h in (meta.get('hunters') or [])) or '_none_'}",
        "",
        "## Summary",
        "",
        "| Status | Count |",
        "| --- | ---: |",
        f"| Candidates | {summary.get('candidate_count', 0)} |",
        f"| VERIFIED | {summary.get('VERIFIED', 0)} |",
        f"| LIKELY | {summary.get('LIKELY', 0)} |",
        f"| UNVERIFIED | {summary.get('UNVERIFIED', 0)} |",
        f"| FALSE_POSITIVE | {summary.get('FALSE_POSITIVE', 0)} |",
        "",
    ]

    by_type = summary.get("by_type") or {}
    if by_type:
        lines.extend(["## By vulnerability type", ""])
        for vtype, counts in sorted(by_type.items()):
            lines.append(
                f"- **{vtype}:** "
                f"V={counts.get('VERIFIED', 0)} "
                f"L={counts.get('LIKELY', 0)} "
                f"U={counts.get('UNVERIFIED', 0)} "
                f"FP={counts.get('FALSE_POSITIVE', 0)}"
            )
        lines.append("")

    judgments = result.get("judgments") or []
    candidates_by_id = {
        c.get("id"): c for c in (result.get("candidates") or []) if c.get("id")
    }

    if judgments:
        lines.extend(["## Judgments", ""])
        # Sort: VERIFIED, LIKELY, UNVERIFIED, FALSE_POSITIVE
        rank = {"VERIFIED": 0, "LIKELY": 1, "UNVERIFIED": 2, "FALSE_POSITIVE": 3}
        for j in sorted(
            judgments, key=lambda x: (rank.get(str(x.get("status")), 9), str(x.get("candidate_id")))
        ):
            cid = j.get("candidate_id")
            cand = candidates_by_id.get(cid) or {}
            loc = cand.get("location") or {}
            lines.append(
                f"- **{j.get('status')}** (`{j.get('confidence')}`) "
                f"`{j.get('vulnerability_type')}` "
                f"@ `{loc.get('file')}:{loc.get('line')}` "
                f"— next=`{j.get('recommended_next_step')}`"
            )
            if j.get("reasoning"):
                lines.append(f"  - {j.get('reasoning')}")
            missing = j.get("missing_evidence") or []
            if missing:
                lines.append(f"  - missing: {', '.join(str(m) for m in missing[:4])}")
            fps = j.get("false_positive_reasons") or []
            if fps:
                lines.append(f"  - fp: {', '.join(str(f) for f in fps[:3])}")
        lines.append("")
    else:
        lines.extend(["## Judgments", "", "_No candidates produced._", ""])

    # Sample candidates without dumping secrets
    candidates = result.get("candidates") or []
    if candidates:
        lines.extend(["## Candidates (sample)", ""])
        for c in candidates[:30]:
            loc = c.get("location") or {}
            df = c.get("data_flow") or {}
            taint = df.get("taint_state") or "—"
            lines.append(
                f"- `{c.get('id')}` **{c.get('vulnerability_type')}** "
                f"conf=`{c.get('confidence')}` taint=`{taint}` "
                f"@ `{loc.get('file')}:{loc.get('line')}`"
            )
        lines.append("")

    lines.extend(
        [
            "## Notes",
            "",
            "- Hunters always emit `status=candidate`; Judge assigns VERIFIED/LIKELY/UNVERIFIED/FALSE_POSITIVE.",
            "- Pattern-only sinks without a Phase 2 taint path stay UNVERIFIED.",
            "- Parameterization / allowlist / SANITIZED paths are FALSE_POSITIVE or UNVERIFIED — not VERIFIED.",
            "- LLM Judge stub exists but is not called by the default pipeline.",
            "",
        ]
    )
    return "\n".join(lines)
