"""Human-readable evidence & confidence summaries."""

from __future__ import annotations

from typing import Any

from engines.evidence.conflicts import RESOLUTION_REVIEW


def summarize_entry(entry: dict[str, Any]) -> str:
    """One compact human sentence describing a finding's evidence + confidence."""
    conf = entry.get("evidence_confidence") or {}
    level = entry.get("confidence_level") or conf.get("level") or "UNKNOWN"
    vtype = entry.get("vulnerability_type") or "finding"
    status = entry.get("status") or "?"
    n_support = len(entry.get("supporting_evidence_ids") or [])
    n_counter = len(entry.get("counter_evidence_ids") or [])
    unknowns = conf.get("unknowns") or []
    conflicts = entry.get("conflicts") or []
    parts = [
        f"{vtype} [{status}] → confidence {level}",
        f"{n_support} supporting / {n_counter} counter evidence item(s)",
    ]
    if unknowns:
        parts.append(f"{len(unknowns)} unknown(s)")
    if any(c.get("resolution") == RESOLUTION_REVIEW for c in conflicts):
        parts.append("unresolved conflict → REQUIRES_REVIEW")
    return "; ".join(parts) + "."


def render_evidence_markdown(result: dict[str, Any]) -> str:
    summary = result.get("summary") or {}
    meta = result.get("meta") or {}
    entries = result.get("findings_evidence") or []
    by_conf = summary.get("by_confidence") or {}

    lines: list[str] = [
        "# AXguard evidence & confidence (diagnostic)",
        "",
        "This is a **static evidence and confidence diagnostic**, not a vulnerability advisory.",
        "Confidence is derived from explainable evidence quality — unknowns pull it down and",
        "a single strong signal never hides a critical unknown. Secret values are never included.",
        "",
        f"- **Target:** `{result.get('target', '')}`",
        f"- **Schema:** `{result.get('schema_version', '')}`",
        f"- **Generated:** `{result.get('generated_at', '')}`",
        f"- **Findings with evidence:** {summary.get('finding_count', 0)}",
        f"- **Unique evidence items:** {summary.get('unique_evidence_count', 0)} "
        f"({summary.get('reused_evidence_count', 0)} reused across findings)",
        f"- **Conflicts:** {summary.get('conflict_count', 0)} · "
        f"**Unknowns:** {summary.get('unknown_count', 0)}",
        "",
        "## Confidence distribution",
        "",
        "| Confidence | Count |",
        "| --- | ---: |",
    ]
    for level in ("VERY_HIGH", "HIGH", "MEDIUM", "LOW", "UNKNOWN"):
        lines.append(f"| {level} | {by_conf.get(level, 0)} |")
    lines.append("")

    if entries:
        lines.extend(["## Findings", ""])
        order = {"VERY_HIGH": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}
        for entry in sorted(
            entries,
            key=lambda e: (
                order.get(str(e.get("confidence_level")), 9),
                str(e.get("finding_id")),
            ),
        ):
            loc = entry.get("location") or {}
            conf = entry.get("evidence_confidence") or {}
            lines.append(
                f"- **{entry.get('confidence_level')}** "
                f"`{entry.get('vulnerability_type')}` "
                f"[{entry.get('status')}] "
                f"@ `{loc.get('file')}:{loc.get('line')}` "
                f"(legacy=`{entry.get('legacy_confidence')}`)"
            )
            lines.append(f"  - {entry.get('summary')}")
            for reason in (conf.get("reasons") or [])[:4]:
                lines.append(f"  - reason: {reason}")
            for unk in (conf.get("unknowns") or [])[:4]:
                lines.append(f"  - unknown: {unk}")
            for conflict in entry.get("conflicts") or []:
                lines.append(
                    f"  - conflict[{conflict.get('aspect')}]: "
                    f"{conflict.get('resolution')} — {conflict.get('reason')}"
                )
        lines.append("")
    else:
        lines.extend(["## Findings", "", "_No findings with evidence produced._", ""])

    lines.extend(
        [
            "## Notes",
            "",
            "- Evidence is deduplicated and reused across findings (see `evidence_store`).",
            "- Unknowns always pull confidence down; a critical unknown caps confidence at MEDIUM.",
            "- Repository comments are never treated as evidence of safety.",
            "- Name-only controls (e.g. `sanitize()`) never raise confidence.",
            "- The LLM evidence stub can only explain existing evidence — it never invents any.",
            f"- Adversary source: `{meta.get('adversary', 'deterministic')}`.",
            "",
        ]
    )
    return "\n".join(lines)
