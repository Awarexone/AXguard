"""Render Investigation Agent reports (markdown / HTML)."""

from __future__ import annotations

import html
import json
from pathlib import Path
from typing import Any

from engines.dataflow.schema import ensure_no_secret_values
from engines.investigation.schema import UNKNOWN


def render_investigation_markdown(result: dict[str, Any]) -> str:
    summary = result.get("summary") or {}
    lines = [
        "# AXguard Investigation Agent",
        "",
        f"- **Target:** `{result.get('target') or UNKNOWN}`",
        f"- **Budget:** `{result.get('budget') or UNKNOWN}`",
        f"- **Generated:** `{result.get('generated_at') or UNKNOWN}`",
        f"- **Investigations:** {summary.get('investigation_count', 0)}",
        f"- **VERIFIED:** {summary.get('verified', 0)}",
        f"- **LIKELY:** {summary.get('likely', 0)}",
        f"- **FALSE_POSITIVE:** {summary.get('false_positive', 0)}",
        f"- **UNVERIFIED:** {summary.get('unverified', 0)}",
        f"- **REQUIRES_REVIEW:** {summary.get('requires_review', 0)}",
        "",
        "> Symbolic investigation — evidence-driven; prefer UNKNOWN over invented facts.",
        "",
    ]
    for inv in result.get("investigations") or []:
        lines.extend(_one_markdown(inv))
    if not (result.get("investigations") or []):
        lines.append("_No candidates investigated._")
        lines.append("")
    return "\n".join(lines)


def _one_markdown(inv: dict[str, Any]) -> list[str]:
    cand = inv.get("candidate") or {}
    lines = [
        f"## Investigation `{inv.get('investigation_id') or UNKNOWN}`",
        "",
        f"- **Candidate:** `{inv.get('candidate_id')}` ({cand.get('vulnerability_type')})",
        f"- **Status:** {inv.get('status')}",
        f"- **Decision:** {inv.get('decision') or UNKNOWN}",
        f"- **Confidence:** {inv.get('confidence_before')} → {inv.get('confidence_after')}",
        f"- **Termination:** {inv.get('termination_reason') or UNKNOWN}",
        f"- **Reasoning:** {inv.get('reasoning_summary') or UNKNOWN}",
        f"- **Cost:** actions={inv.get('actions_spent', 0)} weight={inv.get('cost_spent', 0)}",
        f"- **Specialists:** {', '.join(inv.get('specialists_used') or []) or UNKNOWN}",
        "",
    ]
    if inv.get("hypothesis"):
        lines.append(f"**Hypothesis:** {inv['hypothesis']}")
        lines.append("")

    qs = inv.get("questions") or []
    if qs:
        lines.append("### Questions")
        lines.append("")
        for q in qs:
            lines.append(
                f"- `{q.get('question_id')}` [{q.get('status')}] "
                f"{q.get('text')} → `{q.get('answer')}`"
            )
        lines.append("")

    acts = inv.get("investigations_performed") or []
    if acts:
        lines.append("### Actions")
        lines.append("")
        for a in acts:
            lines.append(
                f"- `{a.get('type')}` cost={a.get('cost')} status={a.get('status')} "
                f"— {a.get('purpose')}"
            )
        lines.append("")

    if inv.get("evidence"):
        lines.append("### Evidence")
        lines.append("")
        for e in inv["evidence"][:30]:
            lines.append(
                f"- [{e.get('strength')}] {e.get('summary')} ({e.get('source')})"
            )
        lines.append("")

    if inv.get("counter_evidence"):
        lines.append("### Counter-evidence")
        lines.append("")
        for e in inv["counter_evidence"][:30]:
            lines.append(
                f"- [{e.get('strength')}] {e.get('summary')} ({e.get('source')})"
            )
        lines.append("")

    if inv.get("controls_found"):
        lines.append("### Controls")
        lines.append("")
        for c in inv["controls_found"][:20]:
            if isinstance(c, dict):
                lines.append(f"- {c.get('name') or c.get('id') or c}")
            else:
                lines.append(f"- {c}")
        lines.append("")

    if inv.get("unknowns"):
        lines.append("### Unknowns")
        lines.append("")
        for u in inv["unknowns"][:20]:
            if isinstance(u, dict):
                lines.append(f"- {u.get('topic')}: {u.get('detail')}")
            else:
                lines.append(f"- {u}")
        lines.append("")

    if inv.get("attack_paths"):
        lines.append("### Attack paths")
        lines.append("")
        for p in inv["attack_paths"][:10]:
            hops = " → ".join(str(h) for h in (p.get("hops") or [])[:8])
            lines.append(f"- [{p.get('status')}] {hops or '(no hops)'}")
        lines.append("")

    if inv.get("timeline"):
        lines.append("### Timeline")
        lines.append("")
        for t in inv["timeline"][:40]:
            lines.append(f"- `{t.get('event')}` — {t.get('detail')}")
        lines.append("")

    return lines


def render_investigation_html_section(result: dict[str, Any]) -> str:
    summary = result.get("summary") or {}
    rows = []
    for inv in (result.get("investigations") or [])[:40]:
        cand = inv.get("candidate") or {}
        rows.append(
            "<article class='axguard-investigation-item'>"
            f"<h3>{html.escape(str(inv.get('investigation_id') or UNKNOWN))}</h3>"
            f"<p class='meta'>Candidate <code>{html.escape(str(inv.get('candidate_id')))}</code>"
            f" · {html.escape(str(cand.get('vulnerability_type') or UNKNOWN))}"
            f" · status {html.escape(str(inv.get('status')))}"
            f" · decision <strong>{html.escape(str(inv.get('decision') or UNKNOWN))}</strong></p>"
            f"<p>{html.escape(str(inv.get('reasoning_summary') or ''))}</p>"
            f"<p class='meta'>Confidence {html.escape(str(inv.get('confidence_before')))}"
            f" → {html.escape(str(inv.get('confidence_after')))}"
            f" · stop: {html.escape(str(inv.get('termination_reason') or UNKNOWN))}</p>"
            "<details><summary>Trail</summary>"
            f"<p>Specialists: {html.escape(', '.join(inv.get('specialists_used') or []) or UNKNOWN)}</p>"
            "<ul>"
            + "".join(
                f"<li><code>{html.escape(str(a.get('type')))}</code> "
                f"({html.escape(str(a.get('cost')))})</li>"
                for a in (inv.get("investigations_performed") or [])[:20]
            )
            + "</ul>"
            "<p>Evidence:</p><ul>"
            + "".join(
                f"<li>{html.escape(str(e.get('summary')))}</li>"
                for e in (inv.get("evidence") or [])[:15]
            )
            + "</ul>"
            "<p>Counter-evidence:</p><ul>"
            + "".join(
                f"<li>{html.escape(str(e.get('summary')))}</li>"
                for e in (inv.get("counter_evidence") or [])[:15]
            )
            + "</ul>"
            "<p>Unknowns:</p><ul>"
            + "".join(
                f"<li>{html.escape(str(u.get('topic') if isinstance(u, dict) else u))}</li>"
                for u in (inv.get("unknowns") or [])[:15]
            )
            + "</ul></details></article>"
        )
    body = "".join(rows) or "<p><em>No investigations.</em></p>"
    return (
        '<section class="axguard-investigation">'
        "<h2>Investigation Agent</h2>"
        f"<p class='meta'>budget <code>{html.escape(str(result.get('budget') or UNKNOWN))}</code>"
        f" · count {html.escape(str(summary.get('investigation_count', 0)))}"
        f" · verified {html.escape(str(summary.get('verified', 0)))}"
        f" · FP {html.escape(str(summary.get('false_positive', 0)))}"
        f" · unverified {html.escape(str(summary.get('unverified', 0)))}</p>"
        f"{body}</section>"
    )


def write_investigation_report(
    result: dict[str, Any],
    out_dir: Path | str,
) -> dict[str, str]:
    root = Path(out_dir)
    root.mkdir(parents=True, exist_ok=True)
    ensure_no_secret_values(result)

    md_path = root / "investigation.md"
    html_path = root / "investigation-section.html"
    json_path = root / "investigation.json"

    md_path.write_text(render_investigation_markdown(result), encoding="utf-8")
    html_path.write_text(render_investigation_html_section(result), encoding="utf-8")
    json_path.write_text(
        json.dumps(result, indent=2, default=str) + "\n", encoding="utf-8"
    )
    return {
        "markdown": str(md_path),
        "html_section": str(html_path),
        "json": str(json_path),
    }
