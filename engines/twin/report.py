"""Security Twin report rendering (markdown + offline HTML)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def render_twin_markdown(result: dict[str, Any]) -> str:
    """Render a Security Twin result as markdown with OBSERVED/SIMULATED sections."""
    twin = result.get("twin") or result
    lines = [
        "# AXguard Security Twin",
        "",
        f"**Target:** `{twin.get('target')}`",
        f"**Schema:** {twin.get('schema_version')}",
        "",
        "> " + (twin.get("disclaimer") or "Symbolic analysis only."),
        "",
        "## Summary (OBSERVED)",
        "",
        _render_summary(twin.get("summary") or {}),
        "",
        "## Entities (OBSERVED)",
        "",
        _render_entities(twin.get("entities") or [], limit=30),
        "",
    ]

    sim = result.get("simulation") or {}
    if sim:
        lines.extend(["## Observed Paths", "", _render_paths(sim.get("observed_paths") or [])])
        lines.extend(["", "## Simulated Paths", "", _render_paths(sim.get("simulated_paths") or [])])

    cf = result.get("counterfactual") or {}
    if cf.get("simulated_paths"):
        lines.extend(["", "## Counterfactual (SIMULATED)", "", _render_counterfactual(cf)])

    controls = result.get("controls") or []
    if controls:
        lines.extend(["", "## Control Effectiveness (OBSERVED)", "", _render_controls(controls)])

    return "\n".join(lines) + "\n"


def render_twin_html_section(result: dict[str, Any]) -> str:
    """Offline HTML snippet — no external assets."""
    md = render_twin_markdown(result)
    escaped = (
        md.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
    )
    twin = result.get("twin") or result
    return f"""<section class="axguard-security-twin">
<style>
.axguard-security-twin {{ font-family: system-ui, sans-serif; max-width: 900px; margin: 1rem auto; }}
.axguard-security-twin h1 {{ color: #1a1a2e; }}
.axguard-security-twin .observed {{ border-left: 4px solid #2ecc71; padding-left: 1rem; }}
.axguard-security-twin .simulated {{ border-left: 4px solid #e67e22; padding-left: 1rem; }}
.axguard-security-twin pre {{ background: #f4f4f4; padding: 1rem; overflow-x: auto; }}
.axguard-security-twin .disclaimer {{ background: #fff3cd; padding: 0.75rem; border-radius: 4px; }}
</style>
<div class="disclaimer">{twin.get('disclaimer', '')}</div>
<div class="observed"><h2>OBSERVED</h2><pre>{escaped.split('## Simulated')[0] if '## Simulated' in escaped else escaped}</pre></div>
<div class="simulated"><h2>SIMULATED / ASSUMED</h2><pre>{escaped.split('## Simulated')[-1] if '## Simulated' in escaped else '(none)'}</pre></div>
</section>"""


def write_twin_report(result: dict[str, Any], out_dir: Path) -> dict[str, Any]:
    """Write security-twin.json, .md, and .html under ``out_dir``."""
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    twin = result.get("twin") or result

    json_path = out_dir / "security-twin.json"
    md_path = out_dir / "security-twin.md"
    html_path = out_dir / "security-twin.html"

    json_path.write_text(json.dumps(result, indent=2, default=str) + "\n", encoding="utf-8")
    md_path.write_text(render_twin_markdown(result), encoding="utf-8")
    html_path.write_text(
        f"<!DOCTYPE html><html><head><meta charset='utf-8'><title>Security Twin</title></head>"
        f"<body>{render_twin_html_section(result)}</body></html>",
        encoding="utf-8",
    )

    return {"json": str(json_path), "markdown": str(md_path), "html": str(html_path)}


def _render_summary(summary: dict[str, Any]) -> str:
    return "\n".join(f"- **{k}:** {v}" for k, v in sorted(summary.items()))


def _render_entities(entities: list[dict[str, Any]], *, limit: int) -> str:
    lines = ["| ID | Type | Layer |", "|---|---|---|"]
    for ent in entities[:limit]:
        lines.append(f"| `{ent.get('id')}` | {ent.get('type')} | {ent.get('layer', 'OBSERVED')} |")
    if len(entities) > limit:
        lines.append(f"\n_…and {len(entities) - limit} more entities._")
    return "\n".join(lines)


def _render_paths(paths: list[dict[str, Any]]) -> str:
    if not paths:
        return "_None._"
    lines = []
    for p in paths:
        pid = p.get("path_id") or p.get("id")
        status = p.get("status")
        if isinstance(status, dict):
            status = status.get("value")
        lines.append(f"- `{pid}` — {status} (layer: {p.get('layer', '?')})")
    return "\n".join(lines)


def _render_counterfactual(cf: dict[str, Any]) -> str:
    lines = [f"Scenario: {cf.get('scenario')}", ""]
    for p in cf.get("simulated_paths") or []:
        lines.append(f"- {p.get('title') or p.get('id')}: {p.get('premise', {}).get('value', '')}")
    return "\n".join(lines)


def _render_controls(controls: list[dict[str, Any]]) -> str:
    lines = ["| Control | Protected | Exposed if removed |", "|---|---|---|"]
    for c in controls[:15]:
        prot = c.get("protected_path_count", {})
        exp = c.get("paths_exposed_if_removed", {})
        lines.append(
            f"| `{c.get('control_id')}` | {prot.get('value', prot)} | {exp.get('value', exp)} |"
        )
    return "\n".join(lines)
