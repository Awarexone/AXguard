"""Markdown + HTML reports for the training-data pipeline."""

from __future__ import annotations

import html
import json
from pathlib import Path
from typing import Any

from engines.dataflow.schema import ensure_no_secret_values


def render_data_markdown(result: dict[str, Any]) -> str:
    reg = result.get("registry") or {}
    summary = result.get("summary") or {}
    prep = result.get("prepare") or {}
    counts = prep.get("counts") or {}
    lines = [
        "# AXGuard Training Data Report",
        "",
        "> Data infrastructure only — **no model was trained**.",
        "",
        f"- Target: `{result.get('target')}`",
        f"- Generated: `{result.get('generated_at')}`",
        f"- Datasets: **{summary.get('dataset_count', (reg.get('summary') or {}).get('dataset_count', 0))}**",
        f"- Examples processed: **{summary.get('example_count', 0)}**",
        f"- Duplicates: **{summary.get('duplicate_count', 0)}**",
        f"- Scrub hits: **{summary.get('scrub_count', 0)}**",
        f"- Poison flags: **{summary.get('poison_count', 0)}**",
        "",
        "## Splits",
        "",
        f"- TRAINING: {counts.get('TRAINING', 0)}",
        f"- VALIDATION: {counts.get('VALIDATION', 0)}",
        f"- TEST: {counts.get('TEST', 0)}",
        f"- BENCHMARK_ONLY: {counts.get('BENCHMARK_ONLY', 0)}",
        f"- RESEARCH_ONLY: {counts.get('RESEARCH_ONLY', 0)}",
        f"- Blocked from training: {counts.get('blocked', 0)}",
        f"- DPO pairs: {counts.get('dpo_pairs', 0)}",
        "",
        "## Datasets",
        "",
    ]
    for d in reg.get("datasets") or []:
        gate = d.get("gate") or {}
        lines.append(
            f"- `{d.get('dataset_id')}` — status={d.get('status')} "
            f"license={d.get('license')} verified={d.get('license_verified')} "
            f"public_train={gate.get('allowed_public_training')}"
        )
        for r in gate.get("reasons") or []:
            lines.append(f"  - gate: {r}")
    if result.get("poison_flags"):
        lines.extend(["", "## Poison flags", ""])
        for p in result["poison_flags"][:20]:
            lines.append(f"- {p.get('example_id')}: {p.get('flag')}")
    if prep.get("blocked_from_training"):
        lines.extend(["", "## Contamination guards", ""])
        for b in prep["blocked_from_training"][:20]:
            lines.append(f"- {b.get('example_id')}: {b.get('reason')}")
    lines.append("")
    return "\n".join(lines)


def render_data_html(result: dict[str, Any]) -> str:
    md_like = render_data_markdown(result)
    body = html.escape(md_like)
    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"/>
<title>AXGuard Training Data Report</title>
<style>
body {{ margin:0; font-family: ui-monospace, monospace; background:#0c1117; color:#e7eef7; }}
.wrap {{ max-width:900px; margin:0 auto; padding:40px 24px; }}
pre {{ white-space:pre-wrap; line-height:1.5; }}
.banner {{ border:1px solid #243041; padding:16px; margin-bottom:24px; }}
.banner strong {{ color:#3dd6c6; }}
</style></head><body><div class="wrap">
<div class="banner"><strong>READ-ONLY DATA PIPELINE</strong><br/>
No model training. No external uploads. License gate enforced.</div>
<pre>{body}</pre>
</div></body></html>
"""


def write_data_reports(result: dict[str, Any], out_dir: Path) -> dict[str, str]:
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    ensure_no_secret_values(result)
    json_path = out_dir / "data-pipeline.json"
    md_path = out_dir / "data-pipeline.md"
    html_path = out_dir / "data-pipeline.html"
    public = {k: v for k, v in result.items() if not str(k).startswith("_")}
    json_path.write_text(json.dumps(public, indent=2) + "\n", encoding="utf-8")
    md_path.write_text(render_data_markdown(result), encoding="utf-8")
    html_path.write_text(render_data_html(result), encoding="utf-8")
    return {"json": str(json_path), "markdown": str(md_path), "html": str(html_path)}
