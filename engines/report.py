"""Report rendering — text, JSON, Markdown, HTML."""

from __future__ import annotations

import html
import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path


def render_report(result: dict, fmt: str = "text") -> str:
    if fmt == "json":
        return json.dumps(result, indent=2) + "\n"
    if fmt == "md" or fmt == "markdown":
        return render_markdown(result)
    if fmt == "html":
        return render_html(result)
    return _text_report(result)


def write_reports(result: dict, out_dir: Path, stem: str = "axguard-report") -> dict[str, Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    paths = {
        "json": out_dir / f"{stem}.json",
        "md": out_dir / f"{stem}.md",
        "html": out_dir / f"{stem}.html",
    }
    paths["json"].write_text(render_report(result, "json"), encoding="utf-8")
    paths["md"].write_text(render_report(result, "md"), encoding="utf-8")
    paths["html"].write_text(render_report(result, "html"), encoding="utf-8")
    return paths


def render_markdown(result: dict) -> str:
    findings = result.get("findings", [])
    counts = result.get("severity_counts") or _counts(findings)
    target = result.get("target", ".")
    when = result.get("finished_at") or datetime.now(timezone.utc).isoformat()
    lines = [
        "# AXguard Audit Report",
        "",
        f"**Target:** `{target}`  ",
        f"**Generated:** {when}  ",
        f"**Findings:** {len(findings)}  ",
        f"**Mode:** {result.get('mode', 'scan')}",
        "",
        "## Severity summary",
        "",
        "| Severity | Count |",
        "|---|---:|",
    ]
    for sev in ("critical", "high", "medium", "low", "info"):
        lines.append(f"| {sev} | {counts.get(sev, 0)} |")
    lines.append("")

    if result.get("phases"):
        lines.extend(["## Audit phases", ""])
        for phase in result["phases"]:
            lines.append(
                f"- **{phase['id']}** — {phase['label']} "
                f"({phase.get('finding_count', 0)} findings)"
            )
        lines.append("")

    lines.extend(["## Findings", ""])
    if not findings:
        lines.append("No findings.")
        lines.append("")
        return "\n".join(lines)

    for i, f in enumerate(findings, 1):
        lines.append(
            f"### {i}. [{str(f.get('severity', '?')).upper()}] {f.get('title', f.get('id'))}"
        )
        lines.append("")
        lines.append(f"- **ID:** `{f.get('id')}`")
        lines.append(f"- **Location:** `{f.get('file')}:{f.get('line')}`")
        if f.get("cwe"):
            lines.append(f"- **CWE:** {f['cwe']}")
        if f.get("snippet"):
            lines.append(f"- **Evidence:** `{f['snippet']}`")
        if f.get("message"):
            lines.append(f"- **Why it matters:** {f['message']}")
        if f.get("fix"):
            lines.append(f"- **Fix:** {f['fix']}")
        lines.append("")
    return "\n".join(lines)


def render_html(result: dict) -> str:
    findings = result.get("findings", [])
    counts = result.get("severity_counts") or _counts(findings)
    target = html.escape(str(result.get("target", ".")))
    when = html.escape(str(result.get("finished_at") or datetime.now(timezone.utc).isoformat()))
    mode = html.escape(str(result.get("mode", "scan")))
    total = len(findings)

    cards = "".join(
        f'<div class="card sev-{sev}"><span class="label">{sev}</span>'
        f'<span class="n">{counts.get(sev, 0)}</span></div>'
        for sev in ("critical", "high", "medium", "low", "info")
    )

    phases_html = ""
    if result.get("phases"):
        items = "".join(
            f"<li><strong>{html.escape(p['id'])}</strong> — "
            f"{html.escape(p['label'])} "
            f"<em>{p.get('finding_count', 0)}</em></li>"
            for p in result["phases"]
        )
        phases_html = f'<section class="phases"><h2>Audit phases</h2><ol>{items}</ol></section>'

    if findings:
        finding_blocks = []
        for i, f in enumerate(findings, 1):
            sev = html.escape(str(f.get("severity", "info")).lower())
            title = html.escape(str(f.get("title", f.get("id", "finding"))))
            fid = html.escape(str(f.get("id", "")))
            loc = html.escape(f"{f.get('file')}:{f.get('line')}")
            message = html.escape(str(f.get("message") or ""))
            fix = html.escape(str(f.get("fix") or ""))
            snippet = html.escape(str(f.get("snippet") or ""))
            cwe = html.escape(str(f.get("cwe") or ""))
            finding_blocks.append(
                f"""
<article class="finding sev-{sev}">
  <header>
    <span class="badge">{sev}</span>
    <h3>{i}. {title}</h3>
  </header>
  <dl>
    <div><dt>ID</dt><dd><code>{fid}</code></dd></div>
    <div><dt>Location</dt><dd><code>{loc}</code></dd></div>
    {"<div><dt>CWE</dt><dd>" + cwe + "</dd></div>" if cwe else ""}
  </dl>
  {"<pre class='evidence'>" + snippet + "</pre>" if snippet else ""}
  {"<p class='why'><strong>Why it matters.</strong> " + message + "</p>" if message else ""}
  {"<p class='fix'><strong>Fix.</strong> " + fix + "</p>" if fix else ""}
</article>
"""
            )
        findings_html = "".join(finding_blocks)
    else:
        findings_html = '<p class="empty">No findings.</p>'

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>AXguard Report</title>
<link rel="preconnect" href="https://fonts.googleapis.com"/>
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin/>
<link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;600&family=Syne:wght@600;700;800&display=swap" rel="stylesheet"/>
<style>
:root {{
  --bg: #0c1117;
  --panel: #141b24;
  --ink: #e7eef7;
  --muted: #8b9bb0;
  --line: #243041;
  --accent: #3dd6c6;
  --critical: #ff5c5c;
  --high: #ff9f43;
  --medium: #f6c945;
  --low: #6ec3ff;
  --info: #8b9bb0;
}}
* {{ box-sizing: border-box; }}
body {{
  margin: 0;
  color: var(--ink);
  background:
    radial-gradient(1200px 600px at 10% -10%, #163028 0%, transparent 55%),
    radial-gradient(900px 500px at 100% 0%, #1a2433 0%, transparent 50%),
    var(--bg);
  font-family: "IBM Plex Mono", ui-monospace, monospace;
  line-height: 1.55;
}}
.wrap {{
  max-width: 980px;
  margin: 0 auto;
  padding: 48px 24px 80px;
}}
.hero {{
  border: 1px solid var(--line);
  background: linear-gradient(160deg, #17202b 0%, #10161e 100%);
  padding: 36px 32px;
  position: relative;
  overflow: hidden;
}}
.hero::before {{
  content: "";
  position: absolute;
  inset: 0 auto 0 0;
  width: 4px;
  background: var(--accent);
}}
.brand {{
  font-family: Syne, system-ui, sans-serif;
  font-weight: 800;
  letter-spacing: 0.08em;
  font-size: 0.85rem;
  color: var(--accent);
  text-transform: uppercase;
}}
h1 {{
  font-family: Syne, system-ui, sans-serif;
  font-size: clamp(2rem, 4vw, 3rem);
  margin: 10px 0 8px;
  letter-spacing: -0.03em;
}}
.meta {{
  color: var(--muted);
  display: grid;
  gap: 4px;
  margin-top: 18px;
  font-size: 0.9rem;
}}
.meta strong {{ color: var(--ink); font-weight: 600; }}
.cards {{
  display: grid;
  grid-template-columns: repeat(5, minmax(0, 1fr));
  gap: 10px;
  margin: 28px 0;
}}
.card {{
  background: var(--panel);
  border: 1px solid var(--line);
  padding: 14px 12px;
  display: grid;
  gap: 6px;
}}
.card .label {{
  text-transform: uppercase;
  font-size: 0.7rem;
  letter-spacing: 0.08em;
  color: var(--muted);
}}
.card .n {{
  font-family: Syne, system-ui, sans-serif;
  font-size: 1.8rem;
  font-weight: 700;
}}
.card.sev-critical .n {{ color: var(--critical); }}
.card.sev-high .n {{ color: var(--high); }}
.card.sev-medium .n {{ color: var(--medium); }}
.card.sev-low .n {{ color: var(--low); }}
.card.sev-info .n {{ color: var(--info); }}
section {{ margin-top: 36px; }}
h2 {{
  font-family: Syne, system-ui, sans-serif;
  font-size: 1.25rem;
  margin: 0 0 16px;
}}
.phases ol {{
  margin: 0;
  padding-left: 1.2rem;
  color: var(--muted);
}}
.phases strong {{ color: var(--ink); }}
.phases em {{
  font-style: normal;
  color: var(--accent);
}}
.finding {{
  background: var(--panel);
  border: 1px solid var(--line);
  border-left: 3px solid var(--line);
  padding: 18px 18px 16px;
  margin-bottom: 12px;
}}
.finding.sev-critical {{ border-left-color: var(--critical); }}
.finding.sev-high {{ border-left-color: var(--high); }}
.finding.sev-medium {{ border-left-color: var(--medium); }}
.finding.sev-low {{ border-left-color: var(--low); }}
.finding header {{
  display: flex;
  gap: 12px;
  align-items: baseline;
  flex-wrap: wrap;
}}
.finding h3 {{
  margin: 0;
  font-family: Syne, system-ui, sans-serif;
  font-size: 1.05rem;
}}
.badge {{
  text-transform: uppercase;
  font-size: 0.68rem;
  letter-spacing: 0.08em;
  padding: 3px 8px;
  border: 1px solid var(--line);
  color: var(--muted);
}}
.finding.sev-critical .badge {{ color: var(--critical); border-color: #5a2a2a; }}
.finding.sev-high .badge {{ color: var(--high); border-color: #5a3d1f; }}
.finding.sev-medium .badge {{ color: var(--medium); border-color: #5a4f1f; }}
.finding.sev-low .badge {{ color: var(--low); border-color: #1f3d5a; }}
dl {{
  display: grid;
  gap: 8px;
  margin: 14px 0 10px;
}}
dl div {{ display: flex; gap: 12px; flex-wrap: wrap; }}
dt {{ color: var(--muted); min-width: 72px; }}
dd {{ margin: 0; }}
code, pre {{
  font-family: "IBM Plex Mono", ui-monospace, monospace;
}}
code {{
  color: var(--accent);
  word-break: break-all;
}}
.evidence {{
  background: #0a0f14;
  border: 1px solid var(--line);
  padding: 12px 14px;
  overflow-x: auto;
  color: #d5e4f5;
  font-size: 0.85rem;
}}
.why, .fix {{ color: #c5d2e2; margin: 10px 0 0; }}
.empty {{ color: var(--muted); }}
footer {{
  margin-top: 48px;
  color: var(--muted);
  font-size: 0.8rem;
  border-top: 1px solid var(--line);
  padding-top: 16px;
}}
@media (max-width: 720px) {{
  .cards {{ grid-template-columns: repeat(2, minmax(0, 1fr)); }}
}}
</style>
</head>
<body>
  <div class="wrap">
    <header class="hero">
      <div class="brand">AXguard</div>
      <h1>Security audit report</h1>
      <div class="meta">
        <div><strong>Target</strong> {target}</div>
        <div><strong>Generated</strong> {when}</div>
        <div><strong>Mode</strong> {mode} · <strong>Findings</strong> {total}</div>
      </div>
    </header>

    <div class="cards">{cards}</div>
    {phases_html}
    <section>
      <h2>Findings</h2>
      {findings_html}
    </section>
    <footer>Generated by AXguard · pre-ship security gate</footer>
  </div>
</body>
</html>
"""


def _text_report(result: dict) -> str:
    findings = result.get("findings", [])
    lines = [
        f"AXguard scan — {result.get('target')}",
        f"Findings: {len(findings)}",
        "",
    ]
    if not findings:
        lines.append("No findings.")
        return "\n".join(lines) + "\n"

    for f in findings:
        lines.append(
            f"[{f.get('severity', '?').upper()}] {f.get('id')} — {f.get('title')}"
        )
        lines.append(f"  {f.get('file')}:{f.get('line')}")
        if f.get("snippet"):
            lines.append(f"  {f['snippet']}")
        if f.get("message"):
            lines.append(f"  {f['message']}")
        if f.get("fix"):
            lines.append(f"  Fix: {f['fix']}")
        lines.append("")
    return "\n".join(lines)


def _counts(findings: list[dict]) -> dict[str, int]:
    c = Counter(str(f.get("severity", "info")).lower() for f in findings)
    return {
        "critical": c.get("critical", 0),
        "high": c.get("high", 0),
        "medium": c.get("medium", 0),
        "low": c.get("low", 0),
        "info": c.get("info", 0),
    }
