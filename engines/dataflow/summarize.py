"""Human-readable dataflow summary (diagnostic, not a vuln report)."""

from __future__ import annotations

from typing import Any


def render_dataflow_markdown(flow: dict[str, Any]) -> str:
    summary = flow.get("summary") or {}
    lines: list[str] = [
        "# AXguard dataflow (diagnostic)",
        "",
        "This is a **static taint / dataflow inventory**, not a vulnerability report.",
        "Prefer UNKNOWN over inventing safety. Confirm before treating paths as findings.",
        "",
        f"- **Target:** `{flow.get('target', '')}`",
        f"- **Schema:** `{flow.get('schema_version', '')}`",
        f"- **Generated:** `{flow.get('generated_at', '')}`",
        "",
        "## Summary",
        "",
        f"| Metric | Count |",
        f"| --- | ---: |",
        f"| Sources | {summary.get('source_count', 0)} |",
        f"| Sinks | {summary.get('sink_count', 0)} |",
        f"| Taint paths | {summary.get('path_count', 0)} |",
        f"| Unsanitized (TAINTED) | {summary.get('unsanitized_path_count', 0)} |",
        "",
    ]

    paths = flow.get("taint_paths") or []
    if paths:
        lines.extend(["## Top taint paths", ""])
        for path in paths[:25]:
            src = path.get("source") or {}
            sink = path.get("sink") or {}
            ep = src.get("endpoint") or {}
            ep_s = ""
            if ep.get("path"):
                ep_s = f" via `{ep.get('method')} {ep.get('path')}`"
            lines.append(
                f"- **{path.get('taint_state')}** "
                f"(`{path.get('confidence')}`) "
                f"`{src.get('name')}` ({src.get('kind')}) → "
                f"`{sink.get('type')}:{sink.get('symbol')}` "
                f"@ `{sink.get('file')}:{sink.get('line')}`{ep_s}"
            )
            controls = path.get("controls_seen") or []
            if controls:
                lines.append(f"  - controls: {', '.join(str(c) for c in controls[:5])}")
        lines.append("")
    else:
        lines.extend(["## Top taint paths", "", "_No source→sink paths inferred._", ""])

    sources = flow.get("sources") or []
    if sources:
        lines.extend(["## Sources (sample)", ""])
        for s in sources[:20]:
            lines.append(
                f"- `{s.get('kind')}` `{s.get('name')}` "
                f"trust=`{s.get('trust_level')}` "
                f"@ `{s.get('file')}:{s.get('line')}`"
            )
        lines.append("")

    sinks = flow.get("sinks") or []
    if sinks:
        lines.extend(["## Sinks (sample)", ""])
        for s in sinks[:20]:
            lines.append(
                f"- `{s.get('type')}` `{s.get('symbol')}` "
                f"@ `{s.get('file')}:{s.get('line')}`"
            )
        lines.append("")

    lines.extend(
        [
            "## Notes",
            "",
            "- Intraprocedural heuristics only (Python / JS/TS first).",
            "- SANITIZED requires confirmed parameterization or allowlist evidence.",
            "- Secret values are never included in this report.",
            "",
        ]
    )
    return "\n".join(lines)
