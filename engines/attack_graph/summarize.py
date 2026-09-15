"""Human-readable attack-path summaries."""

from __future__ import annotations

from typing import Any

from engines.attack_graph.schema import PATH_STATUSES


def build_summary(assembled: dict[str, Any], dead_ends: list[dict[str, Any]]) -> dict[str, Any]:
    paths = assembled.get("paths") or []
    by_status = {s: 0 for s in sorted(PATH_STATUSES)}
    for p in paths:
        st = str(p.get("status"))
        if st in by_status:
            by_status[st] += 1
    return {
        "path_count": len(paths),
        "dead_end_count": len(dead_ends),
        "node_count": len(assembled.get("nodes") or []),
        "edge_count": len(assembled.get("edges") or []),
        "alternate_path_count": len(assembled.get("alternate_paths") or []),
        "by_status": by_status,
    }


def _label_for(graph: dict[str, Any], node_id: str) -> str:
    for n in graph.get("nodes") or []:
        if n.get("id") == node_id:
            return str(n.get("label") or node_id)
    return str(node_id)


def render_path_line(result: dict[str, Any], path: dict[str, Any]) -> str:
    graph = result.get("graph") or {}
    labels = [_label_for(graph, h) for h in path.get("hops") or []]
    arrow = " → ".join(labels)
    return arrow


def render_attack_paths_markdown(result: dict[str, Any]) -> str:
    summary = result.get("summary") or {}
    meta = result.get("meta") or {}
    by_status = summary.get("by_status") or {}
    paths = result.get("paths") or []
    dead_ends = result.get("dead_ends") or []

    lines: list[str] = [
        "# AXguard attack paths (diagnostic)",
        "",
        "This is a **static attack-path composition diagnostic**, not a vulnerability advisory.",
        "Paths chain existing Phase 1-5 findings into `entrypoint → … → sensitive outcome`.",
        "No new confidence system is invented — a path is only as strong as its weakest hop, and",
        "an effective control on a required edge marks the *path* BLOCKED (the finding still stands).",
        "",
        f"- **Target:** `{result.get('target', '')}`",
        f"- **Schema:** `{result.get('schema_version', '')}`",
        f"- **Generated:** `{result.get('generated_at', '')}`",
        f"- **Paths:** {summary.get('path_count', 0)} · **Dead ends:** {summary.get('dead_end_count', 0)}",
        f"- **Graph:** {summary.get('node_count', 0)} nodes / {summary.get('edge_count', 0)} edges",
        "",
        "## Status distribution",
        "",
        "| Status | Count |",
        "| --- | ---: |",
    ]
    for status in ("CONFIRMED", "LIKELY", "UNVERIFIED", "BLOCKED", "INVALID"):
        lines.append(f"| {status} | {by_status.get(status, 0)} |")
    lines.append("")

    if paths:
        lines.extend(["## Attack paths", ""])
        for p in paths:
            lines.append(
                f"### {p.get('id')} — {p.get('status')} "
                f"(confidence {p.get('confidence_level')}, score {p.get('score')})"
            )
            lines.append("")
            lines.append(f"`{render_path_line(result, p)}`")
            lines.append("")
            if p.get("tags"):
                lines.append(f"- tags: {', '.join(p['tags'])}")
            if p.get("selection"):
                lines.append(f"- selection: {', '.join(p['selection'])}")
            for r in p.get("status_reasons") or []:
                lines.append(f"- {r}")
            for c in p.get("controls_encountered") or []:
                lines.append(f"- control encountered: `{c.get('id')}` (effectiveness={c.get('effectiveness')})")
            lines.append("")
    else:
        lines.extend(["## Attack paths", "", "_No multi-hop attack paths composed._", ""])

    if dead_ends:
        lines.extend(["## Dead ends (standalone findings — not chained)", ""])
        for d in dead_ends:
            loc = d.get("location") or {}
            lines.append(
                f"- `{d.get('vulnerability_type')}` [{d.get('status')}] "
                f"@ `{loc.get('file')}:{loc.get('line')}` — {d.get('reason')}"
            )
        lines.append("")

    lines.extend(
        [
            "## Notes",
            "",
            "- Same-file co-location is never upgraded into a chain; only explicit data/control-flow links chain.",
            "- FALSE_POSITIVE hops veto a chain (INVALID); unknown reachability yields UNVERIFIED, not a public claim.",
            "- Effective controls (fails-closed crypto auth) block the path; name-only / mutable-field controls do not.",
            "- Structural seed nodes are LIKELY at best and are clearly marked `candidate_seed` / `attack_graph_seed`.",
            "- The LLM attack-path stub can only explain existing graph elements — it never invents any.",
            f"- Evidence source: `{meta.get('adversary', 'deterministic')}`.",
            "",
        ]
    )
    return "\n".join(lines)
