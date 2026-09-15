"""Render Security Memory reports (markdown / HTML section)."""

from __future__ import annotations

import html
from pathlib import Path
from typing import Any

from engines.dataflow.schema import ensure_no_secret_values
from engines.memory.query import get_current_state, get_history
from engines.memory.schema import UNKNOWN
from engines.memory.store import resolve_memory_dir


def render_memory_markdown(
    snapshot_or_state: dict[str, Any] | None = None,
    *,
    memory_dir: Path | str | None = None,
) -> str:
    """Human-readable memory summary. Structured fields only — no invented history."""
    if snapshot_or_state is None and memory_dir is not None:
        state = get_current_state(memory_dir)
        snap = state.get("snapshot") or {}
        index = state.get("index") or {}
    elif snapshot_or_state and snapshot_or_state.get("kind") == "security_memory_snapshot":
        snap = snapshot_or_state
        index = {}
    elif snapshot_or_state and "snapshot" in (snapshot_or_state or {}):
        snap = snapshot_or_state.get("snapshot") or {}
        index = snapshot_or_state.get("index") or {}
    else:
        snap = snapshot_or_state or {}
        index = {}

    summary = snap.get("summary") or {}
    lines = [
        "# AXguard Security Memory",
        "",
        f"- **Snapshot:** `{snap.get('snapshot_id') or UNKNOWN}`",
        f"- **Revision:** `{snap.get('source_revision') or UNKNOWN}`",
        f"- **Target:** `{snap.get('target') or UNKNOWN}`",
        f"- **Generated:** `{snap.get('generated_at') or UNKNOWN}`",
        f"- **Findings:** {summary.get('finding_count', len(snap.get('findings') or []))}",
        f"- **Controls:** {summary.get('control_count', len(snap.get('controls') or []))}",
        f"- **Attack paths:** {summary.get('path_count', len(snap.get('attack_paths') or []))}",
        f"- **Unknowns:** {summary.get('unknown_count', len(snap.get('unknowns') or []))}",
        "",
    ]
    if index.get("snapshot_ids"):
        lines.append(f"- **Snapshots on disk:** {len(index.get('snapshot_ids') or [])}")
        lines.append("")

    findings = snap.get("findings") or []
    if findings:
        lines.extend(["## Findings", ""])
        for f in findings[:50]:
            lines.append(
                f"- `{f.get('fingerprint')}` — {f.get('lifecycle') or UNKNOWN} / "
                f"{f.get('status') or UNKNOWN} @ `{f.get('file') or UNKNOWN}`"
            )
        lines.append("")

    paths = snap.get("attack_paths") or []
    if paths:
        lines.extend(["## Attack paths", ""])
        for p in paths[:50]:
            hops = " → ".join(str(h) for h in (p.get("hops") or [])[:6])
            lines.append(
                f"- `{p.get('fingerprint')}` — {p.get('status') or UNKNOWN}"
                + (f" ({hops})" if hops else "")
            )
        lines.append("")

    controls = snap.get("controls") or []
    if controls:
        lines.extend(["## Controls", ""])
        for c in controls[:50]:
            lines.append(
                f"- `{c.get('fingerprint')}` — {c.get('control_state') or UNKNOWN} "
                f"effectiveness={c.get('effectiveness') or UNKNOWN}"
            )
        lines.append("")

    unknowns = snap.get("unknowns") or []
    if unknowns:
        lines.extend(["## Unknowns", ""])
        for u in unknowns:
            lines.append(f"- {u.get('topic') or UNKNOWN}: {u.get('detail') or UNKNOWN}")
        lines.append("")

    if not findings and not paths and not controls:
        lines.append("_No memory items in this snapshot._")
        lines.append("")

    return "\n".join(lines)


def render_memory_html_section(
    snapshot_or_state: dict[str, Any] | None = None,
    *,
    memory_dir: Path | str | None = None,
) -> str:
    """Compact HTML section suitable for embedding in a larger report."""
    md_source = snapshot_or_state
    if md_source is None and memory_dir is not None:
        md_source = get_current_state(memory_dir)
    snap = {}
    if isinstance(md_source, dict):
        if md_source.get("kind") == "security_memory_snapshot":
            snap = md_source
        else:
            snap = md_source.get("snapshot") or md_source
    summary = snap.get("summary") or {}

    def esc(v: Any) -> str:
        return html.escape(str(v if v is not None else UNKNOWN))

    rows = []
    for f in (snap.get("findings") or [])[:30]:
        rows.append(
            "<tr>"
            f"<td><code>{esc(f.get('fingerprint'))}</code></td>"
            f"<td>{esc(f.get('lifecycle'))}</td>"
            f"<td>{esc(f.get('status'))}</td>"
            f"<td><code>{esc(f.get('file'))}</code></td>"
            "</tr>"
        )
    table = (
        "<table><thead><tr><th>Fingerprint</th><th>Lifecycle</th>"
        "<th>Status</th><th>File</th></tr></thead><tbody>"
        + ("".join(rows) or "<tr><td colspan='4'>No findings</td></tr>")
        + "</tbody></table>"
    )
    return (
        '<section class="axguard-security-memory">'
        "<h2>Security Memory</h2>"
        f"<p>Snapshot <code>{esc(snap.get('snapshot_id'))}</code> · "
        f"revision <code>{esc(snap.get('source_revision'))}</code> · "
        f"findings {esc(summary.get('finding_count', len(snap.get('findings') or [])))} · "
        f"paths {esc(summary.get('path_count', len(snap.get('attack_paths') or [])))}</p>"
        f"{table}"
        "</section>"
    )


def write_memory_report(
    snapshot_or_state: dict[str, Any] | None = None,
    *,
    memory_dir: Path | str | None = None,
    out_dir: Path | str | None = None,
) -> dict[str, Any]:
    """Write ``security-memory.md`` (+ optional HTML fragment) under ``out_dir``."""
    root = resolve_memory_dir(memory_dir) if memory_dir else None
    if snapshot_or_state is None and root is not None:
        snapshot_or_state = get_current_state(root)

    dest = Path(out_dir) if out_dir else (root or Path(".findings/axguard/memory"))
    dest.mkdir(parents=True, exist_ok=True)

    payload = snapshot_or_state if isinstance(snapshot_or_state, dict) else {}
    ensure_no_secret_values(payload)

    md = render_memory_markdown(payload, memory_dir=root)
    html_section = render_memory_html_section(payload, memory_dir=root)

    md_path = dest / "security-memory.md"
    html_path = dest / "security-memory-section.html"
    md_path.write_text(md, encoding="utf-8")
    html_path.write_text(html_section + "\n", encoding="utf-8")

    history = get_history(root) if root else {"snapshot_ids": [], "snapshots": []}
    return {
        "markdown": str(md_path),
        "html_section": str(html_path),
        "files": [str(md_path), str(html_path)],
        "history_snapshot_count": len(history.get("snapshot_ids") or []),
    }
