"""Attack-graph diffing (Phase 6 Part 2).

Compare two attack-graph result artifacts and describe what changed between
them — new/removed attack paths, controls that got weaker or stronger, new or
removed entry points, and per-path status changes.

**Primary API is dict-vs-dict.** ``compare_attack_graphs(a, b)`` and
``get_attack_path_diff(a, b)`` accept either:

- an in-memory result dict (the output of ``run_attack_graph``), or
- a path (``str`` / ``pathlib.Path``) to an ``attack-paths.json`` file.

There is no git dependency here. The CLI can pass two JSON paths; a caller that
wants a git-based comparison simply runs the attack graph on two checkouts and
hands the two result dicts (or their saved JSON) to this module. Keeping the
core comparison pure (dict-vs-dict) makes it trivial to test and reuse.

Nothing in this module claims a change *is* a vulnerability — it reports
structural deltas. Interpreting a delta as "increasing risk" is the job of
:mod:`engines.attack_graph.predictive`.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from engines.attack_graph.schema import PATH_TIER_RANK

# ---------------------------------------------------------------------------
# change-type vocabulary
# ---------------------------------------------------------------------------
CHANGE_NEW_ATTACK_PATH = "NEW_ATTACK_PATH"
CHANGE_REMOVED_ATTACK_PATH = "REMOVED_ATTACK_PATH"
CHANGE_WEAKENED_CONTROL = "WEAKENED_CONTROL"
CHANGE_STRENGTHENED_CONTROL = "STRENGTHENED_CONTROL"
CHANGE_NEW_ENTRY_POINT = "NEW_ENTRY_POINT"
CHANGE_REMOVED_ENTRY_POINT = "REMOVED_ENTRY_POINT"
CHANGE_PATH_STATUS_CHANGE = "PATH_STATUS_CHANGE"

CHANGE_TYPES = frozenset(
    {
        CHANGE_NEW_ATTACK_PATH,
        CHANGE_REMOVED_ATTACK_PATH,
        CHANGE_WEAKENED_CONTROL,
        CHANGE_STRENGTHENED_CONTROL,
        CHANGE_NEW_ENTRY_POINT,
        CHANGE_REMOVED_ENTRY_POINT,
        CHANGE_PATH_STATUS_CHANGE,
    }
)


# ---------------------------------------------------------------------------
# loading / normalisation
# ---------------------------------------------------------------------------
def _load(obj: Any) -> dict[str, Any]:
    """Accept a result dict or a path to an attack-paths.json file."""
    if isinstance(obj, dict):
        return obj
    if isinstance(obj, (str, Path)):
        text = Path(obj).read_text(encoding="utf-8")
        data = json.loads(text)
        if not isinstance(data, dict):
            raise ValueError(f"{obj}: expected an attack-graph JSON object")
        return data
    raise TypeError(
        "expected an attack-graph result dict or a path to attack-paths.json, "
        f"got {type(obj).__name__}"
    )


def _path_signature(path: dict[str, Any]) -> tuple[str, ...]:
    """Stable identity for a path across runs.

    Node ids are deterministic (derived from type + file + line/symbol), so the
    ordered tuple of hop ids is a stable signature independent of the volatile
    ``path-000N`` sequence number.
    """
    return tuple(str(h) for h in (path.get("hops") or []))


def _paths_by_signature(result: dict[str, Any]) -> dict[tuple[str, ...], dict[str, Any]]:
    return {_path_signature(p): p for p in (result.get("paths") or [])}


def _entrypoint_ids(result: dict[str, Any]) -> set[str]:
    return {
        str(n.get("id"))
        for n in (result.get("graph") or {}).get("nodes") or []
        if n.get("type") == "entrypoint"
    }


def _label_map(result: dict[str, Any]) -> dict[str, str]:
    return {
        str(n.get("id")): str(n.get("label") or n.get("id"))
        for n in (result.get("graph") or {}).get("nodes") or []
    }


def _effective_rank(controls: list[dict[str, Any]]) -> int:
    """Highest control-effectiveness present on a path (higher == stronger)."""
    order = {"ineffective": 0, "unknown": 1, "likely": 2, "confirmed": 3}
    best = 0
    for c in controls or []:
        best = max(best, order.get(str(c.get("effectiveness")), 0))
    return best


def _change(change_type: str, **fields: Any) -> dict[str, Any]:
    rec = {"change": change_type}
    rec.update(fields)
    return rec


# ---------------------------------------------------------------------------
# public API
# ---------------------------------------------------------------------------
def get_attack_path_diff(a: Any, b: Any) -> list[dict[str, Any]]:
    """Return an ordered list of change records between graph ``a`` (before) and
    ``b`` (after). See the ``CHANGE_*`` constants for change types.
    """
    ga = _load(a)
    gb = _load(b)

    a_paths = _paths_by_signature(ga)
    b_paths = _paths_by_signature(gb)
    a_labels = _label_map(ga)
    b_labels = _label_map(gb)

    changes: list[dict[str, Any]] = []

    # --- new / removed attack paths -------------------------------------
    for sig, p in b_paths.items():
        if sig not in a_paths:
            changes.append(
                _change(
                    CHANGE_NEW_ATTACK_PATH,
                    signature=list(sig),
                    status=p.get("status"),
                    tags=p.get("tags") or [],
                    entry=p.get("entry"),
                    target=p.get("target"),
                    hop_labels=[b_labels.get(h, h) for h in sig],
                    detail="attack path present in B but not in A",
                )
            )
    for sig, p in a_paths.items():
        if sig not in b_paths:
            changes.append(
                _change(
                    CHANGE_REMOVED_ATTACK_PATH,
                    signature=list(sig),
                    status=p.get("status"),
                    tags=p.get("tags") or [],
                    entry=p.get("entry"),
                    target=p.get("target"),
                    hop_labels=[a_labels.get(h, h) for h in sig],
                    detail="attack path present in A but not in B",
                )
            )

    # --- persistent paths: control / status deltas ----------------------
    for sig in sorted(set(a_paths) & set(b_paths)):
        pa = a_paths[sig]
        pb = b_paths[sig]
        rank_a = _effective_rank(pa.get("controls_encountered") or [])
        rank_b = _effective_rank(pb.get("controls_encountered") or [])
        status_a = str(pa.get("status"))
        status_b = str(pb.get("status"))

        # control effectiveness / block-state change on the same path
        blocked_a = status_a == "BLOCKED"
        blocked_b = status_b == "BLOCKED"
        if (blocked_a and not blocked_b) or rank_b < rank_a:
            changes.append(
                _change(
                    CHANGE_WEAKENED_CONTROL,
                    signature=list(sig),
                    status_before=status_a,
                    status_after=status_b,
                    control_rank_before=rank_a,
                    control_rank_after=rank_b,
                    hop_labels=[b_labels.get(h, a_labels.get(h, h)) for h in sig],
                    detail="a control on this path became weaker or stopped blocking",
                )
            )
        elif (blocked_b and not blocked_a) or rank_b > rank_a:
            changes.append(
                _change(
                    CHANGE_STRENGTHENED_CONTROL,
                    signature=list(sig),
                    status_before=status_a,
                    status_after=status_b,
                    control_rank_before=rank_a,
                    control_rank_after=rank_b,
                    hop_labels=[b_labels.get(h, a_labels.get(h, h)) for h in sig],
                    detail="a control on this path became stronger or started blocking",
                )
            )

        # generic status-tier change (only report when not already captured as a
        # block-state control change to avoid duplicate noise)
        if status_a != status_b and not (blocked_a != blocked_b):
            direction = (
                "regressed"
                if PATH_TIER_RANK.get(status_b, 0) > PATH_TIER_RANK.get(status_a, 0)
                else "improved"
            )
            changes.append(
                _change(
                    CHANGE_PATH_STATUS_CHANGE,
                    signature=list(sig),
                    status_before=status_a,
                    status_after=status_b,
                    direction=direction,
                    hop_labels=[b_labels.get(h, a_labels.get(h, h)) for h in sig],
                    detail=f"path status changed {status_a} → {status_b}",
                )
            )

    # --- entry-point surface deltas -------------------------------------
    a_entries = _entrypoint_ids(ga)
    b_entries = _entrypoint_ids(gb)
    for eid in sorted(b_entries - a_entries):
        changes.append(
            _change(
                CHANGE_NEW_ENTRY_POINT,
                node=eid,
                label=b_labels.get(eid, eid),
                detail="entry point present in B but not in A",
            )
        )
    for eid in sorted(a_entries - b_entries):
        changes.append(
            _change(
                CHANGE_REMOVED_ENTRY_POINT,
                node=eid,
                label=a_labels.get(eid, eid),
                detail="entry point present in A but not in B",
            )
        )

    return changes


def compare_attack_graphs(a: Any, b: Any) -> dict[str, Any]:
    """Full comparison object: change list + a counts summary.

    ``a`` is treated as *before* (baseline) and ``b`` as *after*.
    """
    ga = _load(a)
    gb = _load(b)
    changes = get_attack_path_diff(ga, gb)

    counts = {ct: 0 for ct in sorted(CHANGE_TYPES)}
    for c in changes:
        ct = c.get("change")
        if ct in counts:
            counts[ct] += 1

    return {
        "kind": "attack_graph_diff",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "before": {
            "target": ga.get("target"),
            "path_count": len((ga.get("paths") or [])),
            "generated_at": ga.get("generated_at"),
        },
        "after": {
            "target": gb.get("target"),
            "path_count": len((gb.get("paths") or [])),
            "generated_at": gb.get("generated_at"),
        },
        "summary": {
            "change_count": len(changes),
            "by_change": counts,
        },
        "changes": changes,
    }


def render_diff_markdown(diff: dict[str, Any]) -> str:
    """Human-readable rendering of a ``compare_attack_graphs`` result."""
    summary = diff.get("summary") or {}
    by_change = summary.get("by_change") or {}
    lines = [
        "# AXguard attack-path diff (diagnostic)",
        "",
        "Structural delta between two attack-graph runs. A delta is **not** a "
        "vulnerability claim — see predictive analysis for risk interpretation.",
        "",
        f"- **Before:** `{(diff.get('before') or {}).get('target', '')}` "
        f"({(diff.get('before') or {}).get('path_count', 0)} paths)",
        f"- **After:** `{(diff.get('after') or {}).get('target', '')}` "
        f"({(diff.get('after') or {}).get('path_count', 0)} paths)",
        f"- **Total changes:** {summary.get('change_count', 0)}",
        "",
        "| Change | Count |",
        "| --- | ---: |",
    ]
    for ct in sorted(by_change):
        lines.append(f"| {ct} | {by_change[ct]} |")
    lines.append("")
    changes = diff.get("changes") or []
    if changes:
        lines.extend(["## Changes", ""])
        for c in changes:
            hops = c.get("hop_labels") or []
            arrow = " → ".join(str(h) for h in hops)
            extra = c.get("label") or arrow or c.get("detail") or ""
            lines.append(f"- **{c.get('change')}** — {extra}")
    else:
        lines.append("_No changes detected._")
    lines.append("")
    return "\n".join(lines)
