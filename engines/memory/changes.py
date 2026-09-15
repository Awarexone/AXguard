"""Compare Security Memory revisions / snapshots."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from engines.memory.regress import detect_regressions
from engines.memory.schema import UNKNOWN
from engines.memory.store import load_snapshot, resolve_memory_dir, write_diff


def compare_snapshots(a: dict[str, Any], b: dict[str, Any]) -> dict[str, Any]:
    """Structural + lifecycle comparison of two in-memory snapshots."""
    regressions = detect_regressions(a or {}, b or {})
    return {
        "kind": "security_memory_diff",
        "before": {
            "snapshot_id": (a or {}).get("snapshot_id"),
            "source_revision": (a or {}).get("source_revision") or UNKNOWN,
            "summary": (a or {}).get("summary") or {},
        },
        "after": {
            "snapshot_id": (b or {}).get("snapshot_id"),
            "source_revision": (b or {}).get("source_revision") or UNKNOWN,
            "summary": (b or {}).get("summary") or {},
        },
        "outcomes": {
            "NEW": regressions.get("NEW") or [],
            "CHANGED": regressions.get("CHANGED") or [],
            "REGRESSED": regressions.get("REGRESSED") or [],
            "RESOLVED": regressions.get("RESOLVED") or [],
            "UNCHANGED": regressions.get("UNCHANGED") or [],
        },
        "summary": regressions.get("summary") or {},
        "attack_graph_diff": regressions.get("attack_graph_diff"),
        "predictive": regressions.get("predictive"),
    }


def compare_revisions(
    memory_dir: Path | str | None,
    before_id: str,
    after_id: str,
    *,
    state_path: Path | str | None = None,
    persist: bool = True,
) -> dict[str, Any]:
    """Load two stored snapshots by id and compare them."""
    root = resolve_memory_dir(memory_dir, state_path=state_path)
    before = load_snapshot(before_id, root)
    after = load_snapshot(after_id, root)
    if before is None or after is None:
        return {
            "kind": "security_memory_diff",
            "error": "snapshot_not_found",
            "before_id": before_id,
            "after_id": after_id,
            "before_found": before is not None,
            "after_found": after is not None,
            "outcomes": {
                "NEW": [],
                "CHANGED": [],
                "REGRESSED": [],
                "RESOLVED": [],
                "UNCHANGED": [],
            },
            "summary": {
                "new": 0,
                "changed": 0,
                "regressed": 0,
                "resolved": 0,
                "unchanged": 0,
            },
        }
    diff = compare_snapshots(before, after)
    if persist:
        write_diff(diff, before_id, after_id, root)
    return diff
