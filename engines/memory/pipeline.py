"""Security Memory pipeline entrypoints."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from engines.memory.changes import compare_revisions, compare_snapshots
from engines.memory.query import get_changes, get_regressions
from engines.memory.record import remember_from_attack_graph, remember_from_audit
from engines.memory.regress import detect_regressions
from engines.memory.report import write_memory_report
from engines.memory.store import list_snapshots, load_snapshot, resolve_memory_dir


def run_memory_record(
    target_or_audit_result: Path | str | dict[str, Any],
    *,
    memory_dir: Path | str | None = None,
    revision: str | None = None,
    write_report: bool = False,
) -> dict[str, Any]:
    """Record memory from an audit result dict, attack-graph dict, or target path.

    - ``dict`` with ``mode == "audit"`` or ``findings`` + phases → audit ingest
    - ``dict`` with ``paths`` / attack-graph shape → attack-graph ingest
    - ``Path`` / ``str`` → run attack graph then ingest
    """
    root = resolve_memory_dir(memory_dir)

    if isinstance(target_or_audit_result, dict):
        result = target_or_audit_result
        if result.get("mode") == "audit" or (
            "phases" in result and "findings" in result
        ):
            snap = remember_from_audit(result, memory_dir=root, revision=revision)
        elif "paths" in result or result.get("kind") == "attack_graph":
            snap = remember_from_attack_graph(result, memory_dir=root, revision=revision)
        elif result.get("attack_graph"):
            snap = remember_from_audit(result, memory_dir=root, revision=revision)
        else:
            # Prefer attack-graph shaped ingest when ambiguous
            snap = remember_from_attack_graph(result, memory_dir=root, revision=revision)
    else:
        from engines.attack_graph import run_attack_graph

        ag = run_attack_graph(Path(target_or_audit_result))
        snap = remember_from_attack_graph(ag, memory_dir=root, revision=revision)

    out: dict[str, Any] = {
        "snapshot": snap,
        "snapshot_id": snap.get("snapshot_id"),
        "summary": snap.get("summary"),
        "memory_dir": str(root),
    }
    if write_report:
        out["report"] = write_memory_report(snap, memory_dir=root, out_dir=root)
    return out


def run_memory_changes(
    memory_dir: Path | str | None = None,
    *,
    before_id: str | None = None,
    after_id: str | None = None,
) -> dict[str, Any]:
    """Compare two memory snapshots (defaults to latest pair)."""
    root = resolve_memory_dir(memory_dir)
    if before_id and after_id:
        return compare_revisions(root, before_id, after_id)
    return get_changes(root)


def run_memory_regressions(
    memory_dir: Path | str | None = None,
    *,
    before_id: str | None = None,
    after_id: str | None = None,
) -> dict[str, Any]:
    """Detect regressions between two snapshots (defaults to latest pair)."""
    root = resolve_memory_dir(memory_dir)
    if before_id and after_id:
        a = load_snapshot(before_id, root)
        b = load_snapshot(after_id, root)
        if a is None or b is None:
            return {
                "kind": "security_memory_regressions",
                "error": "snapshot_not_found",
                "REGRESSED": [],
                "summary": {"regressed": 0},
            }
        return detect_regressions(a, b)
    return get_regressions(root)


def run_memory_compare_snapshots(
    before: dict[str, Any],
    after: dict[str, Any],
) -> dict[str, Any]:
    return compare_snapshots(before, after)


def list_memory_snapshots(memory_dir: Path | str | None = None) -> list[str]:
    return list_snapshots(resolve_memory_dir(memory_dir))
