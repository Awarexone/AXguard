"""Project-local Security Memory persistence (atomic writes).

Layout under ``.findings/axguard/memory/`` (never ``~/.axguard``):

- ``index.json``
- ``ledger.json`` (fingerprint → latest state + relationships)
- ``snapshots/{snapshot_id}.json`` (compact: embedded item summaries)
- ``diffs/{before_id}__{after_id}.json``
"""

from __future__ import annotations

import json
import re
from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from engines.dataflow.schema import ensure_no_secret_values
from engines.memory.schema import empty_ledger, empty_memory_index

DEFAULT_MEMORY_DIR = Path(".findings/axguard/memory")

_SAFE_ID = re.compile(r"[^A-Za-z0-9._-]+")


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def resolve_memory_dir(
    memory_dir: Path | str | None = None,
    *,
    state_path: Path | str | None = None,
) -> Path:
    """Resolve memory root. ``state_path`` may point at index.json or the dir."""
    if memory_dir is not None:
        return Path(memory_dir)
    if state_path is not None:
        p = Path(state_path)
        if p.suffix == ".json":
            return p.parent
        return p
    return Path(DEFAULT_MEMORY_DIR)


def _atomic_write_json(path: Path, payload: dict[str, Any]) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    data = deepcopy(payload)
    ensure_no_secret_values(data)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    tmp.replace(path)
    return path


def _read_json(path: Path) -> dict[str, Any] | None:
    path = Path(path)
    if not path.is_file():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return data if isinstance(data, dict) else None


def _safe_snapshot_filename(snapshot_id: str) -> str:
    cleaned = _SAFE_ID.sub("_", str(snapshot_id or "UNKNOWN")).strip("._") or "UNKNOWN"
    return f"{cleaned}.json"


def load_index(
    memory_dir: Path | str | None = None,
    *,
    state_path: Path | str | None = None,
) -> dict[str, Any]:
    root = resolve_memory_dir(memory_dir, state_path=state_path)
    data = _read_json(root / "index.json")
    return deepcopy(data) if data else empty_memory_index()


def save_index(
    index: dict[str, Any],
    memory_dir: Path | str | None = None,
    *,
    state_path: Path | str | None = None,
) -> Path:
    root = resolve_memory_dir(memory_dir, state_path=state_path)
    payload = deepcopy(index)
    payload["updated_at"] = _utc_now_iso()
    return _atomic_write_json(root / "index.json", payload)


def load_ledger(
    memory_dir: Path | str | None = None,
    *,
    state_path: Path | str | None = None,
) -> dict[str, Any]:
    root = resolve_memory_dir(memory_dir, state_path=state_path)
    data = _read_json(root / "ledger.json")
    return deepcopy(data) if data else empty_ledger()


def save_ledger(
    ledger: dict[str, Any],
    memory_dir: Path | str | None = None,
    *,
    state_path: Path | str | None = None,
) -> Path:
    root = resolve_memory_dir(memory_dir, state_path=state_path)
    payload = deepcopy(ledger)
    payload["updated_at"] = _utc_now_iso()
    return _atomic_write_json(root / "ledger.json", payload)


def write_snapshot(
    snapshot: dict[str, Any],
    memory_dir: Path | str | None = None,
    *,
    state_path: Path | str | None = None,
    update_index: bool = True,
) -> Path:
    root = resolve_memory_dir(memory_dir, state_path=state_path)
    snap = deepcopy(snapshot)
    sid = str(snap.get("snapshot_id") or "UNKNOWN")
    path = root / "snapshots" / _safe_snapshot_filename(sid)
    _atomic_write_json(path, snap)

    if update_index:
        index = load_index(root)
        ids = list(index.get("snapshot_ids") or [])
        if sid not in ids:
            ids.append(sid)
        index["snapshot_ids"] = ids
        index["latest_snapshot_id"] = sid
        index["source_revision"] = snap.get("source_revision") or index.get("source_revision")
        summary = dict(index.get("summary") or {})
        summary["snapshot_count"] = len(ids)
        summary["finding_count"] = len(snap.get("findings") or [])
        summary["control_count"] = len(snap.get("controls") or [])
        summary["path_count"] = len(snap.get("attack_paths") or [])
        summary["unknown_count"] = len(snap.get("unknowns") or [])
        index["summary"] = summary
        save_index(index, root)
    return path


def load_snapshot(
    snapshot_id: str,
    memory_dir: Path | str | None = None,
    *,
    state_path: Path | str | None = None,
) -> dict[str, Any] | None:
    root = resolve_memory_dir(memory_dir, state_path=state_path)
    data = _read_json(root / "snapshots" / _safe_snapshot_filename(snapshot_id))
    return deepcopy(data) if data else None


def list_snapshots(
    memory_dir: Path | str | None = None,
    *,
    state_path: Path | str | None = None,
) -> list[str]:
    root = resolve_memory_dir(memory_dir, state_path=state_path)
    index = load_index(root)
    ids = list(index.get("snapshot_ids") or [])
    if ids:
        return ids
    snap_dir = root / "snapshots"
    if not snap_dir.is_dir():
        return []
    found = sorted(p.stem for p in snap_dir.glob("*.json"))
    return found


def write_diff(
    diff: dict[str, Any],
    before_id: str,
    after_id: str,
    memory_dir: Path | str | None = None,
    *,
    state_path: Path | str | None = None,
) -> Path:
    root = resolve_memory_dir(memory_dir, state_path=state_path)
    a = _SAFE_ID.sub("_", str(before_id))
    b = _SAFE_ID.sub("_", str(after_id))
    path = root / "diffs" / f"{a}__{b}.json"
    return _atomic_write_json(path, deepcopy(diff))


def load_diff(
    before_id: str,
    after_id: str,
    memory_dir: Path | str | None = None,
    *,
    state_path: Path | str | None = None,
) -> dict[str, Any] | None:
    root = resolve_memory_dir(memory_dir, state_path=state_path)
    a = _SAFE_ID.sub("_", str(before_id))
    b = _SAFE_ID.sub("_", str(after_id))
    data = _read_json(root / "diffs" / f"{a}__{b}.json")
    return deepcopy(data) if data else None
