"""Shared hunter helpers for Phase 3 vulnerability hunters."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from engines.verify.hunter import (
    candidate_from_taint_path,
    weak_candidate_from_sink,
)
from engines.verify.schema import VULN_TO_SINK_TYPES


def paths_for_vuln(
    dataflow: dict[str, Any], vulnerability_type: str
) -> list[dict[str, Any]]:
    wanted = VULN_TO_SINK_TYPES.get(vulnerability_type, frozenset())
    out: list[dict[str, Any]] = []
    for path in dataflow.get("taint_paths") or []:
        st = str((path.get("sink") or {}).get("type") or "")
        if st in wanted:
            out.append(path)
    return out


def sinks_for_vuln(
    dataflow: dict[str, Any],
    application_model: dict[str, Any],
    vulnerability_type: str,
) -> list[dict[str, Any]]:
    wanted = VULN_TO_SINK_TYPES.get(vulnerability_type, frozenset())
    seen: set[tuple[str, int, str]] = set()
    out: list[dict[str, Any]] = []

    for sink in list(dataflow.get("sinks") or []) + list(
        application_model.get("sinks") or []
    ):
        st = str(sink.get("type") or "")
        # app_model uses http/exec; dataflow uses net/cmd/eval — already in wanted map
        if st not in wanted:
            continue
        key = (
            str(sink.get("file") or ""),
            int(sink.get("line") or 0),
            str(sink.get("symbol") or sink.get("id") or ""),
        )
        if key in seen:
            continue
        seen.add(key)
        out.append(sink)
    return out


def covered_sink_keys(paths: list[dict[str, Any]]) -> set[tuple[str, int]]:
    keys: set[tuple[str, int]] = set()
    for path in paths:
        sink = path.get("sink") or {}
        keys.add((str(sink.get("file") or ""), int(sink.get("line") or 0)))
    return keys


def covered_sink_files(paths: list[dict[str, Any]]) -> set[str]:
    """Files that already have a taint-path candidate for this vuln class."""
    return {
        str((path.get("sink") or {}).get("file") or "")
        for path in paths
        if (path.get("sink") or {}).get("file")
    }


def _looks_like_non_code_sink(sink: dict[str, Any]) -> bool:
    """Drop docstring/comment inventory noise (prefer UNVERIFIED avoidance)."""
    ev = sink.get("evidence") or {}
    snippet = ""
    if isinstance(ev, dict):
        snippet = str(ev.get("snippet") or "")
    else:
        snippet = str(ev)
    s = snippet.strip()
    if s.startswith(('"""', "'''", "#", "//", "/*")):
        return True
    if s.startswith('"') and "→" in s:
        return True
    return False


def hunt_paths_then_weak_sinks(
    *,
    vulnerability_type: str,
    title_for_path: str,
    title_for_sink: str,
    hunter_name: str,
    application_model: dict[str, Any],
    dataflow: dict[str, Any],
    target: Path | None = None,
) -> list[dict[str, Any]]:
    """
    Prefer Phase 2 taint paths; fall back to unmatched sinks as weak candidates.

    ``target`` reserved for future file-local regex; unused in core.
    """
    _ = target
    candidates: list[dict[str, Any]] = []
    paths = paths_for_vuln(dataflow, vulnerability_type)
    covered = covered_sink_keys(paths)
    covered_files = covered_sink_files(paths)

    for path in paths:
        candidates.append(
            candidate_from_taint_path(
                path,
                vulnerability_type=vulnerability_type,
                title=title_for_path,
                hunter=hunter_name,
            )
        )

    for sink in sinks_for_vuln(dataflow, application_model, vulnerability_type):
        key = (str(sink.get("file") or ""), int(sink.get("line") or 0))
        if key in covered:
            continue
        # If a taint path already covers this file for this class, skip weak
        # inventory duplicates (docstring/import false hits, etc.).
        if key[0] in covered_files:
            continue
        if not key[0] or key[1] < 1:
            continue
        if _looks_like_non_code_sink(sink):
            continue
        candidates.append(
            weak_candidate_from_sink(
                sink,
                vulnerability_type=vulnerability_type,
                title=title_for_sink,
                hunter=hunter_name,
            )
        )

    return candidates
