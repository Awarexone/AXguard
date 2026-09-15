"""HTTP / entrypoint extraction via framework adapters + generic heuristics."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from engines.app_model.adapters import default_adapters
from engines.app_model.discover import read_text, rel_path
from engines.app_model.schema import (
    CONFIDENCE_LIKELY,
    CONFIDENCE_UNKNOWN,
    evidence,
)

_GENERIC_API = re.compile(
    r"""['\"](/api/[A-Za-z0-9_\-/{}.:]+)['\"]""",
)
_AUTH_NEAR = re.compile(
    r"(?i)\b(login_required|require[_-]?auth|requires_auth|require_admin|"
    r"@auth\b|authorize|jwt_required|IsAuthenticated|permission_classes|"
    r"ensure_auth|verifyToken|authenticate|requireAuth)\b"
)


def discover_entrypoints(
    root: Path,
    files: list[Path],
    stack: dict[str, Any],
) -> dict[str, Any]:
    """Run adapters (always attempt soft discover) and optional generic /api/ paths."""
    entrypoints: list[dict[str, Any]] = []
    frameworks: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str, int]] = set()

    for adapter in default_adapters():
        # Always call discover when detect matches OR when soft signals exist.
        # Soft: run all adapters; each returns empty when nothing found.
        should = adapter.detect(root, stack)
        partial = adapter.discover(root, files)
        if not should and not partial.get("entrypoints") and not partial.get("frameworks"):
            continue
        for ep in partial.get("entrypoints") or []:
            key = (
                str(ep.get("method", "")),
                str(ep.get("path", "")),
                str(ep.get("file", "")),
                int(ep.get("line") or 0),
            )
            if key in seen:
                continue
            seen.add(key)
            entrypoints.append(ep)
        for fw in partial.get("frameworks") or []:
            frameworks.append(fw)

    # Generic weak /api/ strings near handlers when coverage is thin
    known_paths = {str(e.get("path")) for e in entrypoints}
    for fpath in files:
        if fpath.suffix.lower() not in {
            ".py",
            ".js",
            ".jsx",
            ".ts",
            ".tsx",
            ".mjs",
            ".cjs",
            ".go",
            ".rb",
            ".php",
            ".java",
        }:
            continue
        content = read_text(fpath)
        if not content:
            continue
        rel = rel_path(fpath, root)
        for m in _GENERIC_API.finditer(content):
            path = m.group(1)
            if path in known_paths:
                continue
            line = content.count("\n", 0, m.start()) + 1
            # skip if this looks like a client fetch URL only and we already have rich routes
            if len(entrypoints) >= 8:
                continue
            entrypoints.append(
                {
                    "kind": "http",
                    "method": "UNKNOWN",
                    "path": path,
                    "file": rel,
                    "line": line,
                    "handler": None,
                    "framework": "unknown",
                    "authentication": {"status": "unknown"},
                    "authorization": {"status": "unknown"},
                    "inputs": [],
                    "outputs": [],
                    "confidence": CONFIDENCE_UNKNOWN
                    if len(entrypoints) > 3
                    else CONFIDENCE_LIKELY,
                    "evidence": evidence(
                        rel,
                        line,
                        reason="Generic /api/ string path near source (weak heuristic)",
                    ),
                }
            )
            known_paths.add(path)

    entrypoints = [_annotate_auth_hints(ep, files, root) for ep in entrypoints]
    return {"entrypoints": entrypoints, "frameworks": frameworks}


def _annotate_auth_hints(
    ep: dict[str, Any],
    files: list[Path],
    root: Path,
) -> dict[str, Any]:
    """Conservative auth annotation: only the decorator stack for this handler."""
    file_rel = ep.get("file")
    if not file_rel:
        return ep
    matches = [p for p in files if rel_path(p, root) == file_rel]
    if not matches:
        return ep
    content = read_text(matches[0])
    line = int(ep.get("line") or 1)
    lines = content.splitlines()
    idx = max(0, line - 1)

    # Include contiguous decorators above this route line.
    start = idx
    for i in range(idx - 1, max(-1, idx - 8), -1):
        stripped = lines[i].strip()
        if not stripped:
            continue
        if stripped.startswith("@"):
            start = i
            continue
        break

    # Downward only until the handler def (do not spill into the next route).
    end = idx
    for i in range(idx, min(len(lines), idx + 12)):
        end = i
        if re.match(r"^\s*(?:async\s+)?def\s+", lines[i]):
            break
        # Another route decorator after a blank means we left this stack
        if i > idx and re.search(r"@(?:app|bp|router|api)\.(?:route|get|post|put|patch|delete)\b", lines[i], re.I):
            end = i - 1
            break

    window = "\n".join(lines[start : end + 1])
    if _AUTH_NEAR.search(window):
        ep = dict(ep)
        ep["authentication"] = {
            "status": "required",
            "confidence": CONFIDENCE_LIKELY,
            "evidence": evidence(
                file_rel,
                line,
                reason="Auth decorator/middleware in this route's decorator stack",
            ),
        }
    return ep
