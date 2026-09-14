"""Flask route discovery adapter."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from engines.app_model.adapters.base import FrameworkAdapter
from engines.app_model.discover import read_text, rel_path
from engines.app_model.schema import CONFIDENCE_CONFIRMED, CONFIDENCE_LIKELY, evidence

_ROUTE_DECO = re.compile(
    r"""@(?:app|bp|blueprint|api|router)\.route\(\s*['\"]([^'\"]+)['\"]([^)]*)\)""",
    re.I,
)
_ADD_URL = re.compile(
    r"""(?:app|bp|blueprint)\.add_url_rule\(\s*['\"]([^'\"]+)['\"]([^)]*)\)""",
    re.I,
)
_DEF_HANDLER = re.compile(r"^\s*def\s+([A-Za-z_][\w]*)\s*\(", re.M)
_METHODS = re.compile(r"methods\s*=\s*\[([^\]]+)\]", re.I)


class FlaskAdapter(FrameworkAdapter):
    name = "flask"

    def detect(self, path: Path, stack: dict[str, Any]) -> bool:
        names = {str(x.get("name", "")).lower() for x in stack.get("frameworks", [])}
        if "flask" in names or "flask" in stack.get("framework_names", []):
            return True
        # soft detect via imports later in discover
        return False

    def discover(self, path: Path, files: list[Path]) -> dict[str, Any]:
        entrypoints: list[dict[str, Any]] = []
        found_import = False
        for fpath in files:
            if fpath.suffix.lower() != ".py":
                continue
            content = read_text(fpath)
            if not content:
                continue
            if re.search(r"\bflask\b", content, re.I):
                found_import = True
            rel = rel_path(fpath, path)
            for pattern in (_ROUTE_DECO, _ADD_URL):
                for m in pattern.finditer(content):
                    route_path = m.group(1)
                    opts = m.group(2) or ""
                    methods = _extract_methods(opts) or ["GET"]
                    line = content.count("\n", 0, m.start()) + 1
                    handler = _next_def(content, m.end())
                    for method in methods:
                        entrypoints.append(
                            _entrypoint(
                                method=method,
                                path=route_path,
                                file=rel,
                                line=line,
                                handler=handler,
                                framework="flask",
                                confidence=CONFIDENCE_CONFIRMED,
                                reason="Flask route decorator or add_url_rule",
                            )
                        )
        partial: dict[str, Any] = {"entrypoints": entrypoints}
        if entrypoints or found_import:
            partial["frameworks"] = [
                {
                    "name": "flask",
                    "confidence": CONFIDENCE_CONFIRMED if entrypoints else CONFIDENCE_LIKELY,
                    "evidence": evidence(
                        entrypoints[0]["file"] if entrypoints else None,
                        entrypoints[0]["line"] if entrypoints else None,
                        reason="Flask adapter detection",
                    ),
                }
            ]
        return partial


def _extract_methods(opts: str) -> list[str]:
    m = _METHODS.search(opts)
    if not m:
        return []
    return [x.strip(" \"'") for x in m.group(1).split(",") if x.strip(" \"'")]


def _next_def(content: str, start: int) -> str | None:
    m = _DEF_HANDLER.search(content, start)
    if not m:
        return None
    # only accept if within a few lines
    between = content[start : m.start()]
    if between.count("\n") > 6:
        return None
    return m.group(1)


def _entrypoint(
    *,
    method: str,
    path: str,
    file: str,
    line: int,
    handler: str | None,
    framework: str,
    confidence: str,
    reason: str,
) -> dict[str, Any]:
    inputs = _path_params(path)
    return {
        "kind": "http",
        "method": method.upper(),
        "path": path,
        "file": file,
        "line": line,
        "handler": handler,
        "framework": framework,
        "authentication": {"status": "unknown"},
        "authorization": {"status": "unknown"},
        "inputs": inputs,
        "outputs": [],
        "confidence": confidence,
        "evidence": evidence(file, line, symbol=handler, reason=reason),
    }


def _path_params(path: str) -> list[dict[str, Any]]:
    params = []
    for m in re.finditer(r"<[^>]+>|:([A-Za-z_][\w]*)|\{([A-Za-z_][\w]*)\}", path):
        raw = m.group(0)
        name = raw.strip("<>{}").split(":")[-1]
        if m.group(1):
            name = m.group(1)
        if m.group(2):
            name = m.group(2)
        params.append(
            {
                "name": name,
                "source": "path",
                "confidence": CONFIDENCE_LIKELY,
            }
        )
    return params
