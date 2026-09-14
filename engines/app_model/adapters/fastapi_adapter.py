"""FastAPI route discovery adapter."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from engines.app_model.adapters.base import FrameworkAdapter
from engines.app_model.discover import read_text, rel_path
from engines.app_model.schema import CONFIDENCE_CONFIRMED, CONFIDENCE_LIKELY, evidence

_HTTP_METHODS = ("get", "post", "put", "patch", "delete", "options", "head", "trace")
_ROUTE = re.compile(
    rf"""@(?:app|router|api_router|api)\.({'|'.join(_HTTP_METHODS)})\(\s*['\"]([^'\"]+)['\"]""",
    re.I,
)
_API_ROUTER = re.compile(r"APIRouter\s*\(", re.I)
_DEF_HANDLER = re.compile(r"^\s*(?:async\s+)?def\s+([A-Za-z_][\w]*)\s*\(", re.M)


class FastAPIAdapter(FrameworkAdapter):
    name = "fastapi"

    def detect(self, path: Path, stack: dict[str, Any]) -> bool:
        names = {str(x.get("name", "")).lower() for x in stack.get("frameworks", [])}
        return "fastapi" in names or "fastapi" in stack.get("framework_names", [])

    def discover(self, path: Path, files: list[Path]) -> dict[str, Any]:
        entrypoints: list[dict[str, Any]] = []
        found = False
        for fpath in files:
            if fpath.suffix.lower() != ".py":
                continue
            content = read_text(fpath)
            if not content:
                continue
            if re.search(r"\bfastapi\b|APIRouter", content, re.I):
                found = True
            rel = rel_path(fpath, path)
            for m in _ROUTE.finditer(content):
                method = m.group(1).upper()
                route_path = m.group(2)
                line = content.count("\n", 0, m.start()) + 1
                handler = _next_def(content, m.end())
                entrypoints.append(
                    {
                        "kind": "http",
                        "method": method,
                        "path": route_path,
                        "file": file_rel(rel),
                        "line": line,
                        "handler": handler,
                        "framework": "fastapi",
                        "authentication": {"status": "unknown"},
                        "authorization": {"status": "unknown"},
                        "inputs": _path_params(route_path),
                        "outputs": [],
                        "confidence": CONFIDENCE_CONFIRMED,
                        "evidence": evidence(
                            rel,
                            line,
                            symbol=handler,
                            reason="FastAPI route decorator",
                        ),
                    }
                )
            if _API_ROUTER.search(content) and not entrypoints:
                # router present but routes may be elsewhere — framework signal only
                pass
        partial: dict[str, Any] = {"entrypoints": entrypoints}
        if entrypoints or found:
            partial["frameworks"] = [
                {
                    "name": "fastapi",
                    "confidence": CONFIDENCE_CONFIRMED if entrypoints else CONFIDENCE_LIKELY,
                    "evidence": evidence(
                        entrypoints[0]["file"] if entrypoints else None,
                        entrypoints[0]["line"] if entrypoints else None,
                        reason="FastAPI adapter detection",
                    ),
                }
            ]
        return partial


def file_rel(rel: str) -> str:
    return rel


def _next_def(content: str, start: int) -> str | None:
    m = _DEF_HANDLER.search(content, start)
    if not m:
        return None
    if content[start : m.start()].count("\n") > 8:
        return None
    return m.group(1)


def _path_params(path: str) -> list[dict[str, Any]]:
    params = []
    for m in re.finditer(r"\{([A-Za-z_][\w]*)(?::[^}]+)?\}", path):
        params.append(
            {
                "name": m.group(1),
                "source": "path",
                "confidence": CONFIDENCE_LIKELY,
            }
        )
    return params
