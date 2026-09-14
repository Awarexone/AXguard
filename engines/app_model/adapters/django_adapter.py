"""Lightweight Django URL discovery adapter."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from engines.app_model.adapters.base import FrameworkAdapter
from engines.app_model.discover import read_text, rel_path
from engines.app_model.schema import CONFIDENCE_CONFIRMED, CONFIDENCE_LIKELY, evidence

_PATH = re.compile(
    r"""(?:path|re_path)\(\s*[rf]?['\"]([^'\"]+)['\"]\s*,\s*([A-Za-z_][\w\.]*)""",
    re.I,
)


class DjangoAdapter(FrameworkAdapter):
    name = "django"

    def detect(self, path: Path, stack: dict[str, Any]) -> bool:
        names = {str(x.get("name", "")).lower() for x in stack.get("frameworks", [])}
        return "django" in names or "django" in stack.get("framework_names", [])

    def discover(self, path: Path, files: list[Path]) -> dict[str, Any]:
        entrypoints: list[dict[str, Any]] = []
        found = False
        for fpath in files:
            if fpath.suffix.lower() != ".py":
                continue
            content = read_text(fpath)
            if not content:
                continue
            if re.search(r"\bdjango\b", content):
                found = True
            # Prefer urls.py but accept any path()/re_path()
            rel = rel_path(fpath, path)
            for m in _PATH.finditer(content):
                route_path = m.group(1)
                handler = m.group(2)
                line = content.count("\n", 0, m.start()) + 1
                # Django paths often omit leading slash
                if not route_path.startswith("^") and not route_path.startswith("/"):
                    display = "/" + route_path
                else:
                    display = route_path
                entrypoints.append(
                    {
                        "kind": "http",
                        "method": "ANY",
                        "path": display,
                        "file": rel,
                        "line": line,
                        "handler": handler,
                        "framework": "django",
                        "authentication": {"status": "unknown"},
                        "authorization": {"status": "unknown"},
                        "inputs": _django_params(route_path),
                        "outputs": [],
                        "confidence": CONFIDENCE_CONFIRMED,
                        "evidence": evidence(
                            rel, line, symbol=handler, reason="Django path()/re_path()"
                        ),
                    }
                )
        partial: dict[str, Any] = {"entrypoints": entrypoints}
        if entrypoints or found:
            partial["frameworks"] = [
                {
                    "name": "django",
                    "confidence": CONFIDENCE_CONFIRMED if entrypoints else CONFIDENCE_LIKELY,
                    "evidence": evidence(
                        entrypoints[0]["file"] if entrypoints else None,
                        entrypoints[0]["line"] if entrypoints else None,
                        reason="Django adapter detection",
                    ),
                }
            ]
        return partial


def _django_params(path: str) -> list[dict[str, Any]]:
    params = []
    for m in re.finditer(r"<\w+:(\w+)>|<(\w+)>", path):
        name = m.group(1) or m.group(2)
        params.append({"name": name, "source": "path", "confidence": CONFIDENCE_LIKELY})
    return params
