"""Express / basic Next.js route discovery adapter."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from engines.app_model.adapters.base import FrameworkAdapter
from engines.app_model.discover import read_text, rel_path
from engines.app_model.schema import CONFIDENCE_CONFIRMED, CONFIDENCE_LIKELY, evidence

_HTTP_METHODS = ("get", "post", "put", "patch", "delete", "options", "head", "all", "use")
_ROUTE = re.compile(
    rf"""(?:app|router|r)\.({'|'.join(_HTTP_METHODS)})\(\s*['"`]([^'"`]+)['"`]""",
    re.I,
)
_HANDLER_NAME = re.compile(
    r"""(?:async\s+)?(?:function\s+([A-Za-z_][\w]*)|([A-Za-z_][\w]*)\s*=\s*(?:async\s*)?\()"""
)


class ExpressAdapter(FrameworkAdapter):
    name = "express"

    def detect(self, path: Path, stack: dict[str, Any]) -> bool:
        names = {str(x.get("name", "")).lower() for x in stack.get("frameworks", [])}
        fw = set(stack.get("framework_names", []))
        return bool({"express", "next"} & (names | fw))

    def discover(self, path: Path, files: list[Path]) -> dict[str, Any]:
        entrypoints: list[dict[str, Any]] = []
        frameworks: list[dict[str, Any]] = []
        saw_express = False
        saw_next = False

        for fpath in files:
            if fpath.suffix.lower() not in {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"}:
                continue
            content = read_text(fpath)
            if not content:
                continue
            rel = rel_path(fpath, path)
            if re.search(r"""['\"]express['\"]""", content):
                saw_express = True
            if re.search(r"""['\"]next(/|['\"])""", content) or "/app/" in rel.replace("\\", "/") or "/pages/" in rel.replace("\\", "/"):
                if "next" in rel.lower() or re.search(r"""from\s+['\"]next""", content):
                    saw_next = True

            for m in _ROUTE.finditer(content):
                method = m.group(1).upper()
                if method == "USE":
                    # middleware mount — still an entry surface if path-like
                    method = "USE"
                route_path = m.group(2)
                if not route_path.startswith("/") and not route_path.startswith("*"):
                    continue
                line = content.count("\n", 0, m.start()) + 1
                handler = _nearby_handler(content, m.end())
                entrypoints.append(
                    {
                        "kind": "http",
                        "method": "ALL" if method == "USE" else method,
                        "path": route_path,
                        "file": rel,
                        "line": line,
                        "handler": handler,
                        "framework": "express",
                        "authentication": {"status": "unknown"},
                        "authorization": {"status": "unknown"},
                        "inputs": _path_params(route_path),
                        "outputs": [],
                        "confidence": CONFIDENCE_CONFIRMED,
                        "evidence": evidence(
                            rel,
                            line,
                            symbol=handler,
                            reason="Express app/router method",
                        ),
                    }
                )

            # Next.js app router: page/route files imply GET (and route handlers)
            norm = rel.replace("\\", "/")
            base = fpath.name.lower()
            if "/app/" in f"/{norm}" and base in {"page.js", "page.jsx", "page.ts", "page.tsx"}:
                route_path = _next_app_path(norm)
                entrypoints.append(
                    {
                        "kind": "http",
                        "method": "GET",
                        "path": route_path,
                        "file": rel,
                        "line": 1,
                        "handler": "page",
                        "framework": "next",
                        "authentication": {"status": "unknown"},
                        "authorization": {"status": "unknown"},
                        "inputs": [],
                        "outputs": [],
                        "confidence": CONFIDENCE_LIKELY,
                        "evidence": evidence(rel, 1, reason="Next.js app router page file"),
                    }
                )
                saw_next = True
            if "/app/" in f"/{norm}" and base in {"route.js", "route.jsx", "route.ts", "route.tsx"}:
                route_path = _next_app_path(norm)
                for method in _export_methods(content):
                    entrypoints.append(
                        {
                            "kind": "http",
                            "method": method,
                            "path": route_path,
                            "file": rel,
                            "line": 1,
                            "handler": method.lower(),
                            "framework": "next",
                            "authentication": {"status": "unknown"},
                            "authorization": {"status": "unknown"},
                            "inputs": [],
                            "outputs": [],
                            "confidence": CONFIDENCE_CONFIRMED,
                            "evidence": evidence(
                                rel, 1, symbol=method, reason="Next.js route handler export"
                            ),
                        }
                    )
                saw_next = True

        if saw_express or any(e.get("framework") == "express" for e in entrypoints):
            frameworks.append(
                {
                    "name": "express",
                    "confidence": CONFIDENCE_CONFIRMED if entrypoints else CONFIDENCE_LIKELY,
                    "evidence": evidence(reason="Express adapter detection"),
                }
            )
        if saw_next:
            frameworks.append(
                {
                    "name": "next",
                    "confidence": CONFIDENCE_LIKELY,
                    "evidence": evidence(reason="Next.js adapter detection"),
                }
            )
        return {"entrypoints": entrypoints, "frameworks": frameworks}


def _nearby_handler(content: str, start: int) -> str | None:
    window = content[start : start + 200]
    m = _HANDLER_NAME.search(window)
    if not m:
        return None
    return m.group(1) or m.group(2)


def _path_params(path: str) -> list[dict[str, Any]]:
    params = []
    for m in re.finditer(r":([A-Za-z_][\w]*)|\{([A-Za-z_][\w]*)\}", path):
        name = m.group(1) or m.group(2)
        params.append({"name": name, "source": "path", "confidence": CONFIDENCE_LIKELY})
    return params


def _next_app_path(rel: str) -> str:
    # .../app/api/users/[id]/route.ts → /api/users/[id]
    norm = rel.replace("\\", "/")
    idx = norm.find("/app/")
    if idx == -1:
        return "/"
    rest = norm[idx + 5 :]
    parts = rest.split("/")
    # drop filename
    parts = parts[:-1]
    cleaned = []
    for p in parts:
        if p.startswith("(") and p.endswith(")"):
            continue
        cleaned.append(p)
    return "/" + "/".join(cleaned) if cleaned else "/"


def _export_methods(content: str) -> list[str]:
    methods = []
    for m in ("GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"):
        if re.search(rf"\bexport\s+(?:async\s+)?function\s+{m}\b|\bexport\s+const\s+{m}\b", content):
            methods.append(m)
    return methods or ["GET"]
