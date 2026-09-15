"""Detect taint sources with trust levels (deterministic heuristics)."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from engines.app_model.discover import read_text, rel_path
from engines.dataflow.schema import (
    CONFIDENCE_CONFIRMED,
    CONFIDENCE_LIKELY,
    TRUST_SEMI,
    TRUST_UNTRUSTED,
    evidence,
)

# (kind, trust_level, confidence, pattern, suffixes or None)
_SOURCE_PATTERNS: list[tuple[str, str, str, re.Pattern[str], set[str] | None]] = [
    # Flask / Werkzeug request inputs
    (
        "request_args",
        TRUST_UNTRUSTED,
        CONFIDENCE_CONFIRMED,
        re.compile(
            r"\brequest\.(args|values|form|json|get_json|data|get_data|files)\b"
            r"|\brequest\.args\.get\s*\("
            r"|\brequest\.form\.get\s*\("
            r"|\brequest\.values\.get\s*\("
        ),
        {".py"},
    ),
    (
        "request_headers",
        TRUST_UNTRUSTED,
        CONFIDENCE_CONFIRMED,
        re.compile(r"\brequest\.headers\b|\brequest\.environ\b"),
        {".py"},
    ),
    (
        "request_cookies",
        TRUST_UNTRUSTED,
        CONFIDENCE_CONFIRMED,
        re.compile(r"\brequest\.cookies\b"),
        {".py"},
    ),
    # FastAPI / Starlette
    (
        "request_param",
        TRUST_UNTRUSTED,
        CONFIDENCE_CONFIRMED,
        re.compile(
            r"\b(Query|Path|Header|Cookie|Form|Body|File|UploadFile)\s*\("
            r"|\brequest\.(query_params|path_params|headers|cookies|body|json)\b"
        ),
        {".py"},
    ),
    # Express / Node
    (
        "request_param",
        TRUST_UNTRUSTED,
        CONFIDENCE_CONFIRMED,
        re.compile(
            r"\breq\.(query|params|body|headers|cookies|files)\b"
            r"|\breq\.get\s*\("
        ),
        {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"},
    ),
    # Env — often semi-trusted (operator-controlled, not remote user)
    (
        "env",
        TRUST_SEMI,
        CONFIDENCE_LIKELY,
        re.compile(
            r"\bos\.environ(?:\.get)?\s*[\[(]"
            r"|\bos\.getenv\s*\("
            r"|\bprocess\.env\."
        ),
        {".py", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"},
    ),
    # Webhook / raw body
    (
        "webhook",
        TRUST_UNTRUSTED,
        CONFIDENCE_LIKELY,
        re.compile(
            r"(?i)(webhook|callback).{0,40}(request\.(get_data|data|json|get_json)|req\.body)"
            r"|request\.get_data\s*\("
        ),
        {".py", ".js", ".jsx", ".ts", ".tsx"},
    ),
    # AI model outputs (treat as untrusted unless proven otherwise)
    (
        "ai_output",
        TRUST_UNTRUSTED,
        CONFIDENCE_LIKELY,
        re.compile(
            r"(?i)(chat\.completions|messages\[-?1\]|response\.content|"
            r"choices\[0\]\.message\.content|completion\.text|"
            r"llm_output|model_output|assistant_message)"
        ),
        None,
    ),
]

# Assignment that binds a name to a request source (Python + JS)
_ASSIGN_SOURCE = re.compile(
    r"(?P<var>[A-Za-z_][\w]*)\s*=\s*"
    r"(?P<rhs>"
    r"request\.(?:args|values|form|json|cookies|headers|data|get_json|get_data)"
    r"(?:\.[A-Za-z_][\w]*)?"
    r"(?:\s*\([^)]*\))?"
    r"|request\.args\.get\s*\([^)]*\)"
    r"|request\.form\.get\s*\([^)]*\)"
    r"|request\.values\.get\s*\([^)]*\)"
    r"|req\.(?:query|params|body|headers|cookies)(?:\.[A-Za-z_][\w]*|\[[^\]]+\])?"
    r"|os\.(?:environ(?:\.get)?|getenv)\s*[\[(][^)\]]*[)\]]"
    r"|process\.env\.[A-Za-z_][\w]*"
    r")"
)

# Path / function params that mirror FastAPI style: def foo(url: str = Query(...))
_FASTAPI_PARAM = re.compile(
    r"def\s+\w+\s*\([^)]*\b(?P<var>[A-Za-z_][\w]*)\s*[:=][^,)]*"
    r"(?:Query|Path|Header|Cookie|Form|Body)\s*\(",
    re.S,
)


def discover_sources(root: Path, files: list[Path]) -> list[dict[str, Any]]:
    """Inventory taint sources with trust_level; prefer unknown over inventing safety."""
    sources: list[dict[str, Any]] = []
    seen: set[tuple[str, int, str]] = set()

    for fpath in files:
        suffix = fpath.suffix.lower()
        content = read_text(fpath)
        if not content:
            continue
        rel = rel_path(fpath, root)
        lines = content.splitlines()

        for kind, trust, conf, pattern, suffixes in _SOURCE_PATTERNS:
            if suffixes is not None and suffix not in suffixes:
                continue
            for m in pattern.finditer(content):
                line_no = content.count("\n", 0, m.start()) + 1
                if _is_comment_only(lines, line_no - 1):
                    continue
                key = (rel, line_no, kind)
                if key in seen:
                    continue
                seen.add(key)
                bound = _bound_name_near(lines, line_no)
                sources.append(
                    {
                        "id": f"src.{kind}.{rel}:{line_no}",
                        "kind": kind,
                        "name": bound or kind,
                        "trust_level": trust,
                        "file": rel,
                        "line": line_no,
                        "confidence": conf,
                        "endpoint": None,
                        "evidence": evidence(
                            rel,
                            line_no,
                            symbol=bound or kind,
                            reason=f"Source kind={kind} trust={trust}",
                            snippet=lines[line_no - 1] if 0 < line_no <= len(lines) else None,
                        ),
                    }
                )

        # Explicit assignments → named sources (better for propagation)
        for m in _ASSIGN_SOURCE.finditer(content):
            line_no = content.count("\n", 0, m.start()) + 1
            if _is_comment_only(lines, line_no - 1):
                continue
            var = m.group("var")
            kind = _kind_from_rhs(m.group("rhs"))
            trust = TRUST_SEMI if kind == "env" else TRUST_UNTRUSTED
            key = (rel, line_no, f"assign:{var}")
            if key in seen:
                continue
            seen.add(key)
            sources.append(
                {
                    "id": f"src.assign.{var}.{rel}:{line_no}",
                    "kind": kind,
                    "name": var,
                    "trust_level": trust,
                    "file": rel,
                    "line": line_no,
                    "confidence": CONFIDENCE_CONFIRMED,
                    "endpoint": None,
                    "evidence": evidence(
                        rel,
                        line_no,
                        symbol=var,
                        reason=f"Assignment binds {var} from {kind}",
                        snippet=lines[line_no - 1] if 0 < line_no <= len(lines) else None,
                    ),
                }
            )

        if suffix == ".py":
            for m in _FASTAPI_PARAM.finditer(content):
                line_no = content.count("\n", 0, m.start()) + 1
                var = m.group("var")
                key = (rel, line_no, f"fastapi:{var}")
                if key in seen:
                    continue
                seen.add(key)
                sources.append(
                    {
                        "id": f"src.fastapi.{var}.{rel}:{line_no}",
                        "kind": "request_param",
                        "name": var,
                        "trust_level": TRUST_UNTRUSTED,
                        "file": rel,
                        "line": line_no,
                        "confidence": CONFIDENCE_CONFIRMED,
                        "endpoint": None,
                        "evidence": evidence(
                            rel,
                            line_no,
                            symbol=var,
                            reason="FastAPI dependency-injected request parameter",
                            snippet=lines[line_no - 1] if 0 < line_no <= len(lines) else None,
                        ),
                    }
                )

    sources.sort(key=lambda s: (s["file"], s["line"], s["id"]))
    return sources


def link_sources_to_endpoints(
    sources: list[dict[str, Any]], entrypoints: list[dict[str, Any]]
) -> None:
    """Attach nearest same-file entrypoint when co-located."""
    by_file: dict[str, list[dict[str, Any]]] = {}
    for ep in entrypoints:
        f = ep.get("file")
        if f:
            by_file.setdefault(str(f), []).append(ep)

    for src in sources:
        eps = by_file.get(str(src.get("file") or ""), [])
        if not eps:
            continue
        line = int(src.get("line") or 0)
        best = min(eps, key=lambda e: abs(int(e.get("line") or 0) - line))
        src["endpoint"] = {
            "method": best.get("method"),
            "path": best.get("path"),
            "file": best.get("file"),
            "line": best.get("line"),
            "handler": best.get("handler"),
        }


def _kind_from_rhs(rhs: str) -> str:
    r = rhs.lower()
    if "cookie" in r:
        return "request_cookies"
    if "header" in r:
        return "request_headers"
    if "environ" in r or "getenv" in r or "process.env" in r:
        return "env"
    if "get_data" in r or "webhook" in r:
        return "webhook"
    if any(x in r for x in ("args", "form", "values", "json", "query", "params", "body")):
        return "request_args"
    return "request_param"


def _bound_name_near(lines: list[str], line_no: int) -> str | None:
    """If the match line looks like ``name = <source>``, return name."""
    if 0 < line_no <= len(lines):
        m = re.match(r"\s*([A-Za-z_][\w]*)\s*=", lines[line_no - 1])
        if m:
            return m.group(1)
    return None


def _is_comment_only(lines: list[str], idx: int) -> bool:
    if idx < 0 or idx >= len(lines):
        return False
    stripped = lines[idx].lstrip()
    return stripped.startswith("#") or stripped.startswith("//") or stripped.startswith("*")
