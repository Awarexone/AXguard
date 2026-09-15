"""Sensitive sink inventory for dataflow (extends app_model sinks)."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from engines.app_model.discover import read_text, rel_path
from engines.dataflow.schema import (
    APP_MODEL_SINK_MAP,
    CONFIDENCE_CONFIRMED,
    CONFIDENCE_LIKELY,
    SINK_AI_TOOL,
    SINK_CMD,
    SINK_DESER,
    SINK_EVAL,
    SINK_FS,
    SINK_HTML,
    SINK_NET,
    SINK_REDIRECT,
    SINK_SQL,
    SINK_TEMPLATE,
    evidence,
)

# Local patterns beyond / overlapping app_model (taxonomized for taint)
_SINK_PATTERNS: list[tuple[str, str, re.Pattern[str], set[str] | None, str]] = [
    (
        SINK_SQL,
        "execute_fstring",
        re.compile(
            r"\.(?:execute|executemany|raw)\s*\(\s*f['\"]"
            r"|(?:execute|executemany|raw)\s*\(\s*f['\"]",
            re.I,
        ),
        {".py"},
        CONFIDENCE_CONFIRMED,
    ),
    (
        SINK_SQL,
        "execute_format",
        re.compile(
            r"\.(?:execute|executemany)\s*\(\s*(?:['\"][^'\"]*%[sdf]|['\"].*\.format\(|['\"].*\+)",
            re.I,
        ),
        {".py"},
        CONFIDENCE_CONFIRMED,
    ),
    (
        SINK_SQL,
        "execute_concat_js",
        re.compile(
            r"\.(?:query|execute|raw)\s*\(\s*[`'\"][^`'\"]*(?:\$\{|\+)",
            re.I,
        ),
        {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"},
        CONFIDENCE_CONFIRMED,
    ),
    (
        SINK_SQL,
        "execute_call",
        re.compile(r"\.(?:execute|executemany)\s*\(", re.I),
        {".py"},
        CONFIDENCE_LIKELY,
    ),
    (
        SINK_NET,
        "requests_call",
        re.compile(
            r"\brequests\.(?:get|post|put|patch|delete|head|request)\s*\("
        ),
        {".py"},
        CONFIDENCE_CONFIRMED,
    ),
    (
        SINK_NET,
        "httpx_call",
        re.compile(r"\bhttpx\.(?:get|post|put|patch|delete|request|stream)\s*\("),
        {".py"},
        CONFIDENCE_CONFIRMED,
    ),
    (
        SINK_NET,
        "urllib_urlopen",
        re.compile(r"\burllib\.request\.urlopen\s*\("),
        {".py"},
        CONFIDENCE_CONFIRMED,
    ),
    (
        SINK_NET,
        "fetch_call",
        re.compile(r"\bfetch\s*\("),
        {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"},
        CONFIDENCE_CONFIRMED,
    ),
    (
        SINK_NET,
        "axios_call",
        re.compile(r"\baxios\.(?:get|post|put|patch|delete|request)\s*\("),
        {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"},
        CONFIDENCE_CONFIRMED,
    ),
    (
        SINK_CMD,
        "subprocess_shell",
        re.compile(r"subprocess\.(?:run|Popen|call|check_output)\s*\([^\n]*shell\s*=\s*True"),
        {".py"},
        CONFIDENCE_CONFIRMED,
    ),
    (
        SINK_CMD,
        "os_system",
        re.compile(r"\bos\.system\s*\("),
        {".py"},
        CONFIDENCE_CONFIRMED,
    ),
    (
        SINK_CMD,
        "child_process",
        re.compile(r"child_process\.(?:exec|execSync|spawn)\s*\("),
        {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"},
        CONFIDENCE_CONFIRMED,
    ),
    (
        SINK_EVAL,
        "eval",
        re.compile(r"\beval\s*\("),
        {".py", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"},
        CONFIDENCE_CONFIRMED,
    ),
    (
        SINK_EVAL,
        "exec",
        re.compile(r"\bexec\s*\("),
        {".py"},
        CONFIDENCE_CONFIRMED,
    ),
    (
        SINK_DESER,
        "pickle_loads",
        re.compile(r"\bpickle\.loads\s*\("),
        {".py"},
        CONFIDENCE_CONFIRMED,
    ),
    (
        SINK_DESER,
        "yaml_load",
        re.compile(r"\byaml\.load\s*\("),
        {".py"},
        CONFIDENCE_LIKELY,
    ),
    (
        SINK_FS,
        "open_call",
        re.compile(r"(?<![\w\.])open\s*\("),
        {".py"},
        CONFIDENCE_LIKELY,
    ),
    (
        SINK_FS,
        "fs_readwrite",
        re.compile(
            r"\bfs\.(?:readFile|readFileSync|writeFile|writeFileSync|createReadStream)\s*\("
        ),
        {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"},
        CONFIDENCE_CONFIRMED,
    ),
    (
        SINK_HTML,
        "innerHTML",
        re.compile(r"\.innerHTML\s*="),
        {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".html", ".htm"},
        CONFIDENCE_CONFIRMED,
    ),
    (
        SINK_HTML,
        "dangerouslySetInnerHTML",
        re.compile(r"dangerouslySetInnerHTML"),
        {".js", ".jsx", ".ts", ".tsx"},
        CONFIDENCE_CONFIRMED,
    ),
    (
        SINK_TEMPLATE,
        "render_template_string",
        re.compile(r"\brender_template_string\s*\("),
        {".py"},
        CONFIDENCE_CONFIRMED,
    ),
    (
        SINK_REDIRECT,
        "redirect",
        re.compile(
            r"\bredirect\s*\(|\bHttpResponseRedirect\s*\(|\bres\.redirect\s*\("
            r"|Location\s*[:=]"
        ),
        {".py", ".js", ".jsx", ".ts", ".tsx"},
        CONFIDENCE_LIKELY,
    ),
    (
        SINK_AI_TOOL,
        "tool_call",
        re.compile(
            r"(tool_calls|function_call|tools?\.invoke|mcp\.(?:call|invoke)|agent\.run)\s*\(",
            re.I,
        ),
        None,
        CONFIDENCE_LIKELY,
    ),
]


def discover_sinks(
    root: Path,
    files: list[Path],
    app_model_sinks: list[dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    """
    Build dataflow sink inventory.

    Consumes Phase 1 ``app_model`` sinks (mapped into taxonomy) and extends with
    local patterns. Dedupes by (file, line, type).
    """
    sinks: list[dict[str, Any]] = []
    seen: set[tuple[str, int, str]] = set()

    for s in app_model_sinks or []:
        mapped = APP_MODEL_SINK_MAP.get(str(s.get("type") or ""), str(s.get("type") or "unknown"))
        file = str(s.get("file") or "")
        line = int(s.get("line") or 0)
        key = (file, line, mapped)
        if key in seen:
            continue
        seen.add(key)
        sinks.append(
            {
                "id": f"sink.{mapped}.{s.get('symbol', 'sym')}.{file}:{line}",
                "type": mapped,
                "symbol": s.get("symbol"),
                "file": file,
                "line": line,
                "confidence": s.get("confidence", CONFIDENCE_LIKELY),
                "from_app_model": True,
                "evidence": s.get("evidence")
                or evidence(file, line, symbol=str(s.get("symbol")), reason="From application model"),
            }
        )

    for fpath in files:
        suffix = fpath.suffix.lower()
        content = read_text(fpath)
        if not content:
            continue
        rel = rel_path(fpath, root)
        lines = content.splitlines()
        for sink_type, symbol, pattern, suffixes, conf in _SINK_PATTERNS:
            if suffixes is not None and suffix not in suffixes:
                continue
            for m in pattern.finditer(content):
                line_no = content.count("\n", 0, m.start()) + 1
                if _is_comment_only(lines, line_no - 1):
                    continue
                key = (rel, line_no, sink_type)
                if key in seen:
                    continue
                seen.add(key)
                snippet = lines[line_no - 1] if 0 < line_no <= len(lines) else ""
                sinks.append(
                    {
                        "id": f"sink.{sink_type}.{symbol}.{rel}:{line_no}",
                        "type": sink_type,
                        "symbol": symbol,
                        "file": rel,
                        "line": line_no,
                        "confidence": conf,
                        "from_app_model": False,
                        "evidence": evidence(
                            rel,
                            line_no,
                            symbol=symbol,
                            reason=f"Sensitive {sink_type} sink",
                            snippet=snippet,
                        ),
                    }
                )

    sinks.sort(key=lambda s: (s["file"], s["line"], s["id"]))
    return sinks


def _is_comment_only(lines: list[str], idx: int) -> bool:
    if idx < 0 or idx >= len(lines):
        return False
    stripped = lines[idx].lstrip()
    return stripped.startswith("#") or stripped.startswith("//") or stripped.startswith("*")
