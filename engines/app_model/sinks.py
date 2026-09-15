"""Sensitive sink inventory (not vulnerability findings)."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from engines.app_model.discover import read_text, rel_path
from engines.app_model.schema import CONFIDENCE_CONFIRMED, CONFIDENCE_LIKELY, evidence

# Inventory patterns inspired by rules packs — stored as sinks, not findings.
_SINK_PATTERNS: list[tuple[str, str, re.Pattern[str], set[str] | None]] = [
    (
        "deserialize",
        "pickle.loads",
        re.compile(r"pickle\.loads\s*\("),
        {".py"},
    ),
    (
        "deserialize",
        "yaml.load",
        re.compile(r"yaml\.load\s*\("),
        {".py"},
    ),
    (
        "exec",
        "eval",
        re.compile(r"\beval\s*\("),
        {".py", ".js", ".jsx", ".ts", ".tsx"},
    ),
    (
        "exec",
        "exec",
        re.compile(r"\bexec\s*\("),
        {".py"},
    ),
    (
        "exec",
        "subprocess_shell",
        re.compile(r"subprocess\.(run|Popen|call|check_output)\([^\n]*shell\s*=\s*True"),
        {".py"},
    ),
    (
        "exec",
        "child_process_exec",
        re.compile(r"child_process\.(exec|execSync)\s*\("),
        {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"},
    ),
    (
        "exec",
        "os_system",
        re.compile(r"\bos\.system\s*\("),
        {".py"},
    ),
    (
        "sql",
        "execute_dynamic",
        re.compile(
            r"(?i)(execute|executemany|raw)\s*\(\s*(f['\"]|['\"].*%[sdf]|['\"].*\.format\(|['\"].*\+)"
        ),
        {".py"},
    ),
    (
        "sql",
        "query_concat",
        re.compile(
            r"(?i)(query|execute|sql)\s*\(\s*[`'\"][^`'\"]*\$\{|[`'\"][^`'\"]*\+"
        ),
        {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"},
    ),
    (
        "sql",
        "orm_raw",
        re.compile(r"(?i)\.(raw|from_sql|execute_sql|text\()\s*\("),
        None,
    ),
    (
        "http",
        "requests_var_url",
        re.compile(
            r"requests\.(get|post|put|patch|delete|head|request)\(\s*[a-zA-Z_][\w\.]*\s*[,)]"
        ),
        {".py"},
    ),
    (
        "http",
        "fetch_var",
        re.compile(r"fetch\(\s*[a-zA-Z_][\w\.]*\s*[,)]"),
        {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"},
    ),
    (
        "http",
        "axios_var",
        re.compile(r"axios\.(get|post|put|patch|delete)\(\s*[a-zA-Z_][\w\.]*\s*[,)]"),
        {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"},
    ),
    (
        "http",
        "urllib_urlopen",
        re.compile(r"urllib\.request\.urlopen\s*\("),
        {".py"},
    ),
    (
        "fs",
        "open_call",
        re.compile(r"(?<![\w\.])open\s*\("),
        {".py"},
    ),
    (
        "fs",
        "readFile",
        re.compile(r"fs\.(readFile|readFileSync|writeFile|writeFileSync|createReadStream)\s*\("),
        {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"},
    ),
    (
        "fs",
        "send_file",
        re.compile(r"(?i)send_file\s*\(|sendfile\s*\("),
        {".py", ".js", ".ts"},
    ),
    (
        "template",
        "render_template_string",
        re.compile(r"render_template_string\s*\("),
        {".py"},
    ),
    (
        "template",
        "jinja_from_string",
        re.compile(r"(?i)(from_string|Template)\s*\("),
        {".py"},
    ),
    (
        "template",
        "pug_compile",
        re.compile(r"(?i)(pug|jade)\.(compile|render)\s*\("),
        {".js", ".jsx", ".ts", ".tsx"},
    ),
    (
        "html",
        "innerHTML",
        re.compile(r"\.innerHTML\s*="),
        {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".html", ".htm", ".vue", ".svelte"},
    ),
    (
        "html",
        "dangerouslySetInnerHTML",
        re.compile(r"dangerouslySetInnerHTML"),
        {".js", ".jsx", ".ts", ".tsx"},
    ),
    (
        "html",
        "document_write",
        re.compile(r"document\.write\s*\("),
        {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"},
    ),
]


def discover_sinks(root: Path, files: list[Path]) -> list[dict[str, Any]]:
    sinks: list[dict[str, Any]] = []
    for fpath in files:
        suffix = fpath.suffix.lower()
        content = read_text(fpath)
        if not content:
            continue
        rel = rel_path(fpath, root)
        for sink_type, symbol, pattern, suffixes in _SINK_PATTERNS:
            if suffixes is not None and suffix not in suffixes:
                continue
            for m in pattern.finditer(content):
                line = content.count("\n", 0, m.start()) + 1
                # Skip obvious comments
                line_text = content[content.rfind("\n", 0, m.start()) + 1 : m.start()].lstrip()
                if line_text.startswith("#") or line_text.startswith("//"):
                    continue
                confidence = CONFIDENCE_CONFIRMED
                if sink_type in {"fs", "template"} and symbol in {"open_call", "jinja_from_string"}:
                    confidence = CONFIDENCE_LIKELY
                sinks.append(
                    {
                        "id": f"sink.{sink_type}.{symbol}",
                        "type": sink_type,
                        "symbol": symbol,
                        "file": rel,
                        "line": line,
                        "confidence": confidence,
                        "evidence": evidence(
                            rel,
                            line,
                            symbol=symbol,
                            reason=f"Sensitive {sink_type} sink inventory match",
                        ),
                    }
                )
    sinks.sort(key=lambda s: (s["file"], s["line"], s["id"]))
    return sinks
