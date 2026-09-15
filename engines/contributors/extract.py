"""Extract technical patterns without identity."""

from __future__ import annotations

import re
from typing import Any

from engines.contributors.sanitize import sanitize_text

_LANG_HINTS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"\.(py)$", re.I), "python"),
    (re.compile(r"\.(ts|tsx)$", re.I), "typescript"),
    (re.compile(r"\.(js|jsx|mjs|cjs)$", re.I), "javascript"),
    (re.compile(r"\.(go)$", re.I), "go"),
    (re.compile(r"\.(rs)$", re.I), "rust"),
    (re.compile(r"\.(java)$", re.I), "java"),
    (re.compile(r"\.(rb)$", re.I), "ruby"),
    (re.compile(r"\.(php)$", re.I), "php"),
]

_FRAMEWORK_HINTS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"\b(django|flask|fastapi|starlette)\b", re.I), "python-web"),
    (re.compile(r"\b(express|next\.?js|nestjs|react)\b", re.I), "node-web"),
    (re.compile(r"\b(rails|sinatra)\b", re.I), "ruby-web"),
    (re.compile(r"\b(spring|ktor)\b", re.I), "jvm-web"),
    (re.compile(r"\b(mcp|model.?context.?protocol)\b", re.I), "mcp"),
    (re.compile(r"\b(langchain|llamaindex|openai|anthropic)\b", re.I), "ai-agent"),
]

_PATTERN_HINTS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"\bssrf\b", re.I), "ssrf"),
    (re.compile(r"\bxss\b", re.I), "xss"),
    (re.compile(r"\bsqli?\b|\bsql.?injection\b", re.I), "sqli"),
    (re.compile(r"\bpath.?traversal\b|\blfi\b", re.I), "path-traversal"),
    (re.compile(r"\bidor\b|\bbroken.?access\b", re.I), "authz-idor"),
    (re.compile(r"\bfalse.?positive\b", re.I), "false-positive"),
    (re.compile(r"\bprompt.?injection\b", re.I), "prompt-injection"),
    (re.compile(r"\bcommand.?injection\b|\brce\b", re.I), "command-injection"),
]

_CONTROL_HINTS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"\bmissing\s+(authz|authorization|authn|authentication)\b", re.I), "auth"),
    (re.compile(r"\bno\s+allowlist\b|\bmissing\s+allowlist\b", re.I), "allowlist"),
    (re.compile(r"\bunescaped\b|\bmissing\s+encoding\b", re.I), "output-encoding"),
    (re.compile(r"\bmissing\s+csrf\b", re.I), "csrf"),
    (re.compile(r"\bmissing\s+rate.?limit\b", re.I), "rate-limit"),
]


def _detect_language(file_path: str | None, blob: str) -> str | None:
    if file_path:
        for pat, lang in _LANG_HINTS:
            if pat.search(file_path):
                return lang
    lowered = blob.lower()
    if "def " in lowered and "import " in lowered:
        return "python"
    if "function " in lowered or "const " in lowered:
        return "javascript"
    return None


def _first_match(patterns: list[tuple[re.Pattern[str], str]], text: str) -> str | None:
    for pat, label in patterns:
        if pat.search(text):
            return label
    return None


def extract_pattern(context: dict[str, Any] | None = None) -> dict[str, Any]:
    """Extract language / framework / pattern / flow / missing control — no identity."""
    ctx = dict(context or {})
    file_path = str(ctx.get("file") or ctx.get("path") or "")
    pieces = [
        str(ctx.get("title") or ""),
        str(ctx.get("rule_id") or ""),
        str(ctx.get("cwe") or ""),
        str(ctx.get("finding_class") or ""),
        str(ctx.get("message") or ""),
        str(ctx.get("description") or ""),
        str(ctx.get("snippet") or ctx.get("code") or ""),
        str(ctx.get("flow_summary") or ""),
        " ".join(str(x) for x in (ctx.get("tags") or [])),
    ]
    blob = "\n".join(p for p in pieces if p)

    language = ctx.get("language") or _detect_language(file_path, blob)
    framework = ctx.get("framework") or _first_match(_FRAMEWORK_HINTS, blob)
    pattern = ctx.get("pattern") or _first_match(_PATTERN_HINTS, blob)
    missing_control = ctx.get("missing_control") or _first_match(_CONTROL_HINTS, blob)

    flow = ctx.get("flow_summary")
    if not flow and ctx.get("source") and ctx.get("sink"):
        flow = f"{ctx.get('source')} → {ctx.get('sink')}"
    if isinstance(flow, str):
        flow, _ = sanitize_text(flow)

    snippet = ctx.get("snippet") or ctx.get("code")
    sanitized_snippet = None
    if isinstance(snippet, str) and snippet.strip():
        sanitized_snippet, _ = sanitize_text(snippet)

    result = {
        "language": language,
        "framework": framework,
        "pattern": pattern,
        "flow_summary": flow,
        "missing_control": missing_control,
        "sanitized_snippet": sanitized_snippet,
        "rule_id": ctx.get("rule_id"),
        "cwe": ctx.get("cwe"),
    }
    # Drop empties for a clean technical fingerprint
    return {k: v for k, v in result.items() if v not in (None, "", [])}
