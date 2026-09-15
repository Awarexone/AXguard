"""Secret / PII scrubber for dataset examples."""

from __future__ import annotations

import re
from typing import Any

from engines.dataflow.schema import ensure_no_secret_values

_SECRET_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"sk_live_[A-Za-z0-9]+"), "[REDACTED_STRIPE]"),
    (re.compile(r"sk-[A-Za-z0-9]{20,}"), "[REDACTED_OPENAI]"),
    (re.compile(r"AKIA[0-9A-Z]{16}"), "[REDACTED_AWS_KEY]"),
    (re.compile(r"ghp_[A-Za-z0-9]{20,}"), "[REDACTED_GITHUB]"),
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----"), "[REDACTED_PRIVATE_KEY]"),
    (re.compile(r"(?i)(password|passwd|secret|token|api[_-]?key)\s*[:=]\s*['\"]?([^\s'\"]+)"), r"\1=[REDACTED]"),
    (re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"), "[REDACTED_EMAIL]"),
]


def scrub_text(text: str) -> tuple[str, list[str]]:
    hits: list[str] = []
    out = text
    for pat, repl in _SECRET_PATTERNS:
        if pat.search(out):
            hits.append(pat.pattern[:40])
            out = pat.sub(repl, out)
    return out, hits


def scrub_example(example: dict[str, Any]) -> tuple[dict[str, Any], list[str]]:
    cleaned = dict(example)
    all_hits: list[str] = []
    for key in ("code", "prompt", "fix", "root_cause", "expected_behavior"):
        if key in cleaned and isinstance(cleaned[key], str):
            cleaned[key], hits = scrub_text(cleaned[key])
            all_hits.extend(hits)
    ensure_no_secret_values(cleaned)
    return cleaned, all_hits


def scrub_examples(
    examples: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    out: list[dict[str, Any]] = []
    report: list[dict[str, Any]] = []
    for ex in examples:
        cleaned, hits = scrub_example(ex)
        out.append(cleaned)
        if hits:
            report.append({"example_id": cleaned.get("example_id"), "hits": hits})
    return out, report
