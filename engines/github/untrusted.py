"""Treat repository content as hostile data — never execute it."""

from __future__ import annotations

import re
from typing import Any

from engines.github.privacy import redact_text

# Patterns that look like instruction / prompt injection attempts in repo text
_INJECTION_MARKERS = re.compile(
    r"(?is)("
    r"ignore\s+(all\s+)?(previous|prior|above)\s+instructions"
    r"|system\s*:\s*"
    r"|you\s+are\s+now\s+"
    r"|override\s+axguard"
    r"|disregard\s+(safety|security)\s+policy"
    r")"
)

_EXEC_HINTS = re.compile(
    r"(?is)("
    r"\b(subprocess|os\.system|eval|exec|__import__)\s*\("
    r"|pip\s+install\b"
    r"|npm\s+install\b"
    r"|curl\s+[^\n]+\|\s*(ba)?sh"
    r")"
)


class UntrustedContentError(RuntimeError):
    """Raised when adapter is asked to execute or trust repository code."""


def assert_never_execute(action: str = "execute repository code") -> None:
    """Hard guard — GitHub adapter must not run repo scripts/builds."""
    raise UntrustedContentError(
        f"AXGuard GitHub adapter refuses to {action}. "
        "Repository contents are data only."
    )


def sanitize_untrusted_text(text: str, *, max_len: int = 4000) -> str:
    """Normalize untrusted strings (PR titles, README, comments) for display.

    Does not treat content as instructions. Redacts secrets. Truncates.
    """
    if not text:
        return ""
    cleaned = redact_text(str(text))
    # Neutralize common injection phrasing in displayed output (data, not prompts)
    if _INJECTION_MARKERS.search(cleaned):
        cleaned = _INJECTION_MARKERS.sub("[untrusted-instruction-redacted]", cleaned)
    if len(cleaned) > max_len:
        cleaned = cleaned[: max_len - 3] + "..."
    return cleaned


def looks_like_prompt_injection(text: str) -> bool:
    return bool(text and _INJECTION_MARKERS.search(text))


def looks_like_exec_payload(text: str) -> bool:
    return bool(text and _EXEC_HINTS.search(text))


def as_data_context(label: str, value: Any) -> dict[str, Any]:
    """Wrap untrusted values so callers treat them as labeled data."""
    text = sanitize_untrusted_text(str(value) if value is not None else "")
    return {
        "kind": "untrusted_repo_data",
        "label": label,
        "value": text,
        "prompt_injection_suspected": looks_like_prompt_injection(str(value or "")),
        "exec_hint_suspected": looks_like_exec_payload(str(value or "")),
    }
