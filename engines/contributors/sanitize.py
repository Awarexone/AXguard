"""Sanitize contribution payloads — reuse data scrubbers, never fork them.

Wraps ``engines.data.scrub`` + ``ensure_no_secret_values``.
Also minimizes PII and private repo identity.
"""

from __future__ import annotations

import re
from copy import deepcopy
from pathlib import Path
from typing import Any

from engines.data.scrub import scrub_example, scrub_text
from engines.dataflow.schema import ensure_no_secret_values

# Private absolute paths → generic placeholders
_ABS_PATH = re.compile(
    r"(?P<pre>^|[\s\"'=:])"
    r"(?P<path>(?:/Users/|/home/|/private/var/|/var/folders/)[^\s\"']+)"
)
_WIN_ABS = re.compile(
    r"(?P<pre>^|[\s\"'=:])"
    r"(?P<path>[A-Za-z]:\\(?:Users|home)\\[^\s\"']+)",
    re.IGNORECASE,
)
_EMAIL = re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")
_PRIVATE_REPO_HINTS = re.compile(
    r"(?i)\b(github\.com|gitlab\.com|bitbucket\.org)/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)"
)


def minimize_absolute_paths(text: str) -> str:
    """Replace private absolute paths with a neutral placeholder."""

    def _sub(m: re.Match[str]) -> str:
        return f"{m.group('pre')}[REDACTED_PATH]"

    out = _ABS_PATH.sub(_sub, text)
    out = _WIN_ABS.sub(_sub, out)
    return out


def minimize_repo_identity(text: str, *, known_private_names: list[str] | None = None) -> str:
    """Normalize private repo / org names when they appear in free text."""
    out = text
    for name in known_private_names or []:
        if name and len(name) >= 2:
            out = re.sub(re.escape(name), "[REDACTED_REPO]", out, flags=re.IGNORECASE)

    def _repo_sub(m: re.Match[str]) -> str:
        host, org, repo = m.group(1), m.group(2), m.group(3)
        # Keep public Awarexone/AXguard identity; minimize others
        if org.lower() == "awarexone" and repo.lower() == "axguard":
            return m.group(0)
        return f"{host}/[REDACTED_ORG]/[REDACTED_REPO]"

    return _PRIVATE_REPO_HINTS.sub(_repo_sub, out)


def minimize_pii(text: str) -> str:
    out, _ = scrub_text(text)
    out = _EMAIL.sub("[REDACTED_EMAIL]", out)
    out = minimize_absolute_paths(out)
    return out


def sanitize_text(
    text: str,
    *,
    known_private_names: list[str] | None = None,
) -> tuple[str, list[str]]:
    """Scrub secrets/PII and minimize private identity. Returns (text, hits)."""
    cleaned, hits = scrub_text(text)
    cleaned = minimize_absolute_paths(cleaned)
    cleaned = minimize_repo_identity(cleaned, known_private_names=known_private_names)
    cleaned = _EMAIL.sub("[REDACTED_EMAIL]", cleaned)
    return cleaned, hits


def sanitize_example(
    example: dict[str, Any],
    *,
    known_private_names: list[str] | None = None,
) -> tuple[dict[str, Any], list[str]]:
    """Sanitize a contribution example dict via shared scrubbers + identity minimization."""
    cleaned, hits = scrub_example(deepcopy(example))
    ensure_no_secret_values(cleaned)
    for key, value in list(cleaned.items()):
        if isinstance(value, str):
            cleaned[key], extra = sanitize_text(
                value, known_private_names=known_private_names
            )
            hits.extend(extra)
        elif isinstance(value, dict):
            nested, extra = sanitize_example(value, known_private_names=known_private_names)
            cleaned[key] = nested
            hits.extend(extra)
    # Never keep identity keys
    for drop in ("author", "author_email", "github_login", "user", "email", "machine_id"):
        cleaned.pop(drop, None)
    if "repo" in cleaned and isinstance(cleaned["repo"], str):
        cleaned["repo"], _ = sanitize_text(
            cleaned["repo"], known_private_names=known_private_names
        )
    if "path" in cleaned and isinstance(cleaned["path"], str):
        cleaned["path"] = _relativize_path(cleaned["path"])
    if "file" in cleaned and isinstance(cleaned["file"], str):
        cleaned["file"] = _relativize_path(cleaned["file"])
    ensure_no_secret_values(cleaned)
    return cleaned, hits


def _relativize_path(path_str: str) -> str:
    """Prefer basename / relative form over private absolute paths."""
    text = minimize_absolute_paths(path_str)
    if text == "[REDACTED_PATH]" or "[REDACTED_PATH]" in text:
        # Keep filename if we can recover it from original
        try:
            name = Path(path_str).name
            if name and name not in (".", ".."):
                return f"[REDACTED_DIR]/{name}"
        except (TypeError, ValueError):
            pass
        return "[REDACTED_PATH]"
    p = Path(path_str)
    if p.is_absolute():
        return f"[REDACTED_DIR]/{p.name}" if p.name else "[REDACTED_PATH]"
    return path_str.replace("\\", "/")
