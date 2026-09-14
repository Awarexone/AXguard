"""Detect validation / sanitization / parameterization / authz along paths."""

from __future__ import annotations

import re
from typing import Any

from engines.dataflow.schema import (
    EFFECT_CONFIRMED,
    EFFECT_INEFFECTIVE,
    EFFECT_LIKELY,
    EFFECT_UNKNOWN,
    evidence,
)

# (control_kind, effectiveness, pattern)
_CONTROL_PATTERNS: list[tuple[str, str, re.Pattern[str]]] = [
    # Parameterized SQL — placeholders with separate args
    (
        "parameterization",
        EFFECT_CONFIRMED,
        re.compile(
            r"\.(?:execute|executemany)\s*\(\s*['\"][^'\"]*\?[^'\"]*['\"]\s*,"
            r"|\.(?:execute|executemany)\s*\(\s*['\"][^'\"]*%s[^'\"]*['\"]\s*,"
            r"|\.(?:execute|executemany)\s*\(\s*['\"][^'\"]*:\w+[^'\"]*['\"]\s*,",
            re.I,
        ),
    ),
    (
        "parameterization",
        EFFECT_LIKELY,
        re.compile(
            r"text\s*\(\s*['\"][^'\"]*:\w+"
            r"|\.filter\s*\([^)]*=="
            r"|cursor\.execute\s*\(\s*['\"][^f'\"].*\?\s*",
            re.I,
        ),
    ),
    # Host / URL allowlists (SSRF mitigations)
    (
        "allowlist",
        EFFECT_LIKELY,
        re.compile(
            r"(ALLOWED_HOSTS|ALLOWLIST|allowlist|allowed_hosts|SAFE_HOSTS|"
            r"urlparse\s*\(|hostname\s*(in|==|not\s+in)|"
            r"startswith\s*\(\s*['\"]https?://)",
            re.I,
        ),
    ),
    (
        "allowlist",
        EFFECT_CONFIRMED,
        re.compile(
            r"(if\s+.*hostname\s+not\s+in\s+\w+|if\s+.*host\s+not\s+in\s+"
            r"(ALLOWED|SAFE|allow))",
            re.I,
        ),
    ),
    # Encoding / escaping
    (
        "sanitization",
        EFFECT_LIKELY,
        re.compile(
            r"(html\.escape|markupsafe\.escape|bleach\.clean|DOMPurify|"
            r"escapeHtml|encodeURIComponent|cgi\.escape|sax\.utils\.escape)",
            re.I,
        ),
    ),
    # Validation
    (
        "validation",
        EFFECT_LIKELY,
        re.compile(
            r"(validators?\.\w+|pydantic|marshmallow|joi\.|zod\.|"
            r"isinstance\s*\(|re\.fullmatch|re\.match\s*\()",
            re.I,
        ),
    ),
    # AuthZ evidence
    (
        "authorization",
        EFFECT_LIKELY,
        re.compile(
            r"(@require_auth|@login_required|@permission_required|"
            r"check_permission|authorize\(|has_permission|Depends\s*\(\s*get_current)",
            re.I,
        ),
    ),
]

# Patterns that look like controls but are ineffective for the sink class
_INEFFECTIVE_FOR_SQL = re.compile(
    r"(replace\s*\(\s*['\"]['\"]|strip\s*\(|lower\s*\()",
    re.I,
)


def find_controls_in_region(
    content: str,
    *,
    file: str,
    start_line: int,
    end_line: int,
    sink_type: str | None = None,
) -> list[dict[str, Any]]:
    """Scan lines between source and sink for control evidence."""
    lines = content.splitlines()
    lo = max(1, min(start_line, end_line))
    hi = min(len(lines), max(start_line, end_line))
    region = "\n".join(lines[lo - 1 : hi])
    controls: list[dict[str, Any]] = []
    seen: set[tuple[str, int]] = set()

    for kind, effectiveness, pattern in _CONTROL_PATTERNS:
        for m in pattern.finditer(region):
            abs_line = lo + region.count("\n", 0, m.start())
            key = (kind, abs_line)
            if key in seen:
                continue
            seen.add(key)
            eff = effectiveness
            # Soften: allowlist alone without reject branch → unknown for net sinks
            if kind == "allowlist" and sink_type == "net":
                if not re.search(
                    r"(?i)(not\s+in|raise|return\s+.*(?:error|abort|400|403))",
                    region,
                ):
                    eff = EFFECT_UNKNOWN if effectiveness != EFFECT_CONFIRMED else EFFECT_LIKELY
            controls.append(
                {
                    "id": f"ctrl.{kind}.{file}:{abs_line}",
                    "kind": kind,
                    "effectiveness": eff,
                    "file": file,
                    "line": abs_line,
                    "evidence": evidence(
                        file,
                        abs_line,
                        symbol=kind,
                        reason=f"Control kind={kind} effectiveness={eff}",
                        snippet=lines[abs_line - 1] if 0 < abs_line <= len(lines) else None,
                    ),
                }
            )

    if sink_type == "sql" and _INEFFECTIVE_FOR_SQL.search(region):
        for m in _INEFFECTIVE_FOR_SQL.finditer(region):
            abs_line = lo + region.count("\n", 0, m.start())
            controls.append(
                {
                    "id": f"ctrl.ineffective.{file}:{abs_line}",
                    "kind": "sanitization",
                    "effectiveness": EFFECT_INEFFECTIVE,
                    "file": file,
                    "line": abs_line,
                    "evidence": evidence(
                        file,
                        abs_line,
                        reason="String strip/replace is not SQL parameterization",
                        snippet=lines[abs_line - 1] if 0 < abs_line <= len(lines) else None,
                    ),
                }
            )

    return controls


def classify_taint_state(
    controls: list[dict[str, Any]],
    *,
    sink_type: str | None = None,
    trust_level: str | None = None,
) -> str:
    """
    Derive path taint_state from observed controls.

    Prefer UNKNOWN / TAINTED over inventing SANITIZED without evidence.
    """
    from engines.dataflow.schema import (
        PARTIALLY_SANITIZED,
        SANITIZED,
        TAINTED,
        TRUSTED,
        TRUST_TRUSTED,
        UNKNOWN,
        VALIDATED,
        EFFECT_CONFIRMED,
        EFFECT_LIKELY,
    )

    if trust_level == TRUST_TRUSTED:
        return TRUSTED

    confirmed = [
        c
        for c in controls
        if c.get("effectiveness") == EFFECT_CONFIRMED
        and c.get("kind") in {"parameterization", "allowlist", "sanitization"}
    ]
    likely = [
        c
        for c in controls
        if c.get("effectiveness") == EFFECT_LIKELY
        and c.get("kind") in {"parameterization", "allowlist", "sanitization", "validation"}
    ]
    validated = [c for c in controls if c.get("kind") == "validation"]

    # Parameterization confirmed for SQL → SANITIZED
    if sink_type == "sql" and any(c.get("kind") == "parameterization" for c in confirmed):
        return SANITIZED
    if sink_type == "net" and any(c.get("kind") == "allowlist" for c in confirmed):
        return SANITIZED

    if confirmed and likely:
        return PARTIALLY_SANITIZED
    if confirmed:
        # Single confirmed control — still sanitized for matching sink
        if any(c.get("kind") == "parameterization" for c in confirmed):
            return SANITIZED
        if any(c.get("kind") == "allowlist" for c in confirmed):
            return VALIDATED
        return PARTIALLY_SANITIZED

    if likely:
        # Do NOT claim SANITIZED on likely-only evidence
        if any(c.get("kind") == "parameterization" for c in likely):
            return PARTIALLY_SANITIZED
        if validated:
            return VALIDATED
        return PARTIALLY_SANITIZED

    if validated:
        return VALIDATED

    if not controls:
        return TAINTED

    return UNKNOWN
