"""Controls as barriers — BLOCKED vs ineffective.

Controls are graph nodes/edges, not silent modifiers. A control sits on an
edge (typically the ``reaches`` edge between the internet and an entrypoint).
It blocks the path only when it is genuinely **effective**:

- EFFECTIVE  → cryptographic / token verification that *fails closed* (e.g.
  ``jwt.decode`` + an early ``return 401/403`` on failure). Blocks the
  unauthenticated-attacker path → ``BLOCKED``.
- INEFFECTIVE → a name-only / mutable-field check (``role`` read from an
  attacker-writable record), or a control undermined by a finding on the same
  path (mass-assignment writes the field the control trusts; BOLA means the
  tenant check never re-validates the returned object). Does **not** block.

This mirrors the adversary philosophy: name-only ``sanitize()`` /
``require_auth``-that-doesn't-check is not enough.
"""

from __future__ import annotations

import re
from typing import Any

from engines.attack_graph.schema import (
    EFFECT_CONFIRMED,
    EFFECT_INEFFECTIVE,
    EFFECT_LIKELY,
    EFFECT_UNKNOWN,
)

# Signals of a cryptographic / token verification that can fail closed.
_CRYPTO_VERIFY = re.compile(
    r"jwt\.decode\(|hmac\.|hashlib\.\w+\(.*compare|"
    r"\.verify\(|verify_signature|itsdangerous|signature",
    re.IGNORECASE,
)
# Signals of a mutable-field-only role/tenant check (no crypto).
_MUTABLE_ROLE_CHECK = re.compile(r"\.get\(['\"]role['\"]\)|\[['\"]role['\"]\]|role\s*!=|role\s*==", re.IGNORECASE)
# Signals the control returns before the handler on failure (fails closed).
_FAILS_CLOSED = re.compile(r"return\s+jsonify\([^)]*\)\s*,\s*(401|403)|abort\(\s*(401|403)\s*\)", re.IGNORECASE)


def extract_decorator_body(source: str, decorator_name: str) -> str:
    """Return the source of ``def <decorator_name>(...)`` up to the next
    top-level ``def``/``class``/route. Empty string if not found.
    """
    lines = source.splitlines()
    start = None
    for i, ln in enumerate(lines):
        if re.match(rf"\s*def\s+{re.escape(decorator_name)}\s*\(", ln):
            start = i
            break
    if start is None:
        return ""
    body = [lines[start]]
    base_indent = len(lines[start]) - len(lines[start].lstrip())
    for ln in lines[start + 1 :]:
        if ln.strip() and (len(ln) - len(ln.lstrip())) <= base_indent and re.match(r"\s*(def|class|@)", ln):
            break
        body.append(ln)
    return "\n".join(body)


def decorators_for_handler(source: str, handler: str) -> list[str]:
    """Return decorator names (excluding app.route) applied to ``handler``."""
    lines = source.splitlines()
    for i, ln in enumerate(lines):
        if re.match(rf"\s*def\s+{re.escape(handler)}\s*\(", ln):
            decs: list[str] = []
            j = i - 1
            while j >= 0 and lines[j].strip().startswith("@"):
                name = lines[j].strip().lstrip("@").split("(")[0].strip()
                if not name.startswith("app.") and "route" not in name:
                    decs.append(name)
                j -= 1
            return decs
    return []


def classify_control(
    name: str,
    source: str,
    *,
    undermined: bool,
) -> dict[str, Any]:
    """Classify a decorator control's effectiveness from its body.

    ``undermined`` is True when a finding on the same path defeats the control
    (mass-assignment writing the trusted field, or BOLA bypassing the scope
    check) — in that case the control is ineffective regardless of its shape.
    """
    body = extract_decorator_body(source, name)
    has_crypto = bool(_CRYPTO_VERIFY.search(body))
    fails_closed = bool(_FAILS_CLOSED.search(body))
    mutable_only = bool(_MUTABLE_ROLE_CHECK.search(body)) and not has_crypto

    if undermined:
        effectiveness = EFFECT_INEFFECTIVE
        reason = (
            f"`{name}` is undermined by a finding on this path (trusts an "
            "attacker-writable field / never re-checks the returned object)."
        )
    elif has_crypto and fails_closed:
        effectiveness = EFFECT_CONFIRMED
        reason = f"`{name}` cryptographically verifies the token and fails closed (returns 401/403)."
    elif mutable_only:
        effectiveness = EFFECT_INEFFECTIVE
        reason = f"`{name}` checks only a mutable role field with no cryptographic verification."
    elif fails_closed:
        effectiveness = EFFECT_LIKELY
        reason = f"`{name}` fails closed but performs no cryptographic verification."
    else:
        effectiveness = EFFECT_UNKNOWN
        reason = f"`{name}` effectiveness could not be established from code."

    return {
        "name": name,
        "effectiveness": effectiveness,
        "blocks": effectiveness in {EFFECT_CONFIRMED},
        "reason": reason,
        "line": _line_of(source, f"def {name}"),
    }


def _line_of(source: str, needle: str, default: int = 1) -> int:
    for i, ln in enumerate(source.splitlines(), 1):
        if needle in ln:
            return i
    return default
