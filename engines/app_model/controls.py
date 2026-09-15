"""Conservative security-control evidence discovery."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from engines.app_model.discover import read_text, rel_path
from engines.app_model.schema import (
    CONFIDENCE_CONFIRMED,
    CONFIDENCE_LIKELY,
    CONFIDENCE_UNKNOWN,
    evidence,
)

_CONTROL_PATTERNS: list[tuple[str, str, re.Pattern[str], str]] = [
    (
        "authentication",
        "flask_login_required",
        re.compile(r"@login_required\b"),
        "Flask login_required decorator",
    ),
    (
        "authentication",
        "jwt_required",
        re.compile(r"@jwt_required\b|jwt_required\s*\("),
        "JWT required decorator/call",
    ),
    (
        "authentication",
        "fastapi_depends_auth",
        re.compile(r"Depends\(\s*[A-Za-z_][\w]*\s*\)"),
        "FastAPI Depends (auth unknown without resolving dependency)",
    ),
    (
        "authentication",
        "express_middleware_auth",
        re.compile(
            r"(?i)(authenticate|requireAuth|verifyToken|isAuthenticated|passport\.authenticate)\s*\("
        ),
        "Express-style auth middleware call",
    ),
    (
        "authorization",
        "django_permission",
        re.compile(r"permission_classes\s*=|@permission_required\b|has_perm\s*\("),
        "Django/DRF permission evidence",
    ),
    (
        "authorization",
        "rbac_role_check",
        re.compile(r"(?i)(require_role|has_role|check_role|roles?\s*\.\s*includes)\s*\("),
        "Role check helper",
    ),
    (
        "csrf",
        "csrf_protect",
        re.compile(r"(?i)csrf[_-]?protect|CsrfViewMiddleware|csurf\b"),
        "CSRF protection reference",
    ),
    (
        "csrf",
        "csrf_exempt",
        re.compile(r"(?i)csrf\.exempt|csrf_exempt|csrf[_-]?protect(ion)?\s*=\s*False"),
        "CSRF exemption / disabled (control gap evidence)",
    ),
    (
        "cors",
        "cors_middleware",
        re.compile(r"(?i)CORSMiddleware|cors\(|Access-Control-Allow-Origin|flask_cors|cors\s*="),
        "CORS configuration evidence",
    ),
    (
        "jwt",
        "jwt_usage",
        re.compile(r"(?i)\bjwt\.(encode|decode)\b|jose\.|jsonwebtoken|PyJWT"),
        "JWT library usage",
    ),
    (
        "rate_limit",
        "rate_limit",
        re.compile(r"(?i)rate[_-]?limit|slowapi|express-rate-limit"),
        "Rate limiting reference",
    ),
    (
        "validation",
        "schema_validation",
        re.compile(r"(?i)BaseModel|pydantic|zod\.|Joi\.|cerberus|marshmallow"),
        "Schema/validation library evidence",
    ),
    (
        "security_headers",
        "helmet_or_headers",
        re.compile(r"(?i)\bhelmet\b|Strict-Transport-Security|Content-Security-Policy"),
        "Security headers / helmet evidence",
    ),
]

# Depends() alone is too weak — mark unknown confidence
_WEAK_TYPES = {"fastapi_depends_auth"}


def discover_controls(root: Path, files: list[Path]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    controls: list[dict[str, Any]] = []
    identities: list[dict[str, Any]] = []
    seen_ctrl: set[tuple[str, str, int]] = set()
    role_names: set[str] = set()

    role_pat = re.compile(
        r"""(?i)(?:role|roles)\s*[=:]\s*['\"]([A-Za-z_][\w\-]*)['\"]|['\"](admin|user|viewer|editor|owner)['\"]"""
    )

    for fpath in files:
        content = read_text(fpath)
        if not content:
            continue
        rel = rel_path(fpath, root)
        for ctrl_type, symbol, pattern, reason in _CONTROL_PATTERNS:
            for m in pattern.finditer(content):
                line = content.count("\n", 0, m.start()) + 1
                key = (symbol, rel, line)
                if key in seen_ctrl:
                    continue
                seen_ctrl.add(key)
                conf = CONFIDENCE_LIKELY
                if symbol in _WEAK_TYPES:
                    conf = CONFIDENCE_UNKNOWN
                elif ctrl_type in {"csrf", "jwt", "cors"} and "exempt" not in symbol:
                    conf = CONFIDENCE_CONFIRMED if symbol != "cors_middleware" else CONFIDENCE_LIKELY
                controls.append(
                    {
                        "type": ctrl_type,
                        "name": symbol,
                        "location": {"file": rel, "line": line},
                        "applies_to": "unknown",
                        "confidence": conf,
                        "evidence": evidence(rel, line, symbol=symbol, reason=reason),
                    }
                )

        for m in role_pat.finditer(content):
            name = m.group(1) or m.group(2)
            if not name or name.lower() in role_names:
                continue
            # Avoid common false positives from HTML/CSS
            if name.lower() in {"user", "admin"} and "role" not in content[max(0, m.start() - 40) : m.end() + 40].lower():
                continue
            role_names.add(name.lower())
            line = content.count("\n", 0, m.start()) + 1
            identities.append(
                {
                    "kind": "role",
                    "name": name,
                    "confidence": CONFIDENCE_LIKELY,
                    "evidence": evidence(rel, line, symbol=name, reason="Role string near role keyword"),
                }
            )

        if re.search(r"(?i)\bsession\b|\bSessionMiddleware\b|express-session", content):
            line = 1
            m = re.search(r"(?i)\bsession\b|\bSessionMiddleware\b|express-session", content)
            if m:
                line = content.count("\n", 0, m.start()) + 1
            identities.append(
                {
                    "kind": "session",
                    "name": "session",
                    "confidence": CONFIDENCE_LIKELY,
                    "evidence": evidence(rel, line, reason="Session mechanism reference"),
                }
            )

    # Dedupe identities by kind+name
    deduped: dict[tuple[str, str], dict[str, Any]] = {}
    for ident in identities:
        key = (ident["kind"], ident["name"].lower())
        if key not in deduped:
            deduped[key] = ident
    return controls, list(deduped.values())
