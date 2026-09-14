"""Evaluate whether observed controls are effective (vs name-only / bypassable)."""

from __future__ import annotations

import re
from typing import Any

from engines.verify.schema import (
    VULN_CMD,
    VULN_PATH,
    VULN_SQL,
    VULN_SSRF,
    VULN_XSS,
)

# SQL: f-string / format / concat near execute → parameterization NOT effective
_SQL_UNSAFE = re.compile(
    r"(?:execute|executemany)\s*\(\s*f['\"]|"
    r"(?:execute|executemany)\s*\(\s*['\"][^'\"]*['\"]\s*%|"
    r"(?:execute|executemany)\s*\(\s*.*\.format\s*\(|"
    r"(?:execute|executemany)\s*\(\s*['\"][^'\"]*['\"]\s*\+",
    re.I,
)
_SQL_PARAM = re.compile(
    r"\.(?:execute|executemany)\s*\(\s*['\"][^'\"]*(?:\?|%s|:\w+)[^'\"]*['\"]\s*,",
    re.I,
)

# SSRF allowlist with reject
_SSRF_ALLOW_REJECT = re.compile(
    r"(?i)if\s+.*(?:hostname|host)\s+not\s+in\s+\w+[\s\S]{0,120}?"
    r"(?:return|raise|abort)",
)
_SSRF_SCHEME_WEAK = re.compile(
    r"(?i)startswith\s*\(\s*['\"]https?://",
)

# XSS escape
_XSS_ESCAPE = re.compile(
    r"(?i)(?:html\.escape|markupsafe\.escape|bleach\.clean|escapeHtml|cgi\.escape)\s*\(",
)
_XSS_RAW = re.compile(
    r"(?i)(?:\|safe\b|Markup\s*\(|dangerouslySetInnerHTML|innerHTML\s*=)",
)

# Path jail
_PATH_JAIL = re.compile(
    r"(?i)(?:commonpath|relative_to|startswith\s*\(\s*(?:str\s*\()?base)",
)
_PATH_NORM_ONLY = re.compile(
    r"(?i)(?:normpath|abspath|realpath|secure_filename)",
)

# Authz
_AUTHZ = re.compile(
    r"(?i)(?:@login_required|@permission_required|@require_auth|"
    r"check_permission|has_permission|authorize\()",
)


def analyze_control_effectiveness(
    *,
    vulnerability_type: str,
    candidate: dict[str, Any],
    counter_hits: list[dict[str, Any]],
    source_snippets: list[str] | None = None,
) -> dict[str, Any]:
    """
    Decide if controls near the finding are effective for this vuln class.

    Returns::
        {
          "effectiveness": "confirmed"|"likely"|"unknown"|"ineffective",
          "bypassable": "yes"|"no"|"unclear"|"unknown",
          "fp_reasons": [...],
          "kinds_seen": [...],
          "name_only_control": bool,
          "surviving_risk": bool,
          "notes": [...],
        }
    """
    vtype = str(vulnerability_type or candidate.get("vulnerability_type") or "")
    hits = counter_hits or []
    kinds = {str(h.get("kind") or "") for h in hits}
    name_only = "name_only_control" in kinds
    # Filter ignored comments out of strength calc
    real_hits = [h for h in hits if h.get("kind") not in {"ignored_comment", "name_only_control"}]

    blobs = list(source_snippets or [])
    for h in real_hits:
        ev = h.get("evidence") or {}
        if isinstance(ev, dict) and ev.get("snippet"):
            blobs.append(str(ev["snippet"]))
    region = "\n".join(blobs)

    fp_reasons: list[str] = []
    notes: list[str] = []
    effectiveness = "unknown"
    bypassable = "unknown"
    surviving_risk = True

    if vtype == VULN_SQL:
        effectiveness, bypassable, fp_reasons, notes, surviving_risk = _sql(
            real_hits, region, name_only
        )
    elif vtype == VULN_SSRF:
        effectiveness, bypassable, fp_reasons, notes, surviving_risk = _ssrf(
            real_hits, region, name_only
        )
    elif vtype == VULN_XSS:
        effectiveness, bypassable, fp_reasons, notes, surviving_risk = _xss(
            real_hits, region, name_only
        )
    elif vtype == VULN_PATH:
        effectiveness, bypassable, fp_reasons, notes, surviving_risk = _path(
            real_hits, region, name_only
        )
    elif vtype == VULN_CMD:
        effectiveness, bypassable, fp_reasons, notes, surviving_risk = _cmd(
            real_hits, region, name_only
        )
    else:
        effectiveness, bypassable, fp_reasons, notes, surviving_risk = _generic(
            real_hits, name_only
        )

    # Authorization / tenant as soft signals (rarely sole FP for injection classes)
    if any(h.get("kind") == "authorization" for h in real_hits):
        notes.append("Authorization evidence present (does not alone disprove injection)")
    if any(h.get("kind") == "tenant_isolation" for h in real_hits):
        notes.append("Tenant isolation evidence present")

    # Name-only never upgrades to confirmed
    if name_only and effectiveness == "confirmed":
        effectiveness = "likely"
        notes.append("Downgraded: sanitize/validate name alone is not confirmed control")
        surviving_risk = True

    return {
        "effectiveness": effectiveness,
        "bypassable": bypassable,
        "fp_reasons": fp_reasons,
        "kinds_seen": sorted(kinds),
        "name_only_control": name_only,
        "surviving_risk": surviving_risk,
        "notes": notes,
    }


def _best_strength(hits: list[dict[str, Any]], kind: str) -> str | None:
    best = None
    rank = {"confirmed": 3, "likely": 2, "weak": 1}
    for h in hits:
        if h.get("kind") != kind:
            continue
        s = str(h.get("strength") or "weak")
        if best is None or rank.get(s, 0) > rank.get(best, 0):
            best = s
    return best


def _sql(
    hits: list[dict[str, Any]], region: str, name_only: bool
) -> tuple[str, str, list[str], list[str], bool]:
    from engines.adversary.schema import FP_SAFE_PARAMETERIZATION

    notes: list[str] = []
    if _SQL_UNSAFE.search(region):
        notes.append("Unsafe dynamic SQL construction near sink")
        return "ineffective", "yes", [], notes, True

    strength = _best_strength(hits, "parameterization")
    if strength == "confirmed" or _SQL_PARAM.search(region):
        if name_only and not _SQL_PARAM.search(region):
            return "unknown", "unclear", [], notes + ["name-only near SQL"], True
        return (
            "confirmed",
            "no",
            [FP_SAFE_PARAMETERIZATION],
            notes + ["Parameterized query with bound arguments"],
            False,
        )
    if strength == "likely":
        return "likely", "unclear", [FP_SAFE_PARAMETERIZATION], notes, True
    return "unknown", "unknown", [], notes, True


def _ssrf(
    hits: list[dict[str, Any]], region: str, name_only: bool
) -> tuple[str, str, list[str], list[str], bool]:
    from engines.adversary.schema import FP_SAFE_VALIDATION, FP_CONFIGURATION_PREVENTS_EXPLOIT

    notes: list[str] = []
    strength = _best_strength(hits, "allowlist")
    if strength == "confirmed" or _SSRF_ALLOW_REJECT.search(region):
        return (
            "confirmed",
            "no",
            [FP_SAFE_VALIDATION, FP_CONFIGURATION_PREVENTS_EXPLOIT],
            notes + ["Hostname allowlist with reject path"],
            False,
        )
    if strength == "likely":
        # startswith http alone is weak
        if _SSRF_SCHEME_WEAK.search(region) and "ALLOWED" not in region.upper():
            return "ineffective", "yes", [], notes + ["Scheme prefix check is bypassable"], True
        return "likely", "unclear", [FP_SAFE_VALIDATION], notes, True
    if name_only:
        return "ineffective", "yes", [], notes + ["Named sanitize without allowlist"], True
    return "unknown", "unknown", [], notes, True


def _xss(
    hits: list[dict[str, Any]], region: str, name_only: bool
) -> tuple[str, str, list[str], list[str], bool]:
    from engines.adversary.schema import FP_SAFE_SANITIZATION, FP_FRAMEWORK_PROTECTION

    notes: list[str] = []
    if _XSS_RAW.search(region):
        notes.append("Raw HTML / |safe / dangerouslySetInnerHTML nearby")
        return "ineffective", "yes", [], notes, True
    strength = _best_strength(hits, "sanitization")
    fw = _best_strength(hits, "framework")
    if strength == "confirmed" or _XSS_ESCAPE.search(region):
        return (
            "confirmed",
            "no",
            [FP_SAFE_SANITIZATION],
            notes + ["Contextual HTML escaping observed"],
            False,
        )
    if fw in {"confirmed", "likely"} and strength in {"likely", "confirmed"}:
        return (
            "likely",
            "unclear",
            [FP_SAFE_SANITIZATION, FP_FRAMEWORK_PROTECTION],
            notes,
            True,
        )
    if strength == "likely" or fw == "likely":
        return "likely", "unclear", [FP_SAFE_SANITIZATION], notes, True
    if name_only:
        return "ineffective", "yes", [], notes + ["sanitize() name without escape API"], True
    return "unknown", "unknown", [], notes, True


def _path(
    hits: list[dict[str, Any]], region: str, name_only: bool
) -> tuple[str, str, list[str], list[str], bool]:
    from engines.adversary.schema import FP_SAFE_VALIDATION, FP_SAFE_SANITIZATION

    notes: list[str] = []
    strength = _best_strength(hits, "path_jail")
    if strength == "confirmed" or _PATH_JAIL.search(region):
        return (
            "confirmed",
            "no",
            [FP_SAFE_VALIDATION],
            notes + ["Base-directory / path jail enforcement"],
            False,
        )
    if strength == "likely" or _PATH_NORM_ONLY.search(region):
        # Normalization alone is often bypassable
        return (
            "likely",
            "unclear",
            [FP_SAFE_SANITIZATION],
            notes + ["Path normalization without proven jail"],
            True,
        )
    if name_only:
        return "ineffective", "yes", [], notes, True
    return "unknown", "unknown", [], notes, True


def _cmd(
    hits: list[dict[str, Any]], region: str, name_only: bool
) -> tuple[str, str, list[str], list[str], bool]:
    from engines.adversary.schema import FP_SAFE_VALIDATION

    notes: list[str] = []
    # shell=False + list argv is a positive control; argv from user still risky
    if re.search(r"(?i)shell\s*=\s*False", region):
        notes.append("shell=False observed — reduces injection surface but input may still be unsafe")
        return "likely", "unclear", [], notes, True
    strength = _best_strength(hits, "validation")
    if strength == "confirmed":
        return "confirmed", "no", [FP_SAFE_VALIDATION], notes, False
    if strength == "likely":
        return "likely", "unclear", [FP_SAFE_VALIDATION], notes, True
    if name_only:
        return "ineffective", "yes", [], notes, True
    return "unknown", "unknown", [], notes, True


def _generic(
    hits: list[dict[str, Any]], name_only: bool
) -> tuple[str, str, list[str], list[str], bool]:
    notes: list[str] = []
    confirmed = [h for h in hits if h.get("strength") == "confirmed"]
    if confirmed and not name_only:
        kinds = {str(h.get("kind")) for h in confirmed}
        reasons = []
        from engines.adversary.schema import (
            FP_AUTHORIZATION_PRESENT,
            FP_SAFE_PARAMETERIZATION,
            FP_SAFE_SANITIZATION,
            FP_SAFE_VALIDATION,
        )

        if "parameterization" in kinds:
            reasons.append(FP_SAFE_PARAMETERIZATION)
        if "sanitization" in kinds:
            reasons.append(FP_SAFE_SANITIZATION)
        if "validation" in kinds or "allowlist" in kinds:
            reasons.append(FP_SAFE_VALIDATION)
        if "authorization" in kinds:
            reasons.append(FP_AUTHORIZATION_PRESENT)
        return "confirmed", "no", reasons, notes, False
    likely = [h for h in hits if h.get("strength") == "likely"]
    if likely:
        return "likely", "unclear", [], notes, True
    return "unknown", "unknown", [], notes, True


def authz_present(counter_hits: list[dict[str, Any]], region: str = "") -> bool:
    if any(h.get("kind") == "authorization" for h in counter_hits):
        return True
    return bool(_AUTHZ.search(region or ""))
