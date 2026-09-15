"""License / provenance gate for the public AXGuard training corpus."""

from __future__ import annotations

import re
from typing import Any

from engines.data.schema import (
    LICENSE_APACHE,
    LICENSE_BSD,
    LICENSE_CC0,
    LICENSE_CC_BY,
    LICENSE_CC_BY_NC,
    LICENSE_CC_BY_SA,
    LICENSE_CUSTOM,
    LICENSE_GPL,
    LICENSE_MIT,
    LICENSE_PROPRIETARY,
    LICENSE_UNKNOWN,
    STATUS_APPROVED,
    STATUS_EVALUATION_ONLY,
    STATUS_REJECTED,
    STATUS_RESTRICTED,
    STATUS_UNDER_REVIEW,
)

# Normalized license → gate decision for *public training* corpus
_APPROVED_PUBLIC_TRAINING = frozenset(
    {LICENSE_MIT, LICENSE_APACHE, LICENSE_BSD, LICENSE_CC0, LICENSE_CC_BY}
)
_EVAL_OR_RESTRICTED = frozenset(
    {LICENSE_CC_BY_SA, LICENSE_CC_BY_NC, LICENSE_GPL, LICENSE_CUSTOM}
)
_HARD_REJECT_PUBLIC = frozenset({LICENSE_PROPRIETARY, LICENSE_UNKNOWN})

_ALIASES: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"\bmit\b", re.I), LICENSE_MIT),
    (re.compile(r"apache[- ]?2(\.0)?", re.I), LICENSE_APACHE),
    (re.compile(r"\bbsd\b", re.I), LICENSE_BSD),
    (re.compile(r"\bcc0\b|public.?domain", re.I), LICENSE_CC0),
    (re.compile(r"cc[- ]?by[- ]?nc", re.I), LICENSE_CC_BY_NC),
    (re.compile(r"cc[- ]?by[- ]?sa", re.I), LICENSE_CC_BY_SA),
    (re.compile(r"cc[- ]?by\b", re.I), LICENSE_CC_BY),
    (re.compile(r"\bgpl\b|agpl|lgpl", re.I), LICENSE_GPL),
    (re.compile(r"proprietary|all rights reserved|closed", re.I), LICENSE_PROPRIETARY),
]


def normalize_license(raw: str | None) -> str:
    text = str(raw or "").strip()
    if not text or text.lower() in {"unknown", "n/a", "none", "?"}:
        return LICENSE_UNKNOWN
    for pat, name in _ALIASES:
        if pat.search(text):
            return name
    return LICENSE_CUSTOM


def gate_flags(license_name: str) -> dict[str, bool]:
    lic = normalize_license(license_name)
    return {
        "commercial_restriction": lic in {LICENSE_CC_BY_NC, LICENSE_PROPRIETARY},
        "non_commercial": lic == LICENSE_CC_BY_NC,
        "share_alike": lic in {LICENSE_CC_BY_SA, LICENSE_GPL},
        "unknown_license": lic == LICENSE_UNKNOWN,
        "proprietary": lic == LICENSE_PROPRIETARY,
        "unclear_provenance": lic in {LICENSE_UNKNOWN, LICENSE_CUSTOM},
        "restricted_redistribution": lic
        in {LICENSE_GPL, LICENSE_CC_BY_SA, LICENSE_PROPRIETARY, LICENSE_UNKNOWN},
    }


def evaluate_for_public_training(
    entry: dict[str, Any],
    *,
    force_research_only: bool = False,
) -> dict[str, Any]:
    """Decide whether a dataset may enter the *public* training corpus.

    UNKNOWN / Proprietary never auto-approve into TRAINING.
    Unverified licenses stay UNDER_REVIEW even when the SPDX string looks fine.
    """
    lic = normalize_license(entry.get("license"))
    verified = bool(entry.get("license_verified"))
    flags = gate_flags(lic)
    reasons: list[str] = []

    if force_research_only:
        return {
            "allowed_public_training": False,
            "recommended_status": STATUS_EVALUATION_ONLY,
            "license_normalized": lic,
            "flags": flags,
            "reasons": ["Explicit research/evaluation-only request"],
            "requires_human_approval": False,
        }

    if lic in _HARD_REJECT_PUBLIC:
        reasons.append(f"{lic} must not enter public training corpus automatically")
        return {
            "allowed_public_training": False,
            "recommended_status": STATUS_REJECTED
            if lic == LICENSE_PROPRIETARY
            else STATUS_RESTRICTED,
            "license_normalized": lic,
            "flags": flags,
            "reasons": reasons,
            "requires_human_approval": True,
        }

    if not verified:
        reasons.append("license_verified=false — human review required")
        return {
            "allowed_public_training": False,
            "recommended_status": STATUS_UNDER_REVIEW,
            "license_normalized": lic,
            "flags": flags,
            "reasons": reasons,
            "requires_human_approval": True,
        }

    if lic in _EVAL_OR_RESTRICTED:
        reasons.append(f"{lic} — evaluation/research only for public AXGuard corpus")
        return {
            "allowed_public_training": False,
            "recommended_status": STATUS_EVALUATION_ONLY
            if lic != LICENSE_PROPRIETARY
            else STATUS_RESTRICTED,
            "license_normalized": lic,
            "flags": flags,
            "reasons": reasons,
            "requires_human_approval": True,
        }

    if lic in _APPROVED_PUBLIC_TRAINING:
        return {
            "allowed_public_training": True,
            "recommended_status": STATUS_APPROVED,
            "license_normalized": lic,
            "flags": flags,
            "reasons": ["License family approved for public training when verified"],
            "requires_human_approval": False,
        }

    reasons.append("Unrecognized license path")
    return {
        "allowed_public_training": False,
        "recommended_status": STATUS_UNDER_REVIEW,
        "license_normalized": lic,
        "flags": flags,
        "reasons": reasons,
        "requires_human_approval": True,
    }


def can_approve_for_training(entry: dict[str, Any]) -> tuple[bool, str]:
    decision = evaluate_for_public_training(entry)
    if decision["allowed_public_training"]:
        return True, "ok"
    return False, "; ".join(decision["reasons"])
