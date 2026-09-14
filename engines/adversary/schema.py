"""False Positive Adversary schema constants and empty factory."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ADVERSARY_VERSION = "1.0.0"
TOOL_NAME = "axguard"

# Final finding statuses (Phase 4 outcomes)
STATUS_CONFIRMED = "CONFIRMED"
STATUS_LIKELY = "LIKELY"
STATUS_UNVERIFIED = "UNVERIFIED"
STATUS_FALSE_POSITIVE = "FALSE_POSITIVE"
STATUS_REQUIRES_REVIEW = "REQUIRES_REVIEW"
ADVERSARY_STATUSES = frozenset(
    {
        STATUS_CONFIRMED,
        STATUS_LIKELY,
        STATUS_UNVERIFIED,
        STATUS_FALSE_POSITIVE,
        STATUS_REQUIRES_REVIEW,
    }
)

# Confidence (shared vocabulary)
CONFIDENCE_CONFIRMED = "confirmed"
CONFIDENCE_LIKELY = "likely"
CONFIDENCE_UNKNOWN = "unknown"
CONFIDENCES = frozenset(
    {CONFIDENCE_CONFIRMED, CONFIDENCE_LIKELY, CONFIDENCE_UNKNOWN}
)

# Severity
SEVERITY_CRITICAL = "critical"
SEVERITY_HIGH = "high"
SEVERITY_MEDIUM = "medium"
SEVERITY_LOW = "low"
SEVERITY_INFO = "info"
SEVERITIES = frozenset(
    {
        SEVERITY_CRITICAL,
        SEVERITY_HIGH,
        SEVERITY_MEDIUM,
        SEVERITY_LOW,
        SEVERITY_INFO,
    }
)

# Structured false-positive reason codes
FP_SOURCE_NOT_CONTROLLED = "SOURCE_NOT_CONTROLLED"
FP_SINK_NOT_REACHABLE = "SINK_NOT_REACHABLE"
FP_DATA_FLOW_NOT_CONFIRMED = "DATA_FLOW_NOT_CONFIRMED"
FP_SAFE_VALIDATION = "SAFE_VALIDATION"
FP_SAFE_SANITIZATION = "SAFE_SANITIZATION"
FP_SAFE_PARAMETERIZATION = "SAFE_PARAMETERIZATION"
FP_AUTHORIZATION_PRESENT = "AUTHORIZATION_PRESENT"
FP_TENANT_ISOLATION_PRESENT = "TENANT_ISOLATION_PRESENT"
FP_FRAMEWORK_PROTECTION = "FRAMEWORK_PROTECTION"
FP_CONFIGURATION_PREVENTS_EXPLOIT = "CONFIGURATION_PREVENTS_EXPLOIT"
FP_UNREACHABLE_CODE = "UNREACHABLE_CODE"
FP_TRUSTED_INPUT = "TRUSTED_INPUT"
FP_CONTRADICTORY_EVIDENCE = "CONTRADICTORY_EVIDENCE"
FP_INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"

FP_REASON_CODES = frozenset(
    {
        FP_SOURCE_NOT_CONTROLLED,
        FP_SINK_NOT_REACHABLE,
        FP_DATA_FLOW_NOT_CONFIRMED,
        FP_SAFE_VALIDATION,
        FP_SAFE_SANITIZATION,
        FP_SAFE_PARAMETERIZATION,
        FP_AUTHORIZATION_PRESENT,
        FP_TENANT_ISOLATION_PRESENT,
        FP_FRAMEWORK_PROTECTION,
        FP_CONFIGURATION_PREVENTS_EXPLOIT,
        FP_UNREACHABLE_CODE,
        FP_TRUSTED_INPUT,
        FP_CONTRADICTORY_EVIDENCE,
        FP_INSUFFICIENT_EVIDENCE,
    }
)

# Judge statuses that get full adversarial challenge
CHALLENGE_STATUSES = frozenset({"VERIFIED", "LIKELY"})
# Optional light challenge
LIGHT_CHALLENGE_STATUSES = frozenset({"UNVERIFIED"})

# Map Phase 3 Judge → Phase 4 starting status before challenge
JUDGE_TO_START: dict[str, str] = {
    "VERIFIED": STATUS_CONFIRMED,
    "LIKELY": STATUS_LIKELY,
    "UNVERIFIED": STATUS_UNVERIFIED,
    "FALSE_POSITIVE": STATUS_FALSE_POSITIVE,
}

SEVERITY_RANK = {
    SEVERITY_CRITICAL: 4,
    SEVERITY_HIGH: 3,
    SEVERITY_MEDIUM: 2,
    SEVERITY_LOW: 1,
    SEVERITY_INFO: 0,
}


def empty_adversary(target: Path) -> dict[str, Any]:
    root = str(target.resolve())
    return {
        "schema_version": ADVERSARY_VERSION,
        "tool": TOOL_NAME,
        "target": root,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "findings": [],
        "summary": {
            "finding_count": 0,
            "challenged_count": 0,
            "CONFIRMED": 0,
            "LIKELY": 0,
            "UNVERIFIED": 0,
            "FALSE_POSITIVE": 0,
            "REQUIRES_REVIEW": 0,
            "by_type": {},
        },
    }
