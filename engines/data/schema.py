"""Training-data pipeline schema (Phase 9).

Infrastructure only — no model training, no dataset dumps, no weights.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any

DATA_VERSION = "1.0.0"
TOOL_NAME = "axguard"

# Registry statuses
STATUS_DISCOVERED = "DISCOVERED"
STATUS_UNDER_REVIEW = "UNDER_REVIEW"
STATUS_APPROVED = "APPROVED"
STATUS_REJECTED = "REJECTED"
STATUS_RESTRICTED = "RESTRICTED"
STATUS_EVALUATION_ONLY = "EVALUATION_ONLY"
STATUS_TRAINING_ONLY = "TRAINING_ONLY"
REGISTRY_STATUSES = frozenset(
    {
        STATUS_DISCOVERED,
        STATUS_UNDER_REVIEW,
        STATUS_APPROVED,
        STATUS_REJECTED,
        STATUS_RESTRICTED,
        STATUS_EVALUATION_ONLY,
        STATUS_TRAINING_ONLY,
    }
)

# Splits / use modes
SPLIT_TRAINING = "TRAINING"
SPLIT_VALIDATION = "VALIDATION"
SPLIT_TEST = "TEST"
SPLIT_BENCHMARK_ONLY = "BENCHMARK_ONLY"
SPLIT_RESEARCH_ONLY = "RESEARCH_ONLY"
SPLITS = frozenset(
    {
        SPLIT_TRAINING,
        SPLIT_VALIDATION,
        SPLIT_TEST,
        SPLIT_BENCHMARK_ONLY,
        SPLIT_RESEARCH_ONLY,
    }
)

# Domains / categories
CATEGORIES = frozenset(
    {
        "CODE_VULNERABILITY",
        "SECURE_CODE",
        "CODE_FIX",
        "SECURITY_REASONING",
        "FALSE_POSITIVE",
        "ATTACK_CHAIN",
        "ATTACK_GRAPH",
        "INCIDENT_GRAPH",
        "DEPENDENCY_SECURITY",
        "CVE_CWE",
        "AI_SECURITY",
        "PROMPT_INJECTION",
        "AI_AGENT_SECURITY",
        "MCP_SECURITY",
        "SUPPLY_CHAIN",
        "CLOUD_SECURITY",
        "AUTHORIZATION",
        "AUTHENTICATION",
        "API_SECURITY",
        "WEB_SECURITY",
        "RED_TEAM",
        "BLUE_TEAM",
        "TELEMETRY",
        "SECURITY_REPORT",
    }
)

# License families (normalized)
LICENSE_MIT = "MIT"
LICENSE_APACHE = "Apache-2.0"
LICENSE_BSD = "BSD"
LICENSE_CC0 = "CC0"
LICENSE_CC_BY = "CC-BY"
LICENSE_CC_BY_SA = "CC-BY-SA"
LICENSE_CC_BY_NC = "CC-BY-NC"
LICENSE_GPL = "GPL-family"
LICENSE_PROPRIETARY = "Proprietary"
LICENSE_UNKNOWN = "Unknown"
LICENSE_CUSTOM = "Custom"

# Quality
QUALITY_HIGH = "HIGH"
QUALITY_MEDIUM = "MEDIUM"
QUALITY_LOW = "LOW"
QUALITY_UNKNOWN = "UNKNOWN"

# Judge / FP verdicts (align Phase 3/4)
VERDICTS = frozenset(
    {"VERIFIED", "LIKELY", "UNVERIFIED", "FALSE_POSITIVE", "REQUIRES_REVIEW"}
)

FP_REASON_CODES = frozenset(
    {
        "SOURCE_NOT_CONTROLLED",
        "SINK_NOT_REACHABLE",
        "DATA_FLOW_NOT_CONFIRMED",
        "SAFE_VALIDATION",
        "SAFE_SANITIZATION",
        "SAFE_PARAMETERIZATION",
        "AUTHORIZATION_PRESENT",
        "TENANT_ISOLATION_PRESENT",
        "FRAMEWORK_PROTECTION",
        "CONFIGURATION_PREVENTS_EXPLOIT",
        "UNREACHABLE_CODE",
        "TRUSTED_INPUT",
        "CONTRADICTORY_EVIDENCE",
        "INSUFFICIENT_EVIDENCE",
    }
)

PATH_STATUSES = frozenset(
    {"CONFIRMED", "LIKELY", "UNVERIFIED", "INVALID", "BLOCKED", "UNKNOWN"}
)


def empty_registry() -> dict[str, Any]:
    return {
        "schema_version": DATA_VERSION,
        "tool": TOOL_NAME,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "datasets": [],
        "summary": {
            "dataset_count": 0,
            "by_status": {},
            "approved_training": 0,
            "rejected": 0,
            "restricted": 0,
            "evaluation_only": 0,
        },
    }


def empty_pipeline_result(target: Path | str) -> dict[str, Any]:
    return {
        "schema_version": DATA_VERSION,
        "tool": TOOL_NAME,
        "target": str(Path(target).resolve()),
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "registry": empty_registry(),
        "examples": [],
        "duplicates": [],
        "scrubbed": [],
        "poison_flags": [],
        "prepare": {},
        "summary": {},
        "meta": {"trained": False, "downloads": False},
    }


def registry_entry(
    dataset_id: str,
    *,
    source: str = "huggingface",
    url: str = "",
    license: str = LICENSE_UNKNOWN,
    license_verified: bool = False,
    commercial_use: bool | None = None,
    redistribution: bool | None = None,
    provenance: str = "",
    size: int | None = None,
    languages: list[str] | None = None,
    domains: list[str] | None = None,
    quality: str = QUALITY_UNKNOWN,
    recommended_use: list[str] | None = None,
    status: str = STATUS_DISCOVERED,
    notes: list[str] | None = None,
) -> dict[str, Any]:
    return {
        "dataset_id": dataset_id,
        "source": source,
        "url": url,
        "license": license,
        "license_verified": bool(license_verified),
        "commercial_use": commercial_use,
        "redistribution": redistribution,
        "provenance": provenance,
        "size": size,
        "languages": list(languages or []),
        "domains": list(domains or []),
        "quality": quality,
        "recommended_use": list(recommended_use or []),
        "status": status,
        "notes": list(notes or []),
    }
