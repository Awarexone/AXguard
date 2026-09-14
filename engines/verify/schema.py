"""Hunter → Judge verification schema constants and empty factory."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any

VERIFICATION_VERSION = "1.0.0"
TOOL_NAME = "axguard"

# Judgment statuses
STATUS_VERIFIED = "VERIFIED"
STATUS_LIKELY = "LIKELY"
STATUS_UNVERIFIED = "UNVERIFIED"
STATUS_FALSE_POSITIVE = "FALSE_POSITIVE"
JUDGMENT_STATUSES = frozenset(
    {
        STATUS_VERIFIED,
        STATUS_LIKELY,
        STATUS_UNVERIFIED,
        STATUS_FALSE_POSITIVE,
    }
)

# Candidate lifecycle state (hunters never auto-verify)
CANDIDATE_STATUS = "candidate"
CANDIDATE_STATES = frozenset({CANDIDATE_STATUS})

# Confidence (shared vocabulary with app_model / dataflow)
CONFIDENCE_CONFIRMED = "confirmed"
CONFIDENCE_LIKELY = "likely"
CONFIDENCE_UNKNOWN = "unknown"
CONFIDENCES = frozenset(
    {CONFIDENCE_CONFIRMED, CONFIDENCE_LIKELY, CONFIDENCE_UNKNOWN}
)

# Exploitability
EXPLOIT_UNKNOWN = "unknown"
EXPLOIT_LIKELY = "likely"
EXPLOIT_CONFIRMED = "confirmed"
EXPLOIT_NONE = "none"
EXPLOITABILITIES = frozenset(
    {EXPLOIT_UNKNOWN, EXPLOIT_LIKELY, EXPLOIT_CONFIRMED, EXPLOIT_NONE}
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

# Vulnerability types hunted in Phase 3 core
VULN_SQL = "sql-injection"
VULN_SSRF = "ssrf"
VULN_XSS = "xss"
VULN_CMD = "command-injection"
VULN_PATH = "path-traversal"
VULN_TYPES = frozenset(
    {VULN_SQL, VULN_SSRF, VULN_XSS, VULN_CMD, VULN_PATH}
)

# Evidence types (weighted in evidence.py)
EV_TAINT_PATH = "taint_path"
EV_SINK_MATCH = "sink_match"
EV_SOURCE_MATCH = "source_match"
EV_CONTROL = "control"
EV_PARAMETERIZATION = "parameterization"
EV_ALLOWLIST = "allowlist"
EV_SANITIZATION = "sanitization"
EV_VALIDATION = "validation"
EV_PATTERN_ONLY = "pattern_only"
EV_COMMENT_OR_FIXTURE = "comment_or_fixture"
EV_CONTRADICTION = "contradiction"
EV_MISSING_LINK = "missing_dataflow_link"
EVIDENCE_TYPES = frozenset(
    {
        EV_TAINT_PATH,
        EV_SINK_MATCH,
        EV_SOURCE_MATCH,
        EV_CONTROL,
        EV_PARAMETERIZATION,
        EV_ALLOWLIST,
        EV_SANITIZATION,
        EV_VALIDATION,
        EV_PATTERN_ONLY,
        EV_COMMENT_OR_FIXTURE,
        EV_CONTRADICTION,
        EV_MISSING_LINK,
    }
)

# Recommended next steps
NEXT_TRIAGE = "triage"
NEXT_IGNORE = "ignore"
NEXT_MANUAL = "needs-manual"
NEXT_FIX = "fix"
NEXT_STEPS = frozenset({NEXT_TRIAGE, NEXT_IGNORE, NEXT_MANUAL, NEXT_FIX})

# Map dataflow / app_model sink types → vuln classes
SINK_TO_VULN: dict[str, str] = {
    "sql": VULN_SQL,
    "net": VULN_SSRF,
    "http": VULN_SSRF,
    "html": VULN_XSS,
    "template": VULN_XSS,
    "cmd": VULN_CMD,
    "exec": VULN_CMD,
    "eval": VULN_CMD,
    "fs": VULN_PATH,
}

VULN_TO_SINK_TYPES: dict[str, frozenset[str]] = {
    VULN_SQL: frozenset({"sql"}),
    VULN_SSRF: frozenset({"net", "http"}),
    VULN_XSS: frozenset({"html", "template"}),
    VULN_CMD: frozenset({"cmd", "exec", "eval"}),
    VULN_PATH: frozenset({"fs"}),
}

DEFAULT_SEVERITY: dict[str, str] = {
    VULN_SQL: SEVERITY_HIGH,
    VULN_SSRF: SEVERITY_HIGH,
    VULN_XSS: SEVERITY_MEDIUM,
    VULN_CMD: SEVERITY_CRITICAL,
    VULN_PATH: SEVERITY_HIGH,
}


def empty_verification(target: Path) -> dict[str, Any]:
    root = str(target.resolve())
    return {
        "schema_version": VERIFICATION_VERSION,
        "tool": TOOL_NAME,
        "target": root,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "candidates": [],
        "judgments": [],
        "summary": {
            "candidate_count": 0,
            "VERIFIED": 0,
            "LIKELY": 0,
            "UNVERIFIED": 0,
            "FALSE_POSITIVE": 0,
            "by_type": {},
        },
    }
