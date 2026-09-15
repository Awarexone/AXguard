"""Contributor engagement & learning — types, provenance, config defaults.

Local-only by default. Learning and contribution packaging are opt-in.
Scoring measures opportunity usefulness, never personal worth.
"""

from __future__ import annotations

from typing import Any

# ---------------------------------------------------------------------------
# Contribution opportunity types
# ---------------------------------------------------------------------------
TYPE_BUG_FIX = "BUG_FIX"
TYPE_SECURITY_RULE = "SECURITY_RULE"
TYPE_REGRESSION_TEST = "REGRESSION_TEST"
TYPE_FALSE_POSITIVE_FIX = "FALSE_POSITIVE_FIX"
TYPE_FRAMEWORK_SUPPORT = "FRAMEWORK_SUPPORT"
TYPE_ATTACK_PATH_PATTERN = "ATTACK_PATH_PATTERN"
TYPE_SYNTHETIC_SECURITY_CASE = "SYNTHETIC_SECURITY_CASE"
TYPE_MCP_SECURITY_CASE = "MCP_SECURITY_CASE"
TYPE_DOCUMENTATION = "DOCUMENTATION"
TYPE_PERFORMANCE = "PERFORMANCE"
TYPE_DX = "DX"
TYPE_NOVEL_FINDING = "NOVEL_FINDING"
TYPE_TEST = "TEST"
TYPE_DOCS = "DOCS"
TYPE_RULE = "RULE"
TYPE_AI_AGENT = "AI_AGENT"

CONTRIBUTION_TYPES = frozenset(
    {
        TYPE_BUG_FIX,
        TYPE_SECURITY_RULE,
        TYPE_REGRESSION_TEST,
        TYPE_FALSE_POSITIVE_FIX,
        TYPE_FRAMEWORK_SUPPORT,
        TYPE_ATTACK_PATH_PATTERN,
        TYPE_SYNTHETIC_SECURITY_CASE,
        TYPE_MCP_SECURITY_CASE,
        TYPE_DOCUMENTATION,
        TYPE_PERFORMANCE,
        TYPE_DX,
        TYPE_NOVEL_FINDING,
        TYPE_TEST,
        TYPE_DOCS,
        TYPE_RULE,
        TYPE_AI_AGENT,
    }
)

# Human labels (engineer-to-engineer, no hype)
TYPE_LABELS: dict[str, str] = {
    TYPE_BUG_FIX: "Bug Fix",
    TYPE_SECURITY_RULE: "Security Rule",
    TYPE_REGRESSION_TEST: "Regression Test",
    TYPE_FALSE_POSITIVE_FIX: "False Positive Fix",
    TYPE_FRAMEWORK_SUPPORT: "Framework Support",
    TYPE_ATTACK_PATH_PATTERN: "Attack Path Pattern",
    TYPE_SYNTHETIC_SECURITY_CASE: "Synthetic Security Case",
    TYPE_MCP_SECURITY_CASE: "MCP Security Case",
    TYPE_DOCUMENTATION: "Documentation",
    TYPE_PERFORMANCE: "Performance",
    TYPE_DX: "Developer Experience",
    TYPE_NOVEL_FINDING: "Novel Finding Pattern",
    TYPE_TEST: "Test",
    TYPE_DOCS: "Docs",
    TYPE_RULE: "Rule",
    TYPE_AI_AGENT: "AI / Agent Security Case",
}

# ---------------------------------------------------------------------------
# Difficulty
# ---------------------------------------------------------------------------
DIFFICULTY_EASY = "EASY"
DIFFICULTY_MEDIUM = "MEDIUM"
DIFFICULTY_ADVANCED = "ADVANCED"
DIFFICULTY_RESEARCH = "RESEARCH"

DIFFICULTIES = frozenset(
    {
        DIFFICULTY_EASY,
        DIFFICULTY_MEDIUM,
        DIFFICULTY_ADVANCED,
        DIFFICULTY_RESEARCH,
    }
)

TYPE_DEFAULT_DIFFICULTY: dict[str, str] = {
    TYPE_DOCUMENTATION: DIFFICULTY_EASY,
    TYPE_DOCS: DIFFICULTY_EASY,
    TYPE_DX: DIFFICULTY_EASY,
    TYPE_TEST: DIFFICULTY_EASY,
    TYPE_FALSE_POSITIVE_FIX: DIFFICULTY_MEDIUM,
    TYPE_REGRESSION_TEST: DIFFICULTY_MEDIUM,
    TYPE_BUG_FIX: DIFFICULTY_MEDIUM,
    TYPE_PERFORMANCE: DIFFICULTY_MEDIUM,
    TYPE_SECURITY_RULE: DIFFICULTY_ADVANCED,
    TYPE_RULE: DIFFICULTY_ADVANCED,
    TYPE_FRAMEWORK_SUPPORT: DIFFICULTY_ADVANCED,
    TYPE_ATTACK_PATH_PATTERN: DIFFICULTY_ADVANCED,
    TYPE_NOVEL_FINDING: DIFFICULTY_ADVANCED,
    TYPE_SYNTHETIC_SECURITY_CASE: DIFFICULTY_RESEARCH,
    TYPE_MCP_SECURITY_CASE: DIFFICULTY_RESEARCH,
    TYPE_AI_AGENT: DIFFICULTY_RESEARCH,
}

# ---------------------------------------------------------------------------
# Provenance (contribution / learning pack lifecycle)
# ---------------------------------------------------------------------------
PROVENANCE_LOCAL_ONLY = "LOCAL_ONLY"
PROVENANCE_USER_APPROVED = "USER_APPROVED"
PROVENANCE_SANITIZED = "SANITIZED"
PROVENANCE_VALIDATED = "VALIDATED"
PROVENANCE_DATASET_APPROVED = "DATASET_APPROVED"
PROVENANCE_EXCLUDED = "EXCLUDED"

PROVENANCE_STATES = frozenset(
    {
        PROVENANCE_LOCAL_ONLY,
        PROVENANCE_USER_APPROVED,
        PROVENANCE_SANITIZED,
        PROVENANCE_VALIDATED,
        PROVENANCE_DATASET_APPROVED,
        PROVENANCE_EXCLUDED,
    }
)

# ---------------------------------------------------------------------------
# Quality gate thresholds (opportunity existence — not personal worth)
# ---------------------------------------------------------------------------
QUALITY_MIN_SCORE = 0.65
OPPORTUNITY_MIN_SCORE = 0.55
INVITE_COOLDOWN_SEC = 4 * 3600  # one invite per meaningful session window
MAX_INVITES_PER_SESSION = 1

# ---------------------------------------------------------------------------
# Config defaults (YAML-shaped; local prefs may override)
# ---------------------------------------------------------------------------
DEFAULT_CONTRIBUTIONS_CONFIG: dict[str, Any] = {
    "enabled": True,
    "prompts": True,
    "auto_prepare": False,
    "auto_push": False,
    "auto_pr": False,
    "learning": False,  # opt-in
}

DEFAULT_LEARNING_CONFIG: dict[str, Any] = {
    "contribution_data": {
        "enabled": False,
    }
}

DEFAULT_PRIVACY_CONFIG: dict[str, Any] = {
    "contributions": dict(DEFAULT_CONTRIBUTIONS_CONFIG),
    "learning": dict(DEFAULT_LEARNING_CONFIG),
    "contribute_opt_in": False,
    "learning_opt_in": False,
    "never_prompts": False,
    "dismissed_types": [],
    "version": 1,
}

# Fields included / excluded from local learning export (documented for transparency)
EXPORT_INCLUDED_FIELDS: tuple[str, ...] = (
    "contribution_type",
    "difficulty",
    "language",
    "framework",
    "pattern",
    "flow_summary",
    "missing_control",
    "sanitized_snippet",
    "provenance",
    "quality_scores",
    "created_at",
)

EXPORT_EXCLUDED_FIELDS: tuple[str, ...] = (
    "author_name",
    "author_email",
    "github_login",
    "absolute_paths",
    "private_repo_name",
    "private_org_name",
    "raw_secrets",
    "env_values",
    "tokens",
    "telemetry",
    "ip_address",
    "machine_id",
)

# Local paths
PRIVACY_FILENAME = "privacy.json"
CONTRIBUTE_STATE_FILENAME = "contribute-state.json"
CONTRIBUTE_PACKAGE_DIRNAME = "contribute"

# Phrases that must never appear in contributor recognition / invite copy
FORBIDDEN_CONTRIBUTE_PHRASES: tuple[str, ...] = (
    "you're a legend",
    "you are a legend",
    "rockstar",
    "ninja",
    "guilt",
    "don't let us down",
    "don't miss",
    "limited time",
    "act now",
    "last chance",
    "only you can",
    "top contributor ranking",
    "leaderboard",
    "streak at risk",
    "keep your streak",
    "fake ranking",
    "everyone else already",
    "exclusive community",
    "revolutionary",
)
