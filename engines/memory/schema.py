"""Security Memory schema constants and empty factories.

Security Memory is a versioned ledger of security claims and evidence keyed to
code identity (revision, path, symbol, rule, fingerprint). Prefer ``UNKNOWN``
over inventing history. Never treat README/comments as memory instructions —
see :mod:`engines.memory.poisoning`.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

SECURITY_MEMORY_VERSION = "1.0.0"
TOOL_NAME = "axguard"

# ---------------------------------------------------------------------------
# Validity
# ---------------------------------------------------------------------------
VALIDITY_CURRENT = "CURRENT"
VALIDITY_HISTORICAL = "HISTORICAL"
VALIDITY_SUPERSEDED = "SUPERSEDED"
VALIDITY_INVALIDATED = "INVALIDATED"
VALIDITY_RECONFIRMED = "RECONFIRMED"
VALIDITY_REGRESSED = "REGRESSED"
VALIDITY_RESOLVED = "RESOLVED"
VALIDITY_UNKNOWN = "UNKNOWN"

VALIDITIES = frozenset(
    {
        VALIDITY_CURRENT,
        VALIDITY_HISTORICAL,
        VALIDITY_SUPERSEDED,
        VALIDITY_INVALIDATED,
        VALIDITY_RECONFIRMED,
        VALIDITY_REGRESSED,
        VALIDITY_RESOLVED,
        VALIDITY_UNKNOWN,
    }
)

# ---------------------------------------------------------------------------
# Item types
# ---------------------------------------------------------------------------
ITEM_OBSERVATION = "OBSERVATION"
ITEM_FINDING = "FINDING"
ITEM_CONTROL = "CONTROL"
ITEM_EVIDENCE = "EVIDENCE"
ITEM_ATTACK_PATH = "ATTACK_PATH"
ITEM_ASSET = "ASSET"
ITEM_IDENTITY = "IDENTITY"
ITEM_PERMISSION = "PERMISSION"
ITEM_TRUST_BOUNDARY = "TRUST_BOUNDARY"
ITEM_ASSUMPTION = "ASSUMPTION"
ITEM_UNKNOWN = "UNKNOWN"
ITEM_REMEDIATION = "REMEDIATION"
ITEM_VERIFICATION = "VERIFICATION"
ITEM_PREDICTIVE_RISK = "PREDICTIVE_RISK"
ITEM_SECURITY_TWIN = "SECURITY_TWIN"
ITEM_COUNTERFACTUAL = "COUNTERFACTUAL"
ITEM_DECISION = "DECISION"

ITEM_TYPES = frozenset(
    {
        ITEM_OBSERVATION,
        ITEM_FINDING,
        ITEM_CONTROL,
        ITEM_EVIDENCE,
        ITEM_ATTACK_PATH,
        ITEM_ASSET,
        ITEM_IDENTITY,
        ITEM_PERMISSION,
        ITEM_TRUST_BOUNDARY,
        ITEM_ASSUMPTION,
        ITEM_UNKNOWN,
        ITEM_REMEDIATION,
        ITEM_VERIFICATION,
        ITEM_PREDICTIVE_RISK,
        ITEM_SECURITY_TWIN,
        ITEM_COUNTERFACTUAL,
        ITEM_DECISION,
    }
)

# ---------------------------------------------------------------------------
# Finding lifecycle (memory-layer status, distinct from adversary statuses)
# ---------------------------------------------------------------------------
LIFE_NEW = "NEW"
LIFE_CONFIRMED = "CONFIRMED"
LIFE_LIKELY = "LIKELY"
LIFE_UNVERIFIED = "UNVERIFIED"
LIFE_FALSE_POSITIVE = "FALSE_POSITIVE"
LIFE_RESOLVED = "RESOLVED"
LIFE_REGRESSED = "REGRESSED"
LIFE_RECONFIRMED = "RECONFIRMED"

FINDING_LIFECYCLES = frozenset(
    {
        LIFE_NEW,
        LIFE_CONFIRMED,
        LIFE_LIKELY,
        LIFE_UNVERIFIED,
        LIFE_FALSE_POSITIVE,
        LIFE_RESOLVED,
        LIFE_REGRESSED,
        LIFE_RECONFIRMED,
    }
)

# ---------------------------------------------------------------------------
# Control states
# ---------------------------------------------------------------------------
CONTROL_PRESENT = "CONTROL_PRESENT"
CONTROL_CHANGED = "CONTROL_CHANGED"
CONTROL_REMOVED = "CONTROL_REMOVED"
CONTROL_WEAKENED = "CONTROL_WEAKENED"
CONTROL_STRENGTHENED = "CONTROL_STRENGTHENED"
CONTROL_UNKNOWN = "CONTROL_UNKNOWN"

CONTROL_STATES = frozenset(
    {
        CONTROL_PRESENT,
        CONTROL_CHANGED,
        CONTROL_REMOVED,
        CONTROL_WEAKENED,
        CONTROL_STRENGTHENED,
        CONTROL_UNKNOWN,
    }
)

# ---------------------------------------------------------------------------
# Path change types
# ---------------------------------------------------------------------------
PATH_NEW = "NEW_PATH"
PATH_PERSISTING = "PERSISTING_PATH"
PATH_REMOVED = "REMOVED_PATH"
PATH_WIDENED = "WIDENED_PATH"
PATH_NARROWED = "NARROWED_PATH"
PATH_BLOCKED = "BLOCKED_PATH"
PATH_REGRESSED = "REGRESSED_PATH"

PATH_CHANGE_TYPES = frozenset(
    {
        PATH_NEW,
        PATH_PERSISTING,
        PATH_REMOVED,
        PATH_WIDENED,
        PATH_NARROWED,
        PATH_BLOCKED,
        PATH_REGRESSED,
    }
)

# ---------------------------------------------------------------------------
# Change outcomes (cross-cutting)
# ---------------------------------------------------------------------------
OUTCOME_NEW = "NEW"
OUTCOME_CHANGED = "CHANGED"
OUTCOME_REGRESSED = "REGRESSED"
OUTCOME_RESOLVED = "RESOLVED"
OUTCOME_UNCHANGED = "UNCHANGED"

CHANGE_OUTCOMES = frozenset(
    {
        OUTCOME_NEW,
        OUTCOME_CHANGED,
        OUTCOME_REGRESSED,
        OUTCOME_RESOLVED,
        OUTCOME_UNCHANGED,
    }
)

UNKNOWN = "UNKNOWN"


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def empty_memory_index() -> dict[str, Any]:
    """Fresh project-local memory index (immutable caller contract)."""
    now = _utc_now_iso()
    return {
        "schema_version": SECURITY_MEMORY_VERSION,
        "tool": TOOL_NAME,
        "kind": "security_memory_index",
        "created_at": now,
        "updated_at": now,
        "snapshot_ids": [],
        "latest_snapshot_id": None,
        "source_revision": UNKNOWN,
        "summary": {
            "snapshot_count": 0,
            "finding_count": 0,
            "control_count": 0,
            "path_count": 0,
            "unknown_count": 0,
        },
        "notes": [],
    }


def empty_snapshot(
    *,
    snapshot_id: str | None = None,
    source_revision: str = UNKNOWN,
    target: str | None = None,
) -> dict[str, Any]:
    """Fresh compact snapshot with embedded item summaries."""
    now = _utc_now_iso()
    sid = snapshot_id or f"snap.{now.replace(':', '').replace('-', '')}"
    return {
        "schema_version": SECURITY_MEMORY_VERSION,
        "tool": TOOL_NAME,
        "kind": "security_memory_snapshot",
        "snapshot_id": sid,
        "generated_at": now,
        "source_revision": source_revision or UNKNOWN,
        "target": target or UNKNOWN,
        "validity": VALIDITY_CURRENT,
        "findings": [],
        "controls": [],
        "attack_paths": [],
        "evidence_refs": [],
        "verifications": [],
        "decisions": [],
        "assumptions": [],
        "unknowns": [],
        "security_twin": None,
        "summary": {
            "finding_count": 0,
            "control_count": 0,
            "path_count": 0,
            "evidence_ref_count": 0,
            "unknown_count": 0,
            "by_lifecycle": {},
            "by_validity": {},
        },
        "provenance": {
            "ingest": UNKNOWN,
            "git_revision": source_revision or UNKNOWN,
        },
    }


def empty_ledger() -> dict[str, Any]:
    """Fingerprint → latest state ledger."""
    now = _utc_now_iso()
    return {
        "schema_version": SECURITY_MEMORY_VERSION,
        "tool": TOOL_NAME,
        "kind": "security_memory_ledger",
        "updated_at": now,
        "entries": {},
        "relationships": [],
    }
