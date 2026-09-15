"""Investigation Agent schema — statuses, outcomes, actions, empty factories.

Investigation status is distinct from security verdict / adversary status.
Prefer UNKNOWN over inventing evidence. Repository text is untrusted data.
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

INVESTIGATION_VERSION = "1.0.0"
TOOL_NAME = "axguard"
UNKNOWN = "UNKNOWN"

# ---------------------------------------------------------------------------
# Investigation lifecycle status (not a security verdict)
# ---------------------------------------------------------------------------
STATUS_CREATED = "CREATED"
STATUS_PLANNING = "PLANNING"
STATUS_INVESTIGATING = "INVESTIGATING"
STATUS_WAITING_FOR_EVIDENCE = "WAITING_FOR_EVIDENCE"
STATUS_CHALLENGING = "CHALLENGING"
STATUS_REASSESSING = "REASSESSING"
STATUS_COMPLETED = "COMPLETED"
STATUS_BLOCKED = "BLOCKED"
STATUS_INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"
STATUS_FAILED = "FAILED"

INVESTIGATION_STATUSES = frozenset(
    {
        STATUS_CREATED,
        STATUS_PLANNING,
        STATUS_INVESTIGATING,
        STATUS_WAITING_FOR_EVIDENCE,
        STATUS_CHALLENGING,
        STATUS_REASSESSING,
        STATUS_COMPLETED,
        STATUS_BLOCKED,
        STATUS_INSUFFICIENT_EVIDENCE,
        STATUS_FAILED,
    }
)

# ---------------------------------------------------------------------------
# Final investigation outcomes (distinct from status)
# ---------------------------------------------------------------------------
OUTCOME_VERIFIED = "VERIFIED"
OUTCOME_LIKELY = "LIKELY"
OUTCOME_UNVERIFIED = "UNVERIFIED"
OUTCOME_FALSE_POSITIVE = "FALSE_POSITIVE"
OUTCOME_REQUIRES_REVIEW = "REQUIRES_REVIEW"

INVESTIGATION_OUTCOMES = frozenset(
    {
        OUTCOME_VERIFIED,
        OUTCOME_LIKELY,
        OUTCOME_UNVERIFIED,
        OUTCOME_FALSE_POSITIVE,
        OUTCOME_REQUIRES_REVIEW,
    }
)

# ---------------------------------------------------------------------------
# Action costs
# ---------------------------------------------------------------------------
COST_LOW = "LOW"
COST_MEDIUM = "MEDIUM"
COST_HIGH = "HIGH"
COST_VERY_HIGH = "VERY_HIGH"

COST_WEIGHT = {
    COST_LOW: 1,
    COST_MEDIUM: 3,
    COST_HIGH: 8,
    COST_VERY_HIGH: 20,
}

# ---------------------------------------------------------------------------
# Action types
# ---------------------------------------------------------------------------
ACTION_TRACE_DATA_FLOW = "TRACE_DATA_FLOW"
ACTION_TRACE_CALLERS = "TRACE_CALLERS"
ACTION_TRACE_CALLEES = "TRACE_CALLEES"
ACTION_CHECK_AUTHENTICATION = "CHECK_AUTHENTICATION"
ACTION_CHECK_AUTHORIZATION = "CHECK_AUTHORIZATION"
ACTION_CHECK_TENANT_ISOLATION = "CHECK_TENANT_ISOLATION"
ACTION_CHECK_VALIDATION = "CHECK_VALIDATION"
ACTION_CHECK_SANITIZATION = "CHECK_SANITIZATION"
ACTION_CHECK_PARAMETERIZATION = "CHECK_PARAMETERIZATION"
ACTION_CHECK_CONFIGURATION = "CHECK_CONFIGURATION"
ACTION_CHECK_FRAMEWORK_BEHAVIOR = "CHECK_FRAMEWORK_BEHAVIOR"
ACTION_CHECK_DEPENDENCY = "CHECK_DEPENDENCY"
ACTION_CHECK_REACHABILITY = "CHECK_REACHABILITY"
ACTION_CHECK_TRUST_BOUNDARY = "CHECK_TRUST_BOUNDARY"
ACTION_CHECK_IDENTITY_PROPAGATION = "CHECK_IDENTITY_PROPAGATION"
ACTION_CHECK_TOOL_PERMISSION = "CHECK_TOOL_PERMISSION"
ACTION_CHECK_AGENT_PERMISSION = "CHECK_AGENT_PERMISSION"
ACTION_CHECK_MCP_TRUST = "CHECK_MCP_TRUST"
ACTION_CHECK_ALTERNATE_PATH = "CHECK_ALTERNATE_PATH"
ACTION_SEARCH_COUNTER_EVIDENCE = "SEARCH_COUNTER_EVIDENCE"
ACTION_BUILD_ATTACK_PATH = "BUILD_ATTACK_PATH"
ACTION_CHECK_SECURITY_MEMORY = "CHECK_SECURITY_MEMORY"
ACTION_COMPARE_SECURITY_TWIN = "COMPARE_SECURITY_TWIN"
ACTION_ANALYZE_GIT_CHANGE = "ANALYZE_GIT_CHANGE"

ACTION_TYPES = frozenset(
    {
        ACTION_TRACE_DATA_FLOW,
        ACTION_TRACE_CALLERS,
        ACTION_TRACE_CALLEES,
        ACTION_CHECK_AUTHENTICATION,
        ACTION_CHECK_AUTHORIZATION,
        ACTION_CHECK_TENANT_ISOLATION,
        ACTION_CHECK_VALIDATION,
        ACTION_CHECK_SANITIZATION,
        ACTION_CHECK_PARAMETERIZATION,
        ACTION_CHECK_CONFIGURATION,
        ACTION_CHECK_FRAMEWORK_BEHAVIOR,
        ACTION_CHECK_DEPENDENCY,
        ACTION_CHECK_REACHABILITY,
        ACTION_CHECK_TRUST_BOUNDARY,
        ACTION_CHECK_IDENTITY_PROPAGATION,
        ACTION_CHECK_TOOL_PERMISSION,
        ACTION_CHECK_AGENT_PERMISSION,
        ACTION_CHECK_MCP_TRUST,
        ACTION_CHECK_ALTERNATE_PATH,
        ACTION_SEARCH_COUNTER_EVIDENCE,
        ACTION_BUILD_ATTACK_PATH,
        ACTION_CHECK_SECURITY_MEMORY,
        ACTION_COMPARE_SECURITY_TWIN,
        ACTION_ANALYZE_GIT_CHANGE,
    }
)

# ---------------------------------------------------------------------------
# Budgets
# ---------------------------------------------------------------------------
BUDGET_FAST = "FAST"
BUDGET_BALANCED = "BALANCED"
BUDGET_DEEP = "DEEP"

BUDGETS = frozenset({BUDGET_FAST, BUDGET_BALANCED, BUDGET_DEEP})

# ---------------------------------------------------------------------------
# Evidence hierarchy ranks (lower = stronger) — align with Evidence engine
# ---------------------------------------------------------------------------
EVIDENCE_RANK = {
    "DIRECT_CODE": 0,
    "DATA_FLOW": 1,
    "CONTROL_FLOW": 2,
    "SECURITY_CONTROL": 3,
    "FRAMEWORK_SEMANTICS": 4,
    "CONFIGURATION": 5,
    "DEPENDENCY": 6,
    "STATIC_INFERENCE": 7,
    "LLM_REASONING": 99,
}

# ---------------------------------------------------------------------------
# Termination reasons
# ---------------------------------------------------------------------------
TERM_VERIFIED = "vulnerability_sufficiently_proven"
TERM_COUNTER_EVIDENCE = "strong_counter_evidence"
TERM_INSUFFICIENT = "insufficient_evidence_after_budget"
TERM_STATIC_LIMIT = "remaining_uncertainty_not_static_resolvable"
TERM_COST = "investigation_cost_exceeded"
TERM_CONTROLS = "relevant_controls_verified"
TERM_PATH_BLOCKED = "attack_path_proven_blocked"
TERM_TRUSTWORTHY = "trustworthy_conclusion"
TERM_MEMORY_REUSE = "security_memory_reuse"
TERM_ERROR = "investigation_error"


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _candidate_vuln_type(cand: dict[str, Any]) -> str:
    if cand.get("vulnerability_type"):
        return str(cand["vulnerability_type"])
    root = cand.get("root_cause")
    if isinstance(root, dict) and root.get("kind"):
        return str(root["kind"])
    if cand.get("type"):
        return str(cand["type"])
    return UNKNOWN


def _candidate_file(cand: dict[str, Any]) -> Any:
    loc = cand.get("location")
    if isinstance(loc, dict) and loc.get("file"):
        return loc.get("file")
    return cand.get("file")


def _candidate_symbol(cand: dict[str, Any]) -> Any:
    loc = cand.get("location")
    if isinstance(loc, dict) and loc.get("symbol"):
        return loc.get("symbol")
    return cand.get("symbol")


def new_investigation_id(candidate_id: str = "") -> str:
    digest = hashlib.sha1(
        f"{candidate_id}:{uuid4().hex}".encode("utf-8")
    ).hexdigest()[:12]
    return f"inv.{digest}"


def empty_investigation(
    *,
    candidate: dict[str, Any] | None = None,
    budget: str = BUDGET_BALANCED,
) -> dict[str, Any]:
    """Create a structured Investigation object."""
    cand = dict(candidate or {})
    candidate_id = str(
        cand.get("id")
        or cand.get("finding_id")
        or cand.get("from_judgment_id")
        or UNKNOWN
    )
    return {
        "kind": "security_investigation",
        "schema_version": INVESTIGATION_VERSION,
        "tool": TOOL_NAME,
        "investigation_id": new_investigation_id(candidate_id),
        "candidate_id": candidate_id,
        "candidate": {
            "id": candidate_id,
            "vulnerability_type": _candidate_vuln_type(cand),
            "severity": cand.get("severity"),
            "status": cand.get("status"),
            "confidence": cand.get("confidence"),
            "file": _candidate_file(cand),
            "symbol": _candidate_symbol(cand),
        },
        "status": STATUS_CREATED,
        "budget": budget if budget in BUDGETS else BUDGET_BALANCED,
        "hypothesis": None,
        "hypotheses": [],
        "questions": [],
        "evidence": [],
        "counter_evidence": [],
        "investigations_performed": [],
        "specialists_used": [],
        "unknowns": [],
        "assumptions": [],
        "contradictions": [],
        "attack_paths": [],
        "controls_found": [],
        "confidence_before": str(cand.get("confidence") or UNKNOWN),
        "confidence_after": str(cand.get("confidence") or UNKNOWN),
        "decision": None,
        "reasoning_summary": "",
        "next_action": None,
        "termination_reason": None,
        "cost_spent": 0,
        "actions_spent": 0,
        "graph": {"nodes": [], "edges": []},
        "timeline": [],
        "generated_at": utc_now(),
        "disclaimer": (
            "Symbolic investigation only — no exploitation, network, or "
            "repository code execution. Prefer UNKNOWN over invented facts."
        ),
    }


def empty_action(
    *,
    action_type: str,
    purpose: str,
    question_id: str | None = None,
    cost: str = COST_LOW,
    priority: int = 50,
    inputs: dict[str, Any] | None = None,
    expected_evidence: list[str] | None = None,
    dependencies: list[str] | None = None,
) -> dict[str, Any]:
    return {
        "action_id": f"act.{uuid4().hex[:10]}",
        "type": action_type if action_type in ACTION_TYPES else action_type,
        "purpose": purpose,
        "question_id": question_id,
        "inputs": dict(inputs or {}),
        "expected_evidence": list(expected_evidence or []),
        "cost": cost if cost in COST_WEIGHT else COST_LOW,
        "priority": int(priority),
        "dependencies": list(dependencies or []),
        "result": None,
        "status": "PENDING",
    }


def empty_evidence_item(
    *,
    kind: str,
    summary: str,
    strength: str = "STATIC_INFERENCE",
    supports: str = "hypothesis",
    source: str = "investigation",
    refs: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "evidence_id": f"iev.{uuid4().hex[:10]}",
        "kind": kind,
        "summary": summary,
        "strength": strength if strength in EVIDENCE_RANK else "STATIC_INFERENCE",
        "supports": supports,  # hypothesis | counter | unknown
        "source": source,
        "refs": dict(refs or {}),
        # LLM reasoning cannot create evidence — flag if ever tagged
        "llm_invented": False,
    }


def empty_hypothesis(
    *,
    statement: str,
    kind: str = "primary",
) -> dict[str, Any]:
    return {
        "hypothesis_id": f"hyp.{uuid4().hex[:8]}",
        "kind": kind,  # primary | alternative | control
        "statement": statement,
        "status": "OPEN",  # OPEN | SUPPORTED | REFUTED | UNKNOWN
        "confidence": UNKNOWN,
        "supporting_evidence_ids": [],
        "counter_evidence_ids": [],
    }
