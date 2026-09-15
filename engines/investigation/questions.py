"""Planner question bank — what evidence is still missing?"""

from __future__ import annotations

from typing import Any

from engines.investigation.schema import UNKNOWN

# Stable question ids (planner converts unanswered → actions)
QUESTION_SPECS: list[dict[str, Any]] = [
    {
        "id": "Q_SOURCE_CONTROLLED",
        "text": "Is the source attacker-controlled?",
        "actions": ["TRACE_DATA_FLOW", "CHECK_TRUST_BOUNDARY"],
    },
    {
        "id": "Q_SOURCE_REACHABLE",
        "text": "Is the source reachable?",
        "actions": ["CHECK_REACHABILITY", "TRACE_CALLERS"],
    },
    {
        "id": "Q_SINK_DANGEROUS",
        "text": "Is the sink dangerous?",
        "actions": ["TRACE_CALLEES", "CHECK_FRAMEWORK_BEHAVIOR"],
    },
    {
        "id": "Q_DATA_REACHES_SINK",
        "text": "Does data actually reach the sink?",
        "actions": ["TRACE_DATA_FLOW"],
    },
    {
        "id": "Q_CONTROL_PRESENT",
        "text": "Is there a security control?",
        "actions": ["SEARCH_COUNTER_EVIDENCE", "CHECK_AUTHORIZATION"],
    },
    {
        "id": "Q_CONTROL_BYPASS",
        "text": "Can the control be bypassed?",
        "actions": ["CHECK_ALTERNATE_PATH", "BUILD_ATTACK_PATH"],
    },
    {
        "id": "Q_AUTHZ",
        "text": "Is authorization present?",
        "actions": ["CHECK_AUTHORIZATION", "CHECK_AUTHENTICATION"],
    },
    {
        "id": "Q_TENANT",
        "text": "Is tenant isolation present?",
        "actions": ["CHECK_TENANT_ISOLATION", "CHECK_IDENTITY_PROPAGATION"],
    },
    {
        "id": "Q_CONFIG",
        "text": "Does configuration change the behavior?",
        "actions": ["CHECK_CONFIGURATION"],
    },
    {
        "id": "Q_PATH_REACHABLE",
        "text": "Is the vulnerable path actually reachable?",
        "actions": ["CHECK_REACHABILITY", "BUILD_ATTACK_PATH"],
    },
    {
        "id": "Q_PRIVILEGE",
        "text": "What privilege is required?",
        "actions": ["CHECK_AUTHENTICATION", "CHECK_AGENT_PERMISSION"],
    },
    {
        "id": "Q_ASSET",
        "text": "What asset is affected?",
        "actions": ["COMPARE_SECURITY_TWIN", "BUILD_ATTACK_PATH"],
    },
    {
        "id": "Q_IMPACT",
        "text": "Is there a realistic impact?",
        "actions": ["COMPARE_SECURITY_TWIN", "CHECK_TOOL_PERMISSION"],
    },
    {
        "id": "Q_CONTRADICTIONS",
        "text": "Are there contradictions?",
        "actions": ["SEARCH_COUNTER_EVIDENCE"],
    },
    {
        "id": "Q_UNKNOWNS",
        "text": "What remains unknown?",
        "actions": ["CHECK_SECURITY_MEMORY", "ANALYZE_GIT_CHANGE"],
    },
]


def initial_questions(candidate: dict[str, Any]) -> list[dict[str, Any]]:
    """Seed unanswered questions for a candidate (status OPEN)."""
    _ = candidate
    out: list[dict[str, Any]] = []
    for spec in QUESTION_SPECS:
        out.append(
            {
                "question_id": spec["id"],
                "text": spec["text"],
                "status": "OPEN",  # OPEN | ANSWERED | UNKNOWN
                "answer": None,
                "preferred_actions": list(spec["actions"]),
            }
        )
    return out


def mark_question(
    questions: list[dict[str, Any]],
    question_id: str,
    *,
    status: str,
    answer: Any,
) -> None:
    for q in questions:
        if q.get("question_id") == question_id:
            q["status"] = status
            q["answer"] = answer if answer is not None else UNKNOWN
            return


def unanswered(questions: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [q for q in questions if q.get("status") == "OPEN"]
