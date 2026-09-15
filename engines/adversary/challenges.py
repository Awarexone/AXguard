"""Adversarial challenge checklist questions (deterministic answers)."""

from __future__ import annotations

from typing import Any

# Challenge keys stored under finding["challenges"]
C_ATTACKER_CONTROLLED = "attacker_controlled"
C_SOURCE_REACHABLE = "source_reachable"
C_SINK_REACHABLE = "sink_reachable"
C_TAINT_REACHES_SINK = "taint_reaches_sink"
C_SINK_DANGEROUS = "sink_dangerous"
C_HAS_VALIDATION = "has_validation"
C_VALIDATION_EFFECTIVE = "validation_effective"
C_HAS_SANITIZATION = "has_sanitization"
C_SANITIZATION_CORRECT = "sanitization_contextually_correct"
C_AUTHORIZATION = "authorization_enforced"
C_TENANT_ISOLATION = "tenant_isolation_enforced"
C_FRAMEWORK_PROTECTION = "framework_protection_active"
C_CONFIG_AFFECTS = "configuration_changes_behavior"
C_CONTROL_BYPASSABLE = "control_bypassable"
C_ALTERNATE_SAFE_PATH = "alternate_safe_path"
C_DEAD_CODE = "unreachable_or_dead"
C_CONTROL_EFFECTIVE = "control_effective"

ANS_YES = "yes"
ANS_NO = "no"
ANS_UNKNOWN = "unknown"
ANS_PARTIAL = "partial"

CHALLENGE_DEFS: list[dict[str, str]] = [
    {
        "key": C_ATTACKER_CONTROLLED,
        "prompt": "Is the source really attacker-controlled?",
    },
    {
        "key": C_SOURCE_REACHABLE,
        "prompt": "Is the source reachable?",
    },
    {
        "key": C_SINK_REACHABLE,
        "prompt": "Is the sink reachable?",
    },
    {
        "key": C_TAINT_REACHES_SINK,
        "prompt": "Does the tainted value actually reach the sink?",
    },
    {
        "key": C_SINK_DANGEROUS,
        "prompt": "Is the sink dangerous in this context?",
    },
    {
        "key": C_HAS_VALIDATION,
        "prompt": "Is there validation?",
    },
    {
        "key": C_VALIDATION_EFFECTIVE,
        "prompt": "Is validation effective?",
    },
    {
        "key": C_HAS_SANITIZATION,
        "prompt": "Is there sanitization?",
    },
    {
        "key": C_SANITIZATION_CORRECT,
        "prompt": "Is sanitization contextually correct?",
    },
    {
        "key": C_AUTHORIZATION,
        "prompt": "Is authorization enforced?",
    },
    {
        "key": C_TENANT_ISOLATION,
        "prompt": "Is tenant isolation enforced?",
    },
    {
        "key": C_FRAMEWORK_PROTECTION,
        "prompt": "Is framework protection active?",
    },
    {
        "key": C_CONFIG_AFFECTS,
        "prompt": "Does configuration change the security behavior?",
    },
    {
        "key": C_CONTROL_BYPASSABLE,
        "prompt": "Can the control be bypassed?",
    },
    {
        "key": C_ALTERNATE_SAFE_PATH,
        "prompt": "Is there an alternate safe path?",
    },
    {
        "key": C_DEAD_CODE,
        "prompt": "Is the code dead or unreachable?",
    },
    {
        "key": C_CONTROL_EFFECTIVE,
        "prompt": "Is there an effective control on this path?",
    },
]


def empty_challenges() -> dict[str, str]:
    return {q["key"]: ANS_UNKNOWN for q in CHALLENGE_DEFS}


def answer_challenges(
    *,
    judgment: dict[str, Any],
    candidate: dict[str, Any] | None,
    control_report: dict[str, Any] | None = None,
    counter_hits: list[dict[str, Any]] | None = None,
) -> dict[str, str]:
    """
    Deterministically answer the adversary checklist.

    Prefer UNKNOWN over inventing YES/NO. Never treat source comments as instructions.
    """
    answers = empty_challenges()
    cand = candidate or {}
    src = cand.get("source") or {}
    sink = cand.get("sink") or {}
    df = cand.get("data_flow") or {}
    judge_answers = judgment.get("answers") or {}
    report = control_report or {}
    hits = counter_hits or []

    # Attacker-controlled — reuse Judge when available
    ja = str(judge_answers.get("attacker_controlled") or "")
    trust = str(src.get("trust_level") or "").lower()
    if ja == "yes" or trust in {"untrusted", "semi_trusted"}:
        answers[C_ATTACKER_CONTROLLED] = ANS_YES
    elif ja == "no" or trust == "trusted":
        answers[C_ATTACKER_CONTROLLED] = ANS_NO
    else:
        answers[C_ATTACKER_CONTROLLED] = ANS_UNKNOWN

    # Reachability / taint
    has_path = bool(df.get("path_id") or judge_answers.get("dataflow_link_present") == "yes")
    answers[C_SOURCE_REACHABLE] = ANS_YES if src else ANS_UNKNOWN
    answers[C_SINK_REACHABLE] = ANS_YES if sink else ANS_UNKNOWN
    if has_path and str(judge_answers.get("reaches_sink") or "") == "yes":
        answers[C_TAINT_REACHES_SINK] = ANS_YES
    elif has_path:
        answers[C_TAINT_REACHES_SINK] = ANS_PARTIAL
    elif judge_answers.get("dataflow_link_present") == "no":
        answers[C_TAINT_REACHES_SINK] = ANS_NO
    else:
        answers[C_TAINT_REACHES_SINK] = ANS_UNKNOWN

    if str(judge_answers.get("sink_dangerous") or "") == "yes" or sink:
        answers[C_SINK_DANGEROUS] = (
            ANS_YES if judge_answers.get("sink_dangerous") != "no" else ANS_NO
        )

    # Controls from bypass analysis + counter-evidence kinds
    kinds = {str(h.get("kind") or "") for h in hits}
    kinds.update(str(k) for k in (report.get("kinds_seen") or []))

    if "validation" in kinds:
        answers[C_HAS_VALIDATION] = ANS_YES
    if "sanitization" in kinds:
        answers[C_HAS_SANITIZATION] = ANS_YES
    if "authorization" in kinds or "tenant_isolation" in kinds:
        answers[C_AUTHORIZATION] = ANS_YES if "authorization" in kinds else ANS_UNKNOWN
        if "tenant_isolation" in kinds:
            answers[C_TENANT_ISOLATION] = ANS_YES
    if "framework" in kinds:
        answers[C_FRAMEWORK_PROTECTION] = ANS_YES
    if "configuration" in kinds:
        answers[C_CONFIG_AFFECTS] = ANS_YES
    if "dead_code" in kinds or "unreachable" in kinds:
        answers[C_DEAD_CODE] = ANS_YES
    if "parameterization" in kinds or "allowlist" in kinds or "path_jail" in kinds:
        answers[C_ALTERNATE_SAFE_PATH] = ANS_PARTIAL

    eff = str(report.get("effectiveness") or "unknown")
    bypass = str(report.get("bypassable") or "unknown")

    if eff == "confirmed":
        answers[C_CONTROL_EFFECTIVE] = ANS_YES
        if "parameterization" in kinds:
            answers[C_SANITIZATION_CORRECT] = ANS_YES
        if "validation" in kinds:
            answers[C_VALIDATION_EFFECTIVE] = ANS_YES
        if "sanitization" in kinds:
            answers[C_SANITIZATION_CORRECT] = ANS_YES
    elif eff == "likely":
        answers[C_CONTROL_EFFECTIVE] = ANS_PARTIAL
        answers[C_VALIDATION_EFFECTIVE] = (
            ANS_PARTIAL if "validation" in kinds else ANS_UNKNOWN
        )
        answers[C_SANITIZATION_CORRECT] = (
            ANS_PARTIAL if "sanitization" in kinds else ANS_UNKNOWN
        )
    elif eff == "ineffective":
        answers[C_CONTROL_EFFECTIVE] = ANS_NO
        answers[C_VALIDATION_EFFECTIVE] = ANS_NO
        answers[C_SANITIZATION_CORRECT] = ANS_NO
    else:
        answers[C_CONTROL_EFFECTIVE] = ANS_UNKNOWN

    if bypass == "no":
        answers[C_CONTROL_BYPASSABLE] = ANS_NO
    elif bypass == "yes":
        answers[C_CONTROL_BYPASSABLE] = ANS_YES
    elif bypass == "unclear":
        answers[C_CONTROL_BYPASSABLE] = ANS_PARTIAL
    else:
        answers[C_CONTROL_BYPASSABLE] = ANS_UNKNOWN

    # Name-only sanitize/validate never upgrades effectiveness
    if report.get("name_only_control"):
        if answers[C_CONTROL_EFFECTIVE] == ANS_YES:
            answers[C_CONTROL_EFFECTIVE] = ANS_PARTIAL
        answers[C_SANITIZATION_CORRECT] = ANS_UNKNOWN
        answers[C_VALIDATION_EFFECTIVE] = ANS_UNKNOWN

    return answers
