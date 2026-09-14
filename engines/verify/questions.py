"""Structured Judge questions checklist (deterministic answers)."""

from __future__ import annotations

from typing import Any

# Canonical question keys stored under judgment["answers"]
Q_ATTACKER_CONTROLLED = "attacker_controlled"
Q_REACHES_SINK = "reaches_sink"
Q_EFFECTIVE_CONTROL = "effective_control"
Q_SINK_DANGEROUS = "sink_dangerous"
Q_COMMENT_OR_FIXTURE = "comment_or_fixture"
Q_CONTRADICTORY = "contradictory_evidence"
Q_PARAMETERIZED = "parameterized_or_bound"
Q_DATAFLOW_LINK = "dataflow_link_present"
Q_TAINT_STATE = "taint_state"

# Answer vocabulary for yes/no/unknown style questions
ANS_YES = "yes"
ANS_NO = "no"
ANS_UNKNOWN = "unknown"
ANS_PARTIAL = "partial"

QUESTION_DEFS: list[dict[str, str]] = [
    {
        "key": Q_ATTACKER_CONTROLLED,
        "prompt": "Is the source attacker-controlled (untrusted / request-like)?",
    },
    {
        "key": Q_DATAFLOW_LINK,
        "prompt": "Is there a Phase 2 taint path linking source to sink?",
    },
    {
        "key": Q_REACHES_SINK,
        "prompt": "Does tainted data reach a dangerous sink?",
    },
    {
        "key": Q_TAINT_STATE,
        "prompt": "What is the dataflow taint_state at the sink?",
    },
    {
        "key": Q_EFFECTIVE_CONTROL,
        "prompt": "Is there an effective control (parameterization/allowlist/sanitization)?",
    },
    {
        "key": Q_PARAMETERIZED,
        "prompt": "Are SQL/query args parameterized or bound near the sink?",
    },
    {
        "key": Q_SINK_DANGEROUS,
        "prompt": "Is the sink class dangerous for this vulnerability type?",
    },
    {
        "key": Q_COMMENT_OR_FIXTURE,
        "prompt": "Is the hit comment-only, fixture bait, or non-executable?",
    },
    {
        "key": Q_CONTRADICTORY,
        "prompt": "Does model/control evidence contradict the hunter claim?",
    },
]


def empty_answers() -> dict[str, str]:
    return {q["key"]: ANS_UNKNOWN for q in QUESTION_DEFS}


def answer_checklist(
    candidate: dict[str, Any],
    *,
    dataflow: dict[str, Any] | None = None,
) -> dict[str, str]:
    """
    Deterministically answer the Judge checklist from candidate + dataflow context.

    Prefer UNKNOWN over inventing YES.
    """
    answers = empty_answers()
    src = candidate.get("source") or {}
    sink = candidate.get("sink") or {}
    df = candidate.get("data_flow") or {}
    evidence = candidate.get("evidence") or []
    loc = candidate.get("location") or {}
    file_s = str(loc.get("file") or sink.get("file") or "").lower()

    # Attacker-controlled
    trust = str(src.get("trust_level") or "").lower()
    kind = str(src.get("kind") or "").lower()
    if trust in {"untrusted", "semi_trusted"} or kind.startswith("request") or kind in {
        "webhook",
        "ai_output",
    }:
        answers[Q_ATTACKER_CONTROLLED] = ANS_YES
    elif trust == "trusted":
        answers[Q_ATTACKER_CONTROLLED] = ANS_NO
    elif src:
        answers[Q_ATTACKER_CONTROLLED] = ANS_UNKNOWN
    else:
        answers[Q_ATTACKER_CONTROLLED] = ANS_UNKNOWN

    # Dataflow link
    path_id = df.get("path_id")
    taint_state = str(df.get("taint_state") or "")
    if path_id and taint_state:
        answers[Q_DATAFLOW_LINK] = ANS_YES
        answers[Q_REACHES_SINK] = ANS_YES
        answers[Q_TAINT_STATE] = taint_state
    else:
        answers[Q_DATAFLOW_LINK] = ANS_NO
        answers[Q_REACHES_SINK] = ANS_UNKNOWN
        answers[Q_TAINT_STATE] = ANS_UNKNOWN

    # Effective control / parameterization from candidate controls + evidence types
    ctrl_ids = [str(c) for c in (candidate.get("controls") or [])]
    ev_types = {str(e.get("type") or "") for e in evidence}
    has_param = "parameterization" in ev_types or any(
        "param" in c.lower() for c in ctrl_ids
    )
    has_allow = "allowlist" in ev_types or any("allow" in c.lower() for c in ctrl_ids)
    has_san = "sanitization" in ev_types or any("sanit" in c.lower() for c in ctrl_ids)
    has_val = "validation" in ev_types

    # Resolve control details from dataflow.controls when available
    flow_controls = (dataflow or {}).get("controls") or []
    matched_ctrls = [
        c
        for c in flow_controls
        if c.get("id") in set(candidate.get("controls") or [])
        or (
            str(c.get("file") or "") == str(sink.get("file") or "")
            and abs(int(c.get("line") or 0) - int(sink.get("line") or 0)) <= 8
        )
    ]
    for c in matched_ctrls:
        kind_c = str(c.get("kind") or "")
        if kind_c == "parameterization":
            has_param = True
        elif kind_c == "allowlist":
            has_allow = True
        elif kind_c == "sanitization":
            has_san = True
        elif kind_c == "validation":
            has_val = True

    answers[Q_PARAMETERIZED] = ANS_YES if has_param else ANS_NO

    if has_param or has_allow:
        # Confirmed-looking control evidence
        eff = any(
            str(c.get("effectiveness") or "") in {"confirmed", "likely"}
            for c in matched_ctrls
        )
        if matched_ctrls and not eff and not (has_param or has_allow):
            answers[Q_EFFECTIVE_CONTROL] = ANS_UNKNOWN
        elif has_param or has_allow or has_san:
            answers[Q_EFFECTIVE_CONTROL] = ANS_YES
        else:
            answers[Q_EFFECTIVE_CONTROL] = ANS_PARTIAL if has_val else ANS_NO
    elif has_san or has_val:
        answers[Q_EFFECTIVE_CONTROL] = ANS_PARTIAL
    elif taint_state in {"SANITIZED", "VALIDATED"}:
        answers[Q_EFFECTIVE_CONTROL] = ANS_YES
    elif taint_state == "PARTIALLY_SANITIZED":
        answers[Q_EFFECTIVE_CONTROL] = ANS_PARTIAL
    elif taint_state == "TAINTED":
        answers[Q_EFFECTIVE_CONTROL] = ANS_NO
    else:
        answers[Q_EFFECTIVE_CONTROL] = ANS_UNKNOWN

    # Sink dangerous for vuln type — hunters only emit matching sinks
    if sink.get("type") or sink.get("symbol"):
        answers[Q_SINK_DANGEROUS] = ANS_YES
    else:
        answers[Q_SINK_DANGEROUS] = ANS_UNKNOWN

    # Comment / fixture false-positive patterns
    if any(
        x in file_s
        for x in ("false_positive", "fixture", "/test", "tests/", "conftest")
    ):
        answers[Q_COMMENT_OR_FIXTURE] = ANS_YES
    elif any(str(e.get("type") or "") == "comment_or_fixture" for e in evidence):
        answers[Q_COMMENT_OR_FIXTURE] = ANS_YES
    else:
        answers[Q_COMMENT_OR_FIXTURE] = ANS_NO

    # Contradiction: hunter claims vuln but controls / sanitized state present
    hunter_claims = candidate.get("confidence") in {"likely", "confirmed"}
    if hunter_claims and (
        taint_state in {"SANITIZED", "VALIDATED", "TRUSTED"}
        or answers[Q_EFFECTIVE_CONTROL] == ANS_YES
        or answers[Q_PARAMETERIZED] == ANS_YES
    ):
        answers[Q_CONTRADICTORY] = ANS_YES
    elif "contradiction" in ev_types:
        answers[Q_CONTRADICTORY] = ANS_YES
    else:
        answers[Q_CONTRADICTORY] = ANS_NO

    return answers
