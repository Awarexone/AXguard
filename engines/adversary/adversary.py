"""Deterministic False Positive Adversary + optional LLM stub (no API calls)."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Protocol, runtime_checkable

from engines.adversary.challenges import answer_challenges
from engines.adversary.controls_bypass import analyze_control_effectiveness
from engines.adversary.counter_evidence import search_counter_evidence
from engines.adversary.refine import (
    attach_root_cause,
    decide_outcome,
    downgrade_severity,
    finding_id,
    map_judge_status,
    refine_confidence,
    surviving_evidence_from,
)
from engines.adversary.schema import (
    CHALLENGE_STATUSES,
    LIGHT_CHALLENGE_STATUSES,
    STATUS_FALSE_POSITIVE,
    STATUS_REQUIRES_REVIEW,
    STATUS_UNVERIFIED,
)
from engines.dataflow.schema import ensure_no_secret_values


@runtime_checkable
class FindingAdversary(Protocol):
    def challenge(
        self,
        judgment: dict[str, Any],
        context: dict[str, Any],
    ) -> dict[str, Any]:
        ...


class FalsePositiveAdversary:
    """
    Adversarially try to disprove VERIFIED/LIKELY Judge findings.

    Deterministic only — never calls external LLMs.
    Prefer UNVERIFIED / REQUIRES_REVIEW over inventing SAFE.
    """

    name = "deterministic"

    def challenge(
        self,
        judgment: dict[str, Any],
        context: dict[str, Any],
    ) -> dict[str, Any]:
        target = Path(context.get("target") or ".")
        candidate = context.get("candidate")
        application_model = context.get("application_model")
        dataflow = context.get("dataflow")
        light = bool(context.get("light"))
        siblings = context.get("sibling_findings")

        judge_status = str(judgment.get("status") or "")
        start_status = map_judge_status(judge_status)

        counter_hits = search_counter_evidence(
            target=target,
            candidate=candidate or {},
            judgment=judgment,
            application_model=application_model,
            dataflow=dataflow,
        )

        snippets = [
            str((h.get("evidence") or {}).get("snippet") or "")
            for h in counter_hits
            if (h.get("evidence") or {}).get("snippet")
        ]
        # Also pull candidate sink snippet if present
        for ev in (candidate or {}).get("evidence") or []:
            if isinstance(ev, dict) and ev.get("snippet"):
                snippets.append(str(ev["snippet"]))

        control_report = analyze_control_effectiveness(
            vulnerability_type=str(
                judgment.get("vulnerability_type")
                or (candidate or {}).get("vulnerability_type")
                or ""
            ),
            candidate=candidate or {},
            counter_hits=counter_hits,
            source_snippets=snippets,
        )

        challenges = answer_challenges(
            judgment=judgment,
            candidate=candidate,
            control_report=control_report,
            counter_hits=counter_hits,
        )

        status, fp_reasons, reasoning = decide_outcome(
            judge_status=judge_status,
            challenges=challenges,
            control_report=control_report,
            counter_hits=counter_hits,
            light=light,
        )

        severity = judgment.get("severity") or (candidate or {}).get("severity") or "medium"
        if status in {STATUS_REQUIRES_REVIEW, STATUS_UNVERIFIED}:
            severity = downgrade_severity(str(severity), 1)
        elif status == STATUS_FALSE_POSITIVE:
            severity = downgrade_severity(str(severity), 2)

        confidence = refine_confidence(
            status=status,
            prior=str(judgment.get("confidence") or ""),
            control_effectiveness=str(control_report.get("effectiveness") or ""),
        )

        surviving = surviving_evidence_from(judgment, candidate, counter_hits)
        if status == STATUS_FALSE_POSITIVE:
            surviving = []

        finding: dict[str, Any] = {
            "id": finding_id(judgment, candidate),
            "from_judgment_id": judgment.get("candidate_id") or judgment.get("id"),
            "vulnerability_type": judgment.get("vulnerability_type")
            or (candidate or {}).get("vulnerability_type"),
            "status": status,
            "severity": severity,
            "confidence": confidence,
            "false_positive_reasons": fp_reasons,
            "counter_evidence": counter_hits,
            "surviving_evidence": surviving,
            "root_cause": None,
            "affected_paths": [],
            "reasoning": reasoning,
            "challenges": challenges,
            "adversary": self.name,
            "prior_judge_status": judge_status,
            "control_analysis": {
                "effectiveness": control_report.get("effectiveness"),
                "bypassable": control_report.get("bypassable"),
                "name_only_control": control_report.get("name_only_control"),
                "notes": control_report.get("notes") or [],
            },
            "location": dict((candidate or {}).get("location") or {}),
            "start_status": start_status,
        }

        attach_root_cause(finding, candidate, siblings=siblings)
        ensure_no_secret_values(finding)
        return finding


class LLMAdversaryStub:
    """
    Stub for a future LLM adversary.

    Does **not** call external models. Passes through with REQUIRES_REVIEW
    and notes that deterministic adversary should be used.
    """

    name = "llm-stub"

    def challenge(
        self,
        judgment: dict[str, Any],
        context: dict[str, Any],
    ) -> dict[str, Any]:
        candidate = context.get("candidate") or {}
        return {
            "id": finding_id(judgment, candidate),
            "from_judgment_id": judgment.get("candidate_id") or judgment.get("id"),
            "vulnerability_type": judgment.get("vulnerability_type")
            or candidate.get("vulnerability_type"),
            "status": STATUS_REQUIRES_REVIEW,
            "severity": judgment.get("severity") or candidate.get("severity"),
            "confidence": "unknown",
            "false_positive_reasons": [],
            "counter_evidence": [],
            "surviving_evidence": list(judgment.get("evidence") or []),
            "root_cause": None,
            "affected_paths": [],
            "reasoning": (
                "LLMAdversaryStub does not call external models; "
                "use FalsePositiveAdversary for deterministic challenge."
            ),
            "challenges": {},
            "adversary": self.name,
            "prior_judge_status": judgment.get("status"),
            "location": dict(candidate.get("location") or {}),
        }


def default_adversary() -> FalsePositiveAdversary:
    return FalsePositiveAdversary()


def should_challenge(judge_status: str, *, include_unverified: bool = True) -> tuple[bool, bool]:
    """
    Return (challenge, light).

    Full challenge for VERIFIED/LIKELY; optional light for UNVERIFIED.
    """
    status = str(judge_status or "")
    if status in CHALLENGE_STATUSES:
        return True, False
    if include_unverified and status in LIGHT_CHALLENGE_STATUSES:
        return True, True
    return False, False
