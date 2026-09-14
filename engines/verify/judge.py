"""Deterministic SecurityJudge + optional LLM Judge stub (no external calls)."""

from __future__ import annotations

from typing import Any, Protocol, runtime_checkable

from engines.verify.evidence import (
    evidence_score,
    has_evidence_type,
    make_evidence,
)
from engines.verify.questions import (
    ANS_NO,
    ANS_PARTIAL,
    ANS_UNKNOWN,
    ANS_YES,
    Q_ATTACKER_CONTROLLED,
    Q_COMMENT_OR_FIXTURE,
    Q_CONTRADICTORY,
    Q_DATAFLOW_LINK,
    Q_EFFECTIVE_CONTROL,
    Q_PARAMETERIZED,
    Q_REACHES_SINK,
    Q_SINK_DANGEROUS,
    Q_TAINT_STATE,
    answer_checklist,
)
from engines.verify.schema import (
    CONFIDENCE_CONFIRMED,
    CONFIDENCE_LIKELY,
    CONFIDENCE_UNKNOWN,
    EV_COMMENT_OR_FIXTURE,
    EV_CONTRADICTION,
    EV_MISSING_LINK,
    EV_PARAMETERIZATION,
    EXPLOIT_CONFIRMED,
    EXPLOIT_LIKELY,
    EXPLOIT_NONE,
    EXPLOIT_UNKNOWN,
    NEXT_FIX,
    NEXT_IGNORE,
    NEXT_MANUAL,
    NEXT_TRIAGE,
    STATUS_FALSE_POSITIVE,
    STATUS_LIKELY,
    STATUS_UNVERIFIED,
    STATUS_VERIFIED,
    VULN_SQL,
)


@runtime_checkable
class SecurityJudge(Protocol):
    def judge(
        self,
        candidate: dict[str, Any],
        *,
        application_model: dict[str, Any] | None = None,
        dataflow: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        ...


class DeterministicJudge:
    """
    Rule / heuristic Judge. Prefer UNVERIFIED over inventing VERIFIED.

    Never calls external LLMs.
    """

    name = "deterministic"

    def judge(
        self,
        candidate: dict[str, Any],
        *,
        application_model: dict[str, Any] | None = None,
        dataflow: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        _ = application_model  # reserved for control/contradiction enrichment
        answers = answer_checklist(candidate, dataflow=dataflow)
        evidence = list(candidate.get("evidence") or [])
        missing: list[str] = []
        fp_reasons: list[str] = []
        reasoning_parts: list[str] = []

        # --- Hard FALSE_POSITIVE gates ---
        if answers[Q_COMMENT_OR_FIXTURE] == ANS_YES:
            evidence.append(
                make_evidence(
                    EV_COMMENT_OR_FIXTURE,
                    file=(candidate.get("location") or {}).get("file"),
                    line=(candidate.get("location") or {}).get("line"),
                    reason="Comment-only / fixture / test path pattern",
                )
            )
            fp_reasons.append("Hit looks like comment-only, fixture, or test bait")
            return self._judgment(
                candidate,
                status=STATUS_FALSE_POSITIVE,
                confidence=CONFIDENCE_LIKELY,
                exploitability=EXPLOIT_NONE,
                evidence=evidence,
                missing=missing,
                answers=answers,
                reasoning="False positive: comment/fixture/test pattern.",
                fp_reasons=fp_reasons,
                next_step=NEXT_IGNORE,
            )

        # Parameterized SQL / bound args near sink
        if (
            candidate.get("vulnerability_type") == VULN_SQL
            and answers[Q_PARAMETERIZED] == ANS_YES
        ):
            evidence.append(
                make_evidence(
                    EV_PARAMETERIZATION,
                    file=(candidate.get("sink") or {}).get("file"),
                    line=(candidate.get("sink") or {}).get("line"),
                    reason="Parameterized / bound SQL arguments near sink",
                )
            )
            fp_reasons.append("Parameterized SQL / bound args near sink")
            return self._judgment(
                candidate,
                status=STATUS_FALSE_POSITIVE,
                confidence=CONFIDENCE_LIKELY,
                exploitability=EXPLOIT_NONE,
                evidence=evidence,
                missing=missing,
                answers=answers,
                reasoning="Downgraded: parameterization evidence near SQL sink.",
                fp_reasons=fp_reasons,
                next_step=NEXT_IGNORE,
            )

        taint = answers.get(Q_TAINT_STATE, ANS_UNKNOWN)
        if taint in {"SANITIZED", "VALIDATED", "TRUSTED"} and answers[
            Q_EFFECTIVE_CONTROL
        ] in {ANS_YES, ANS_PARTIAL}:
            evidence.append(
                make_evidence(
                    EV_CONTRADICTION,
                    reason=f"taint_state={taint} with effective/partial control",
                )
            )
            fp_reasons.append(f"Dataflow taint_state={taint} with control evidence")
            status = (
                STATUS_FALSE_POSITIVE
                if taint in {"SANITIZED", "TRUSTED"} and answers[Q_EFFECTIVE_CONTROL] == ANS_YES
                else STATUS_UNVERIFIED
            )
            return self._judgment(
                candidate,
                status=status,
                confidence=CONFIDENCE_LIKELY if status == STATUS_FALSE_POSITIVE else CONFIDENCE_UNKNOWN,
                exploitability=EXPLOIT_NONE,
                evidence=evidence,
                missing=missing,
                answers=answers,
                reasoning=f"Control/taint evidence suggests mitigated path ({taint}).",
                fp_reasons=fp_reasons,
                next_step=NEXT_IGNORE if status == STATUS_FALSE_POSITIVE else NEXT_MANUAL,
            )

        # Contradictory evidence (hunter vs allowlist/model)
        if answers[Q_CONTRADICTORY] == ANS_YES and answers[Q_EFFECTIVE_CONTROL] == ANS_YES:
            fp_reasons.append("Hunter claim contradicted by allowlist/parameterization")
            return self._judgment(
                candidate,
                status=STATUS_FALSE_POSITIVE,
                confidence=CONFIDENCE_LIKELY,
                exploitability=EXPLOIT_NONE,
                evidence=evidence
                + [
                    make_evidence(
                        EV_CONTRADICTION,
                        reason="Hunter vs control model contradiction",
                    )
                ],
                missing=missing,
                answers=answers,
                reasoning="Contradiction between hunter signal and effective control.",
                fp_reasons=fp_reasons,
                next_step=NEXT_IGNORE,
            )

        # Missing dataflow link → never VERIFIED on pattern alone
        if answers[Q_DATAFLOW_LINK] != ANS_YES:
            evidence.append(
                make_evidence(
                    EV_MISSING_LINK,
                    reason="No Phase 2 taint path; pattern/sink inventory only",
                )
            )
            missing.append("source→sink taint path")
            missing.append("confirmed attacker-controlled reachability")
            reasoning_parts.append("Missing dataflow link — pattern alone is not VERIFIED.")
            return self._judgment(
                candidate,
                status=STATUS_UNVERIFIED,
                confidence=CONFIDENCE_UNKNOWN,
                exploitability=EXPLOIT_UNKNOWN,
                evidence=evidence,
                missing=missing,
                answers=answers,
                reasoning=" ".join(reasoning_parts),
                fp_reasons=fp_reasons,
                next_step=NEXT_MANUAL,
            )

        # Effective control without full SANITIZED → UNVERIFIED or FP soft
        if answers[Q_EFFECTIVE_CONTROL] == ANS_YES:
            fp_reasons.append("Effective control observed on path")
            return self._judgment(
                candidate,
                status=STATUS_FALSE_POSITIVE,
                confidence=CONFIDENCE_LIKELY,
                exploitability=EXPLOIT_NONE,
                evidence=evidence,
                missing=missing,
                answers=answers,
                reasoning="Effective control on path → treat as false positive unless bypass proven.",
                fp_reasons=fp_reasons,
                next_step=NEXT_IGNORE,
            )

        if answers[Q_EFFECTIVE_CONTROL] == ANS_PARTIAL or taint == "PARTIALLY_SANITIZED":
            missing.append("proof that partial control is bypassable")
            return self._judgment(
                candidate,
                status=STATUS_UNVERIFIED,
                confidence=CONFIDENCE_UNKNOWN,
                exploitability=EXPLOIT_UNKNOWN,
                evidence=evidence,
                missing=missing,
                answers=answers,
                reasoning="Partial sanitization/validation — needs manual review.",
                fp_reasons=fp_reasons,
                next_step=NEXT_MANUAL,
            )

        # Positive path: TAINTED + reaches sink + dangerous + no effective control
        if (
            taint == "TAINTED"
            and answers[Q_REACHES_SINK] == ANS_YES
            and answers[Q_SINK_DANGEROUS] == ANS_YES
            and answers[Q_EFFECTIVE_CONTROL] == ANS_NO
        ):
            attacker = answers[Q_ATTACKER_CONTROLLED]
            path_conf = str((candidate.get("data_flow") or {}).get("confidence") or "")
            score = evidence_score(evidence)

            if attacker == ANS_YES and path_conf in {"confirmed", "likely"} and score >= 40:
                return self._judgment(
                    candidate,
                    status=STATUS_VERIFIED,
                    confidence=CONFIDENCE_CONFIRMED
                    if path_conf == "confirmed" and attacker == ANS_YES
                    else CONFIDENCE_LIKELY,
                    exploitability=EXPLOIT_LIKELY
                    if path_conf != "confirmed"
                    else EXPLOIT_CONFIRMED,
                    evidence=evidence,
                    missing=missing,
                    answers=answers,
                    reasoning=(
                        "Tainted untrusted source reaches dangerous sink with no "
                        "effective control (deterministic)."
                    ),
                    fp_reasons=fp_reasons,
                    next_step=NEXT_FIX,
                )

            if attacker in {ANS_YES, ANS_UNKNOWN} and score >= 30:
                if attacker == ANS_UNKNOWN:
                    missing.append("explicit confirmation of attacker control")
                return self._judgment(
                    candidate,
                    status=STATUS_LIKELY,
                    confidence=CONFIDENCE_LIKELY,
                    exploitability=EXPLOIT_LIKELY,
                    evidence=evidence,
                    missing=missing,
                    answers=answers,
                    reasoning=(
                        "Tainted path to dangerous sink without effective control; "
                        "prefer LIKELY over inventing VERIFIED when confidence incomplete."
                    ),
                    fp_reasons=fp_reasons,
                    next_step=NEXT_TRIAGE,
                )

            missing.append("stronger taint/source confidence")
            return self._judgment(
                candidate,
                status=STATUS_LIKELY if attacker == ANS_YES else STATUS_UNVERIFIED,
                confidence=CONFIDENCE_LIKELY if attacker == ANS_YES else CONFIDENCE_UNKNOWN,
                exploitability=EXPLOIT_UNKNOWN,
                evidence=evidence,
                missing=missing,
                answers=answers,
                reasoning="Tainted path present but confidence incomplete.",
                fp_reasons=fp_reasons,
                next_step=NEXT_TRIAGE if attacker == ANS_YES else NEXT_MANUAL,
            )

        # Default: prefer UNVERIFIED
        if not has_evidence_type(evidence, "taint_path"):
            missing.append("taint_path evidence")
        missing.append("complete judge checklist satisfaction")
        return self._judgment(
            candidate,
            status=STATUS_UNVERIFIED,
            confidence=CONFIDENCE_UNKNOWN,
            exploitability=EXPLOIT_UNKNOWN,
            evidence=evidence,
            missing=missing,
            answers=answers,
            reasoning="Insufficient deterministic evidence — UNVERIFIED (not inventing VERIFIED).",
            fp_reasons=fp_reasons,
            next_step=NEXT_MANUAL,
        )

    def _judgment(
        self,
        candidate: dict[str, Any],
        *,
        status: str,
        confidence: str,
        exploitability: str,
        evidence: list[dict[str, Any]],
        missing: list[str],
        answers: dict[str, str],
        reasoning: str,
        fp_reasons: list[str],
        next_step: str,
    ) -> dict[str, Any]:
        return {
            "candidate_id": candidate.get("id"),
            "status": status,
            "confidence": confidence,
            "severity": candidate.get("severity"),
            "exploitability": exploitability,
            "evidence": evidence,
            "missing_evidence": missing,
            "reasoning": reasoning,
            "false_positive_reasons": fp_reasons,
            "answers": answers,
            "recommended_next_step": next_step,
            "judge": self.name,
            "vulnerability_type": candidate.get("vulnerability_type"),
        }


class LLMJudgeStub:
    """
    Stub interface for a future LLM Judge.

    Does **not** call external LLMs. Always returns UNVERIFIED and points
    callers at DeterministicJudge.
    """

    name = "llm-stub"

    def judge(
        self,
        candidate: dict[str, Any],
        *,
        application_model: dict[str, Any] | None = None,
        dataflow: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        _ = (application_model, dataflow)
        return {
            "candidate_id": candidate.get("id"),
            "status": STATUS_UNVERIFIED,
            "confidence": CONFIDENCE_UNKNOWN,
            "severity": candidate.get("severity"),
            "exploitability": EXPLOIT_UNKNOWN,
            "evidence": list(candidate.get("evidence") or []),
            "missing_evidence": [
                "LLM Judge not enabled — use DeterministicJudge",
            ],
            "reasoning": (
                "LLMJudgeStub does not call external models; "
                "no verification performed."
            ),
            "false_positive_reasons": [],
            "answers": {},
            "recommended_next_step": NEXT_MANUAL,
            "judge": self.name,
            "vulnerability_type": candidate.get("vulnerability_type"),
        }


def default_judge() -> DeterministicJudge:
    return DeterministicJudge()
