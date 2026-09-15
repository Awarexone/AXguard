"""Quality gate for contribution opportunities.

Only surface strong opportunities: novelty, reusability, relevance, testability.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from engines.contributors.schema import QUALITY_MIN_SCORE
from engines.contributors.signals import OpportunitySignal


@dataclass(frozen=True)
class QualityAssessment:
    passed: bool
    score: float
    novelty: float
    reusability: float
    relevance: float
    testability: float
    reasons: tuple[str, ...]

    def as_dict(self) -> dict[str, Any]:
        return {
            "passed": self.passed,
            "score": round(self.score, 3),
            "novelty": round(self.novelty, 3),
            "reusability": round(self.reusability, 3),
            "relevance": round(self.relevance, 3),
            "testability": round(self.testability, 3),
            "reasons": list(self.reasons),
        }


def _clamp(value: float) -> float:
    return max(0.0, min(1.0, float(value)))


def assess_quality(
    signal: OpportunitySignal,
    context: dict[str, Any] | None = None,
    *,
    min_score: float = QUALITY_MIN_SCORE,
) -> QualityAssessment:
    """Score a single opportunity. Does not rank people."""
    ctx = context or {}
    evidence = signal.evidence or {}

    novelty = 0.35
    if evidence.get("novel") or ctx.get("novel_finding") or ctx.get("first_verified"):
        novelty = 0.85
    elif evidence.get("regression") or ctx.get("regression"):
        novelty = 0.7
    elif evidence.get("rule_gap") or evidence.get("mcp") or evidence.get("ai_agent"):
        novelty = 0.75
    elif int(evidence.get("fp_rejected") or 0) > 0:
        novelty = 0.55

    reusability = 0.4
    ctype = signal.contribution_type
    if ctype in {
        "FALSE_POSITIVE_FIX",
        "REGRESSION_TEST",
        "SECURITY_RULE",
        "ATTACK_PATH_PATTERN",
        "TEST",
        "RULE",
    }:
        reusability = 0.8
    elif ctype in {"DOCUMENTATION", "DOCS", "DX"}:
        reusability = 0.65
    elif ctype in {"MCP_SECURITY_CASE", "SYNTHETIC_SECURITY_CASE", "AI_AGENT", "NOVEL_FINDING"}:
        reusability = 0.7

    relevance = _clamp(0.45 + signal.score * 0.45)
    if ctx.get("security_primary") or ctx.get("verified_count") or ctx.get("fp_rejected"):
        relevance = max(relevance, 0.7)

    testability = 0.4
    if ctype in {"REGRESSION_TEST", "TEST", "FALSE_POSITIVE_FIX", "BUG_FIX"}:
        testability = 0.85
    elif ctype in {"SECURITY_RULE", "RULE", "ATTACK_PATH_PATTERN"}:
        testability = 0.7
    elif ctype in {"DOCUMENTATION", "DOCS", "DX", "PERFORMANCE"}:
        testability = 0.45
    if ctx.get("has_fixture") or ctx.get("testable"):
        testability = max(testability, 0.8)

    score = _clamp(0.25 * novelty + 0.3 * reusability + 0.25 * relevance + 0.2 * testability)
    # Blend with opportunity signal score lightly
    score = _clamp(0.65 * score + 0.35 * signal.score)

    reasons: list[str] = []
    if novelty >= 0.7:
        reasons.append("novel or uncommon pattern relative to typical noise")
    if reusability >= 0.65:
        reasons.append("likely reusable beyond this single repo session")
    if relevance >= 0.65:
        reasons.append("tied to observable security work in this session")
    if testability >= 0.65:
        reasons.append("can be expressed as a test, fixture, or rule case")
    if score < min_score:
        reasons.append("below quality threshold — not surfaced")

    return QualityAssessment(
        passed=score >= min_score,
        score=score,
        novelty=_clamp(novelty),
        reusability=_clamp(reusability),
        relevance=_clamp(relevance),
        testability=_clamp(testability),
        reasons=tuple(reasons),
    )


def filter_strong(
    signals: list[OpportunitySignal],
    context: dict[str, Any] | None = None,
    *,
    min_score: float = QUALITY_MIN_SCORE,
) -> list[tuple[OpportunitySignal, QualityAssessment]]:
    """Return only opportunities that clear the quality gate, best first."""
    out: list[tuple[OpportunitySignal, QualityAssessment]] = []
    for sig in signals:
        qa = assess_quality(sig, context, min_score=min_score)
        if qa.passed:
            out.append((sig, qa))
    out.sort(key=lambda pair: pair[1].score, reverse=True)
    return out
