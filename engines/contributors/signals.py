"""Map observable work → contribution opportunity score + type.

Scores opportunity existence only — never personal worth or ranking.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from engines.contributors.schema import (
    DIFFICULTY_ADVANCED,
    DIFFICULTY_EASY,
    DIFFICULTY_MEDIUM,
    DIFFICULTY_RESEARCH,
    OPPORTUNITY_MIN_SCORE,
    TYPE_AI_AGENT,
    TYPE_ATTACK_PATH_PATTERN,
    TYPE_DOCS,
    TYPE_FALSE_POSITIVE_FIX,
    TYPE_MCP_SECURITY_CASE,
    TYPE_NOVEL_FINDING,
    TYPE_REGRESSION_TEST,
    TYPE_RULE,
    TYPE_SECURITY_RULE,
    TYPE_TEST,
    TYPE_DEFAULT_DIFFICULTY,
)


@dataclass(frozen=True)
class OpportunitySignal:
    """A candidate contribution opportunity derived from local work."""

    contribution_type: str
    score: float
    difficulty: str
    reason: str
    evidence: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {
            "contribution_type": self.contribution_type,
            "score": round(self.score, 3),
            "difficulty": self.difficulty,
            "reason": self.reason,
            "evidence": dict(self.evidence),
        }


def _clamp(value: float) -> float:
    return max(0.0, min(1.0, float(value)))


def _difficulty_for(contribution_type: str) -> str:
    return TYPE_DEFAULT_DIFFICULTY.get(contribution_type, DIFFICULTY_MEDIUM)


def signals_from_context(context: dict[str, Any] | None) -> list[OpportunitySignal]:
    """Derive opportunity signals from audit / adversary / memory context."""
    ctx = context or {}
    signals: list[OpportunitySignal] = []

    fp = int(ctx.get("fp_rejected") or ctx.get("rejected_count") or 0)
    if fp > 0:
        signals.append(
            OpportunitySignal(
                contribution_type=TYPE_FALSE_POSITIVE_FIX,
                score=_clamp(0.55 + min(fp, 5) * 0.08),
                difficulty=_difficulty_for(TYPE_FALSE_POSITIVE_FIX),
                reason="A false positive was correctly rejected — a reusable FP fix or corpus case may help.",
                evidence={"fp_rejected": fp},
            )
        )

    verified = int(ctx.get("verified_count") or 0)
    novel = bool(ctx.get("novel_finding") or ctx.get("first_verified"))
    if verified > 0 and novel:
        signals.append(
            OpportunitySignal(
                contribution_type=TYPE_NOVEL_FINDING,
                score=_clamp(0.6 + min(verified, 3) * 0.1),
                difficulty=_difficulty_for(TYPE_NOVEL_FINDING),
                reason="A verified finding looks novel enough to document as a pattern or rule case.",
                evidence={"verified_count": verified, "novel": True},
            )
        )
    elif verified > 0:
        signals.append(
            OpportunitySignal(
                contribution_type=TYPE_REGRESSION_TEST,
                score=_clamp(0.5 + min(verified, 4) * 0.07),
                difficulty=_difficulty_for(TYPE_REGRESSION_TEST),
                reason="A verified finding can become a regression fixture so it stays covered.",
                evidence={"verified_count": verified},
            )
        )

    if ctx.get("regression") or int(ctx.get("regression_count") or 0) > 0:
        signals.append(
            OpportunitySignal(
                contribution_type=TYPE_REGRESSION_TEST,
                score=_clamp(0.75),
                difficulty=DIFFICULTY_MEDIUM,
                reason="A regression was observed — a focused regression test would lock the fix in.",
                evidence={"regression": True},
            )
        )

    paths = int(ctx.get("attack_paths_confirmed") or 0)
    if paths > 0:
        signals.append(
            OpportunitySignal(
                contribution_type=TYPE_ATTACK_PATH_PATTERN,
                score=_clamp(0.62 + min(paths, 3) * 0.08),
                difficulty=_difficulty_for(TYPE_ATTACK_PATH_PATTERN),
                reason="A confirmed attack path can be captured as a reusable chain pattern.",
                evidence={"attack_paths_confirmed": paths},
            )
        )

    if ctx.get("rule_gap") or ctx.get("missing_rule"):
        signals.append(
            OpportunitySignal(
                contribution_type=TYPE_SECURITY_RULE,
                score=_clamp(0.7),
                difficulty=DIFFICULTY_ADVANCED,
                reason="Observable work suggests a detection gap that a rule could cover.",
                evidence={"rule_gap": True},
            )
        )
    elif ctx.get("rule_candidate"):
        signals.append(
            OpportunitySignal(
                contribution_type=TYPE_RULE,
                score=_clamp(0.58),
                difficulty=DIFFICULTY_ADVANCED,
                reason="A rule refinement candidate was observed in this session.",
                evidence={"rule_candidate": True},
            )
        )

    if ctx.get("test_gap") or ctx.get("missing_test"):
        signals.append(
            OpportunitySignal(
                contribution_type=TYPE_TEST,
                score=_clamp(0.6),
                difficulty=DIFFICULTY_EASY,
                reason="A test gap was observed for a security behavior that already has evidence.",
                evidence={"test_gap": True},
            )
        )

    if ctx.get("docs_gap") or ctx.get("missing_docs"):
        signals.append(
            OpportunitySignal(
                contribution_type=TYPE_DOCS,
                score=_clamp(0.55),
                difficulty=DIFFICULTY_EASY,
                reason="Documentation would clarify a behavior this session already exercised.",
                evidence={"docs_gap": True},
            )
        )

    if ctx.get("mcp") or ctx.get("mcp_finding") or str(ctx.get("domain") or "").upper() == "MCP":
        signals.append(
            OpportunitySignal(
                contribution_type=TYPE_MCP_SECURITY_CASE,
                score=_clamp(0.68),
                difficulty=DIFFICULTY_RESEARCH,
                reason="MCP-related security work can become a shared MCP security case.",
                evidence={"mcp": True},
            )
        )

    if ctx.get("ai_agent") or ctx.get("agent_finding") or str(ctx.get("domain") or "").upper() in {
        "AI_AGENT",
        "AI_SECURITY",
    }:
        signals.append(
            OpportunitySignal(
                contribution_type=TYPE_AI_AGENT,
                score=_clamp(0.66),
                difficulty=DIFFICULTY_RESEARCH,
                reason="AI-agent security behavior observed here could seed a reusable case.",
                evidence={"ai_agent": True},
            )
        )

    # Deduplicate by type — keep highest score
    best: dict[str, OpportunitySignal] = {}
    for sig in signals:
        prev = best.get(sig.contribution_type)
        if prev is None or sig.score > prev.score:
            best[sig.contribution_type] = sig
    return sorted(best.values(), key=lambda s: s.score, reverse=True)


def best_opportunity(
    context: dict[str, Any] | None,
    *,
    min_score: float = OPPORTUNITY_MIN_SCORE,
) -> OpportunitySignal | None:
    ranked = signals_from_context(context)
    for sig in ranked:
        if sig.score >= min_score:
            return sig
    return None
