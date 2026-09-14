"""Transparent path prioritization.

Score is a **ranking aid for triage order**, not a new severity system and not
a new confidence system. It is a weighted combination of the documented factors
in ``docs/attack-graph.md`` ("Scoring factors"):

1. Weakest-link confidence (dominant) — from the path status.
2. Hop count / directness — shorter paths to the same asset outrank longer.
3. Asset impact tier — credentials/secrets/admin > PII/financial > internal.
4. Reachability — public unauth > authenticated > internal/queue > prior.
5. Control effectiveness — only genuinely effective controls reduce score.
6. AI/agent multiplier — chains ending in autonomous tool execution rank higher.

The returned ``score`` is in ``[0, 1]`` with a ``factors`` breakdown so a
reader can see exactly why one path outranks another.
"""

from __future__ import annotations

from typing import Any

from engines.attack_graph.schema import (
    AI_AGENT_MULTIPLIER,
    ASSET_IMPACT_TIER,
    REACHABILITY_TIER,
    SCORE_STATUS_WEIGHT,
    SCORE_WEIGHTS,
)


def _asset_impact(chain: dict[str, Any]) -> float:
    target = chain.get("target")
    for n in chain.get("nodes") or []:
        if n.get("id") == target and n.get("type") == "asset":
            return ASSET_IMPACT_TIER.get(str(n.get("kind") or "unknown"), 0.3)
    return 0.3


def _reachability(chain: dict[str, Any]) -> float:
    for n in chain.get("nodes") or []:
        if n.get("id") == chain.get("entry"):
            return REACHABILITY_TIER.get(str(n.get("reachability") or "unknown"), 0.4)
    return 0.4


def _directness(chain: dict[str, Any]) -> float:
    hops = max(1, len(chain.get("edges") or []))
    # 1 hop → 1.0, decaying gently; never below 0.3.
    return max(0.3, 1.0 - 0.1 * (hops - 1))


def score_path(chain: dict[str, Any], status: str) -> dict[str, Any]:
    conf = SCORE_STATUS_WEIGHT.get(status, 0.0)
    asset = _asset_impact(chain)
    reach = _reachability(chain)
    direct = _directness(chain)

    base = (
        SCORE_WEIGHTS["confidence"] * conf
        + SCORE_WEIGHTS["asset_impact"] * asset
        + SCORE_WEIGHTS["reachability"] * reach
        + SCORE_WEIGHTS["directness"] * direct
    )
    multiplier = AI_AGENT_MULTIPLIER if chain.get("ai_agent") else 1.0
    score = round(min(1.0, base * multiplier), 4)
    return {
        "score": score,
        "factors": {
            "confidence": round(conf, 3),
            "asset_impact": round(asset, 3),
            "reachability": round(reach, 3),
            "directness": round(direct, 3),
            "ai_agent_multiplier": multiplier,
        },
    }
