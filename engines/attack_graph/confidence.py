"""Path confidence & status derivation.

Reuses the Phase 5 confidence vocabulary (``VERY_HIGH … UNKNOWN``) for
``path.confidence_level`` and computes the whole-chain ``status`` from its
weakest hop plus barrier state — never averaged, never invented independently
of the underlying findings.
"""

from __future__ import annotations

from typing import Any

from engines.attack_graph.schema import (
    CONF_UNKNOWN,
    CONFIDENCE_RANK,
    FINDING_STATUS_TO_PATH,
    PATH_BLOCKED,
    PATH_CONFIRMED,
    PATH_INVALID,
    PATH_LIKELY,
    PATH_TIER_RANK,
    PATH_UNVERIFIED,
    SEED_STATUS_TO_CONFIDENCE,
)


def _finding_nodes(chain: dict[str, Any]) -> list[dict[str, Any]]:
    return [n for n in chain.get("nodes") or [] if n.get("type") in {"finding", "candidate_seed"}]


def derive_status(chain: dict[str, Any]) -> tuple[str, list[str]]:
    """Return ``(status, reasons)`` for a chain.

    Order of precedence:
    1. INVALID — any hop finding is FALSE_POSITIVE / co-location-only (hard veto).
    2. BLOCKED — an effective control sits on a required edge, un-bypassed.
    3. weakest-link of the remaining hop statuses (UNVERIFIED < LIKELY < CONFIRMED).
    """
    reasons: list[str] = []
    findings = _finding_nodes(chain)
    if not findings:
        return PATH_UNVERIFIED, ["no finding hop on this chain"]

    hop_tiers: list[str] = []
    for fn in findings:
        tier = FINDING_STATUS_TO_PATH.get(str(fn.get("status") or ""), PATH_UNVERIFIED)
        hop_tiers.append(tier)
        if tier == PATH_INVALID:
            reasons.append(f"hop `{fn.get('label')}` is FALSE_POSITIVE/INVALID — chain vetoed")

    if PATH_INVALID in hop_tiers:
        return PATH_INVALID, reasons

    if chain.get("blocked"):
        blocking = [c for c in chain.get("controls_encountered") or [] if c.get("effectiveness") == "confirmed"]
        reasons.append(
            "effective control on a required edge blocks the unauthenticated path"
            + (f" ({blocking[0]['id']})" if blocking else "")
        )
        return PATH_BLOCKED, reasons

    weakest = min(hop_tiers, key=lambda t: PATH_TIER_RANK.get(t, 2))
    reasons.append(f"weakest hop status → {weakest}")
    return weakest, reasons


def path_confidence_level(chain: dict[str, Any]) -> str:
    """Weakest-link Phase 5 confidence across the chain's finding hops."""
    findings = _finding_nodes(chain)
    if not findings:
        return CONF_UNKNOWN
    levels: list[str] = []
    for fn in findings:
        level = fn.get("confidence_level")
        if not level:
            level = SEED_STATUS_TO_CONFIDENCE.get(str(fn.get("status") or ""), CONF_UNKNOWN)
        levels.append(str(level))
    return min(levels, key=lambda l: CONFIDENCE_RANK.get(l, 0))
