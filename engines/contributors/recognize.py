"""Recognition messages tied to observable work — engineer-to-engineer tone.

Calls engagement when appropriate. Never invents praise or rankings.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from engines.contributors.schema import (
    FORBIDDEN_CONTRIBUTE_PHRASES,
    TYPE_LABELS,
)
from engines.contributors.signals import OpportunitySignal, best_opportunity
from engines.engagement.messages import EngagementCTA, EngagementMessage
from engines.engagement.policy import contains_banned_pattern, reject_if_manipulative
from engines.engagement.schema import (
    CTA_CONTRIBUTE,
    EVENT_CONTRIBUTION_SUGGESTED,
    PRIORITY_PRODUCT_INFO,
    SIGNATURE,
    STATE_COMMUNITY_INVITATION,
    STATE_FIRST_MILESTONE,
)


def _assert_clean(text: str) -> None:
    lowered = text.lower()
    for phrase in FORBIDDEN_CONTRIBUTE_PHRASES:
        if phrase in lowered:
            raise ValueError(f"forbidden contribute phrase: {phrase}")
    if contains_banned_pattern(text):
        raise ValueError("banned engagement pattern in recognition copy")


def build_recognition_message(
    context: dict[str, Any] | None = None,
    *,
    signal: OpportunitySignal | None = None,
    with_cta: bool = True,
) -> EngagementMessage | None:
    """Build a recognition message from observable work only."""
    ctx = context or {}
    sig = signal or best_opportunity(ctx)
    if sig is None:
        # Still recognize FP / verified without a typed opportunity
        if int(ctx.get("fp_rejected") or ctx.get("rejected_count") or 0) > 0:
            body = (
                "AXGuard rejected a false positive in this session.",
                "",
                "That control-aware rejection is useful signal — the kind that improves rules and corpus cases.",
            )
            msg = EngagementMessage(
                id="recognize_fp_rejected",
                stage=STATE_FIRST_MILESTONE,
                event=EVENT_CONTRIBUTION_SUGGESTED,
                body_lines=body,
                signature=SIGNATURE,
                cta=(
                    EngagementCTA(
                        kind=CTA_CONTRIBUTE,
                        label="Optional: axguard contribute suggest",
                        url=None,
                    )
                    if with_cta
                    else None
                ),
                priority=PRIORITY_PRODUCT_INFO,
            )
        elif int(ctx.get("verified_count") or 0) > 0 or ctx.get("novel_finding"):
            body = (
                "A finding was verified with evidence in this session.",
                "",
                "If the pattern is reusable, a local contribution package can capture it — only if you want.",
            )
            msg = EngagementMessage(
                id="recognize_verified_finding",
                stage=STATE_FIRST_MILESTONE,
                event=EVENT_CONTRIBUTION_SUGGESTED,
                body_lines=body,
                signature=SIGNATURE,
                cta=(
                    EngagementCTA(
                        kind=CTA_CONTRIBUTE,
                        label="Optional: axguard contribute suggest",
                        url=None,
                    )
                    if with_cta
                    else None
                ),
                priority=PRIORITY_PRODUCT_INFO,
            )
        else:
            return None
    else:
        label = TYPE_LABELS.get(sig.contribution_type, sig.contribution_type)
        body = (
            f"Observable work in this session points to a possible {label} contribution.",
            "",
            sig.reason,
            "",
            "This is optional. You stay in control of prepare, push, and PR.",
        )
        msg = EngagementMessage(
            id=f"recognize_{sig.contribution_type.lower()}",
            stage=STATE_COMMUNITY_INVITATION,
            event=EVENT_CONTRIBUTION_SUGGESTED,
            body_lines=body,
            signature=SIGNATURE,
            cta=(
                EngagementCTA(
                    kind=CTA_CONTRIBUTE,
                    label="Optional: axguard contribute prepare",
                    url=None,
                )
                if with_cta
                else None
            ),
            priority=PRIORITY_PRODUCT_INFO,
        )

    text = "\n".join(msg.body_lines)
    _assert_clean(text)
    if reject_if_manipulative(msg) is not None:
        return None
    return msg


def recognize(
    context: dict[str, Any] | None = None,
    *,
    state_path: Path | None = None,
    call_engagement: bool = True,
) -> EngagementMessage | None:
    """Build recognition and optionally record an engagement event."""
    msg = build_recognition_message(context)
    if msg is None:
        return None
    if call_engagement:
        try:
            from engines.engagement.engine import record_event

            record_event(
                EVENT_CONTRIBUTION_SUGGESTED,
                {
                    **(context or {}),
                    "count_meaningful": False,
                    "recognition_message_id": msg.id,
                },
                state_path=state_path,
            )
        except Exception:  # noqa: BLE001 — recognition must not break callers
            pass
    return msg


# Catalog entries for anti-manipulation tests / introspection
RECOGNIZE_FP = EngagementMessage(
    id="recognize_fp_rejected",
    stage=STATE_FIRST_MILESTONE,
    event=EVENT_CONTRIBUTION_SUGGESTED,
    body_lines=(
        "AXGuard rejected a false positive in this session.",
        "",
        "That control-aware rejection is useful signal — the kind that improves rules and corpus cases.",
    ),
    signature=SIGNATURE,
    cta=EngagementCTA(kind=CTA_CONTRIBUTE, label="Optional: axguard contribute suggest", url=None),
    priority=PRIORITY_PRODUCT_INFO,
)

RECOGNIZE_VERIFIED = EngagementMessage(
    id="recognize_verified_finding",
    stage=STATE_FIRST_MILESTONE,
    event=EVENT_CONTRIBUTION_SUGGESTED,
    body_lines=(
        "A finding was verified with evidence in this session.",
        "",
        "If the pattern is reusable, a local contribution package can capture it — only if you want.",
    ),
    signature=SIGNATURE,
    cta=EngagementCTA(kind=CTA_CONTRIBUTE, label="Optional: axguard contribute suggest", url=None),
    priority=PRIORITY_PRODUCT_INFO,
)

CONTRIBUTE_MESSAGE_CATALOG: dict[str, EngagementMessage] = {
    RECOGNIZE_FP.id: RECOGNIZE_FP,
    RECOGNIZE_VERIFIED.id: RECOGNIZE_VERIFIED,
}
