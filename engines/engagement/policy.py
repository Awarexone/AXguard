"""Anti-manipulation policy and priority — security always wins."""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any

from engines.engagement.config import support_threshold
from engines.engagement.messages import EngagementCTA, EngagementMessage
from engines.engagement.schema import (
    COOLDOWN_AFTER_DISMISS_SEC,
    COOLDOWN_ESCALATED_SEC,
    CTA_KINDS,
    CTA_SUPPORT,
    EVENT_FIRST_RUN,
    GITHUB_URL,
    PRIORITY_AWAREXONE,
    PRIORITY_CRITICAL_SECURITY,
    PRIORITY_GITHUB,
    PRIORITY_HIGH_SECURITY,
    PRIORITY_RANK,
    PRIORITY_YC,
    PROMO_PRIORITIES,
    STATE_DISABLED,
    STATE_DISMISSED,
    STATE_FIRST_RUN,
    STATE_NEW_USER,
    STATE_SUPPORT_REQUEST,
)

# Phrases that must never ship in engagement copy
BANNED_PATTERNS: tuple[re.Pattern[str], ...] = tuple(
    re.compile(p, re.IGNORECASE)
    for p in (
        r"\brevolutionary\b",
        r"\bexclusive community\b",
        r"don'?t miss\b",
        r"\blimited time\b",
        r"\bact now\b",
        r"\blast chance\b",
        r"\bonly \d+ users\b",
        r"\byou won'?t believe\b",
        r"\bjoin our .{0,40}ecosystem\b",
        r"\bforce(d)?\s+star\b",
        r"\bgilt[- ]trip\b",
        r"\burgen(t|cy)\b.{0,20}(star|support|follow)",
        r"\bfear of missing\b",
        r"\bYC[- ]accepted\b",
        r"\bYC[- ]funded\b",
        r"\bYC[- ]backed\b",
        r"\bYC[- ]endorsed\b",
    )
)


def _parse_iso(value: str | None) -> datetime | None:
    if not value or not isinstance(value, str):
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def _now() -> datetime:
    return datetime.now(timezone.utc)


def message_text(message: EngagementMessage) -> str:
    return "\n".join(message.body_lines)


def contains_banned_pattern(text: str) -> bool:
    return any(p.search(text) for p in BANNED_PATTERNS)


def reject_if_manipulative(message: EngagementMessage) -> str | None:
    """Return a skip reason if the message violates anti-manipulation rules."""
    text = message_text(message)
    if contains_banned_pattern(text):
        return "banned_pattern"
    if message.cta is not None and message.cta.kind not in CTA_KINDS:
        return "invalid_cta_kind"
    # Never claim YC acceptance/funding in body
    lowered = text.lower()
    for claim in ("yc accepted", "yc funded", "yc backed", "yc endorsed", "yc partnership"):
        if claim in lowered:
            return "yc_claim_forbidden"
    return None


def security_blocks_promo(context: dict[str, Any] | None) -> bool:
    """True when critical/high findings are the primary output — block promo CTAs."""
    ctx = context or {}
    primary = (ctx.get("primary_priority") or ctx.get("output_priority") or "").upper()
    if primary in (PRIORITY_CRITICAL_SECURITY, PRIORITY_HIGH_SECURITY):
        return True
    severity = (ctx.get("max_severity") or ctx.get("severity") or "").upper()
    if severity in ("CRITICAL", "HIGH"):
        return True
    if ctx.get("showing_critical") or ctx.get("showing_high"):
        return True
    critical_count = int(ctx.get("critical_count") or 0)
    high_count = int(ctx.get("high_count") or 0)
    if critical_count > 0 or high_count > 0:
        # Only block when context says these are being shown as primary output
        if ctx.get("security_primary", True):
            return critical_count > 0 or (high_count > 0 and ctx.get("security_primary"))
    return False


def _in_cooldown(state: dict[str, Any]) -> bool:
    last = _parse_iso(state.get("last_support_ask_at"))
    if last is None and int(state.get("support_dismiss_count") or 0) == 0:
        return False
    dismisses = int(state.get("support_dismiss_count") or 0)
    window = COOLDOWN_ESCALATED_SEC if dismisses >= 2 else COOLDOWN_AFTER_DISMISS_SEC
    # Also cool down after a support ask even without dismiss
    if last is None:
        return False
    elapsed = (_now() - last.astimezone(timezone.utc)).total_seconds()
    return elapsed < window


def may_show_promo(
    state: dict[str, Any],
    event: str,
    context: dict[str, Any] | None = None,
) -> bool:
    """Whether promotional / support messaging is allowed for this event."""
    ctx = context or {}

    if state.get("promo_disabled"):
        return False
    if state.get("state") == STATE_DISABLED:
        return False

    # Never ask for star on first install / first run
    if event == EVENT_FIRST_RUN:
        return False
    if state.get("state") in (STATE_NEW_USER, STATE_FIRST_RUN):
        return False
    if not state.get("first_run_shown") and int(state.get("meaningful_sessions") or 0) == 0:
        return False

    if security_blocks_promo(ctx):
        return False

    if _in_cooldown(state):
        return False

    # Need demonstrated value + score threshold
    score = int(state.get("engagement_score") or 0)
    if score < support_threshold(state):
        return False

    if int(state.get("meaningful_sessions") or 0) < 2:
        return False

    return True


def may_show_yc(state: dict[str, Any], context: dict[str, Any] | None = None) -> bool:
    """YC messaging only when explicitly enabled and URL configured — never invent acceptance."""
    if not state.get("yc_messaging_enabled"):
        return False
    if not state.get("yc_url"):
        return False
    if state.get("promo_disabled"):
        return False
    if security_blocks_promo(context):
        return False
    return True


def may_show_social_proof(state: dict[str, Any]) -> bool:
    proof = state.get("social_proof")
    return isinstance(proof, dict) and bool(proof)


def select_cta(
    message: EngagementMessage | None,
    state: dict[str, Any],
    event: str,
    context: dict[str, Any] | None = None,
) -> EngagementCTA | None:
    """Return at most one CTA, stripped when policy forbids promo."""
    if message is None or message.cta is None:
        return None

    cta = message.cta
    ctx = context or {}

    if security_blocks_promo(ctx) and message.priority in PROMO_PRIORITIES:
        return None

    if cta.kind == CTA_SUPPORT:
        if not may_show_promo(state, event, ctx):
            return None
        url = cta.url or GITHUB_URL
        return EngagementCTA(kind=cta.kind, label=cta.label, url=url)

    if message.priority == PRIORITY_YC:
        if not may_show_yc(state, ctx):
            return None

    if message.priority == PRIORITY_AWAREXONE and security_blocks_promo(ctx):
        return None

    return EngagementCTA(kind=cta.kind, label=cta.label, url=cta.url)


def apply_message_policy(
    message: EngagementMessage | None,
    state: dict[str, Any],
    event: str,
    context: dict[str, Any] | None = None,
) -> tuple[EngagementMessage | None, str | None]:
    """Filter/adjust a candidate message. Returns (message_or_none, skip_reason)."""
    if message is None:
        return None, "no_candidate"

    reason = reject_if_manipulative(message)
    if reason:
        return None, reason

    # Dedup recent ids
    if message.id in (state.get("last_message_ids") or []):
        return None, "recent_duplicate"

    ctx = context or {}

    # Block promo priorities when security is primary
    if security_blocks_promo(ctx) and message.priority in PROMO_PRIORITIES:
        return None, "security_blocks_promo"

    if message.priority == PRIORITY_YC and not may_show_yc(state, ctx):
        return None, "yc_not_enabled"

    if message.priority == PRIORITY_GITHUB:
        if not may_show_promo(state, event, ctx):
            return None, "promo_not_allowed"

    cta = select_cta(message, state, event, ctx)
    # If message was support-oriented and CTA stripped, skip the whole promo ask
    if message.priority == PRIORITY_GITHUB and cta is None:
        return None, "support_cta_blocked"

    if cta is not message.cta:
        message = EngagementMessage(
            id=message.id,
            stage=message.stage,
            body_lines=message.body_lines,
            signature=message.signature,
            cta=cta,
            priority=message.priority,
            event=message.event,
        )

    return message, None


def priority_beats(a: str, b: str) -> bool:
    """True if priority ``a`` outranks ``b`` (security-first ordering)."""
    return PRIORITY_RANK.get(a, 99) < PRIORITY_RANK.get(b, 99)


def should_suppress_for_dismissed(state: dict[str, Any], message: EngagementMessage) -> bool:
    if state.get("state") == STATE_DISMISSED and message.priority in (
        PRIORITY_GITHUB,
        PRIORITY_YC,
    ):
        return _in_cooldown(state)
    if state.get("state") == STATE_SUPPORT_REQUEST and _in_cooldown(state):
        return message.priority == PRIORITY_GITHUB
    return False
