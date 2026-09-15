"""Human-centered engagement engine — value first, optional support later.

Public API: ``record_event``, render helpers, about/disable/dismiss.
No network calls. Score stays internal.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from html import escape
from pathlib import Path
from typing import Any

from engines.engagement.config import load_configured_state, support_threshold
from engines.engagement.messages import (
    ABOUT_PAGE,
    EngagementMessage,
    select_message,
)
from engines.engagement.policy import (
    apply_message_policy,
    may_show_promo,
    may_show_yc,
)
from engines.engagement.schema import (
    EVENT_ABOUT_VIEWED,
    EVENT_ATTACK_PATH_CONFIRMED,
    EVENT_AUDIT_COMPLETE,
    EVENT_DISABLE_PROMO,
    EVENT_ENABLE_PROMO,
    EVENT_FIRST_RUN,
    EVENT_FIX_VERIFIED,
    EVENT_FP_REJECTED,
    EVENT_HTML_REPORT,
    EVENT_SCAN_COMPLETE,
    EVENT_SESSION_RETURN,
    EVENT_SUPPORT_DISMISSED,
    EVENTS,
    MATURE_SESSION_THRESHOLD,
    SIGNATURE,
    STATE_COMMUNITY_INVITATION,
    STATE_COOLDOWN,
    STATE_DISABLED,
    STATE_DISMISSED,
    STATE_FIRST_MILESTONE,
    STATE_FIRST_RUN,
    STATE_FIRST_VALUE,
    STATE_MATURE_USER,
    STATE_NEW_USER,
    STATE_REPEATED_VALUE,
    STATE_SUPPORT_REQUEST,
)
from engines.engagement.score import apply_event_score
from engines.engagement.state import (
    add_milestone,
    load_state,
    public_snapshot,
    remember_message,
    resolve_state_path,
    save_state,
    update_state,
)


@dataclass(frozen=True)
class EngagementResult:
    """Outcome of ``record_event``.

    ``state_snapshot`` is renderer-safe (no raw engagement_score).
    ``skipped_reason`` explains why no message was shown.
    """

    message: EngagementMessage | None
    state_snapshot: dict[str, Any]
    skipped_reason: str | None = None


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _transition(state: dict[str, Any], event: str, context: dict[str, Any]) -> dict[str, Any]:
    """Advance the journey state machine; returns a new state dict."""
    current = state.get("state") or STATE_NEW_USER
    next_state = update_state(state)

    if event == EVENT_DISABLE_PROMO or context.get("promo_disabled"):
        return update_state(next_state, state=STATE_DISABLED, promo_disabled=True)

    if event == EVENT_ENABLE_PROMO:
        return update_state(
            next_state,
            promo_disabled=False,
            state=STATE_REPEATED_VALUE if int(next_state.get("meaningful_sessions") or 0) >= 2 else STATE_FIRST_VALUE,
        )

    if event == EVENT_SUPPORT_DISMISSED:
        count = int(next_state.get("support_dismiss_count") or 0) + 1
        return update_state(
            next_state,
            state=STATE_DISMISSED,
            support_dismiss_count=count,
            last_support_ask_at=_utc_now_iso(),
        )

    if next_state.get("promo_disabled") or current == STATE_DISABLED:
        return update_state(next_state, state=STATE_DISABLED)

    # Session accounting
    if event == EVENT_SESSION_RETURN:
        sessions = int(next_state.get("sessions") or 0) + 1
        next_state = update_state(
            next_state,
            sessions=sessions,
            last_session_at=_utc_now_iso(),
        )
        if sessions >= MATURE_SESSION_THRESHOLD:
            return update_state(next_state, state=STATE_MATURE_USER)

    if event == EVENT_FIRST_RUN:
        return update_state(next_state, state=STATE_FIRST_RUN, sessions=max(1, int(next_state.get("sessions") or 0)))

    meaningful = event in (
        EVENT_AUDIT_COMPLETE,
        EVENT_SCAN_COMPLETE,
        EVENT_FP_REJECTED,
        EVENT_ATTACK_PATH_CONFIRMED,
        EVENT_FIX_VERIFIED,
        EVENT_HTML_REPORT,
    )

    if meaningful:
        ms = int(next_state.get("meaningful_sessions") or 0)
        # Count at most one meaningful bump per call when marked
        if context.get("count_meaningful", True):
            ms += 1
        next_state = update_state(next_state, meaningful_sessions=ms)

        if current in (STATE_NEW_USER, STATE_FIRST_RUN):
            next_state = update_state(next_state, state=STATE_FIRST_VALUE)
        elif current == STATE_FIRST_VALUE and event in (
            EVENT_FP_REJECTED,
            EVENT_ATTACK_PATH_CONFIRMED,
            EVENT_FIX_VERIFIED,
        ):
            next_state = update_state(next_state, state=STATE_FIRST_MILESTONE)
        elif current == STATE_FIRST_VALUE and ms >= 2:
            next_state = update_state(next_state, state=STATE_FIRST_MILESTONE)
        elif current == STATE_FIRST_MILESTONE and ms >= 3:
            next_state = update_state(next_state, state=STATE_REPEATED_VALUE)
        elif current == STATE_REPEATED_VALUE and ms >= 4:
            next_state = update_state(next_state, state=STATE_COMMUNITY_INVITATION)
        elif current == STATE_COMMUNITY_INVITATION:
            score = int(next_state.get("engagement_score") or 0)
            if score >= support_threshold(next_state) and ms >= 2:
                next_state = update_state(next_state, state=STATE_SUPPORT_REQUEST)
        elif current in (STATE_DISMISSED, STATE_COOLDOWN):
            next_state = update_state(next_state, state=STATE_REPEATED_VALUE)
        elif current == STATE_MATURE_USER:
            pass
        elif current == STATE_SUPPORT_REQUEST:
            next_state = update_state(next_state, state=STATE_COOLDOWN)

        if ms >= MATURE_SESSION_THRESHOLD:
            next_state = update_state(next_state, state=STATE_MATURE_USER)

    # Milestone tags
    if event == EVENT_ATTACK_PATH_CONFIRMED:
        next_state = add_milestone(next_state, "first_attack_path")
    if event == EVENT_FIX_VERIFIED:
        next_state = add_milestone(next_state, "first_remediation")
    if event == EVENT_FP_REJECTED:
        next_state = add_milestone(next_state, "fp_rejected")
    if context.get("verified_count", 0) > 0 or context.get("first_verified"):
        next_state = add_milestone(next_state, "first_verified")

    return next_state


def record_event(
    event: str,
    context: dict[str, Any] | None = None,
    *,
    state_path: Path | None = None,
) -> EngagementResult:
    """Load state → transition → score → pick message → save.

    ``engagement_score`` is persisted but stripped from ``state_snapshot``.
    """
    ctx = dict(context or {})
    path = resolve_state_path(state_path)

    if event not in EVENTS:
        state = load_state(path)
        return EngagementResult(
            message=None,
            state_snapshot=public_snapshot(state),
            skipped_reason="unknown_event",
        )

    state = load_configured_state(path)

    # Preference events short-circuit messaging
    if event == EVENT_DISABLE_PROMO:
        state = _transition(state, event, ctx)
        save_state(state, path)
        return EngagementResult(None, public_snapshot(state), "promo_disabled")

    if event == EVENT_ENABLE_PROMO:
        state = _transition(state, event, ctx)
        save_state(state, path)
        return EngagementResult(None, public_snapshot(state), "promo_enabled")

    if event == EVENT_SUPPORT_DISMISSED:
        state = _transition(state, event, ctx)
        save_state(state, path)
        return EngagementResult(None, public_snapshot(state), "support_dismissed")

    # Score first so transitions can use updated score for support gate
    state = apply_event_score(state, event, ctx)
    state = _transition(state, event, ctx)

    # Mark first-run shown after FIRST_RUN transition
    if event == EVENT_FIRST_RUN:
        state = update_state(state, first_run_shown=True, state=STATE_FIRST_RUN)

    stage = state.get("state") or STATE_NEW_USER
    allow_support = may_show_promo(state, event, ctx)
    allow_yc = may_show_yc(state, ctx)

    # Security primary: still allow non-promo product/analysis messages
    candidate = select_message(
        stage=stage,
        event=event,
        state=state,
        context=ctx,
        allow_support=allow_support,
        allow_yc=allow_yc,
    )

    message, skip = apply_message_policy(candidate, state, event, ctx)

    if message is not None:
        state = remember_message(state, message.id)
        if message.cta and message.cta.kind == "SUPPORT":
            state = update_state(
                state,
                last_support_ask_at=_utc_now_iso(),
                state=STATE_SUPPORT_REQUEST if stage != STATE_DISABLED else stage,
            )
        if event == EVENT_FIRST_RUN:
            state = update_state(state, first_run_shown=True)

    save_state(state, path)

    if message is None:
        return EngagementResult(None, public_snapshot(state), skip or "no_message")

    return EngagementResult(message, public_snapshot(state), None)


def render_cli(message: EngagementMessage | None) -> str:
    """Concise terminal rendering."""
    if message is None:
        return ""
    lines = [line for line in message.body_lines]
    parts: list[str] = []
    body = "\n".join(lines).strip()
    if body:
        parts.append(body)
    if message.signature:
        parts.append(f"- {message.signature}")
    if message.cta is not None:
        label = message.cta.label
        url = message.cta.url
        if url:
            # Prefer short github host form when matching our repo
            display = url.replace("https://", "").replace("http://", "")
            parts.append(f"{label}: {display}" if label else display)
        else:
            parts.append(label)
    return "\n\n".join(parts).rstrip() + ("\n" if parts else "")


def render_html_section(message: EngagementMessage | None, about: bool = False) -> str:
    """Bottom-of-report HTML helper only — never place above security findings."""
    if message is None:
        return ""
    title = "About AXGuard" if about or message.id in ("about_page", "html_about_footer") else "AXGuard"
    body_html = "<br/>\n".join(escape(line) if line else "<br/>" for line in message.body_lines)
    chunks = [
        '<section class="axguard-engagement" data-placement="footer">',
        f"<h2>{escape(title)}</h2>",
        f"<p>{body_html}</p>",
    ]
    if message.signature:
        chunks.append(f"<p class=\"axguard-signature\">— {escape(message.signature)}</p>")
    if message.cta is not None:
        label = escape(message.cta.label)
        if message.cta.url:
            url = escape(message.cta.url, quote=True)
            chunks.append(f'<p class="axguard-cta"><a href="{url}">{label}</a></p>')
        else:
            chunks.append(f'<p class="axguard-cta">{label}</p>')
    chunks.append("</section>")
    return "\n".join(chunks) + "\n"


def about_content(state: dict[str, Any] | None = None) -> EngagementMessage:
    """Content for ``axguard about`` — project story, optional configured YC link."""
    st = state if state is not None else {}
    if st.get("yc_messaging_enabled") and st.get("yc_url") and not st.get("promo_disabled"):
        from engines.engagement.messages import YC_APPLYING, EngagementCTA
        from engines.engagement.schema import CTA_SUPPORT

        return EngagementMessage(
            id=YC_APPLYING.id,
            stage=YC_APPLYING.stage,
            body_lines=YC_APPLYING.body_lines,
            signature=SIGNATURE,
            cta=EngagementCTA(kind=CTA_SUPPORT, label="YC application profile", url=str(st["yc_url"])),
            priority=YC_APPLYING.priority,
            event=EVENT_ABOUT_VIEWED,
        )
    # Soft GitHub CTA is fine on explicit about
    return ABOUT_PAGE


def disable_promo(state_path: Path | None = None) -> EngagementResult:
    """Permanently disable promotional messaging (local preference)."""
    return record_event(EVENT_DISABLE_PROMO, state_path=state_path)


def dismiss_support(state_path: Path | None = None) -> EngagementResult:
    """User dismissed a support ask — start/escalate cooldown."""
    return record_event(EVENT_SUPPORT_DISMISSED, state_path=state_path)


def enable_promo(state_path: Path | None = None) -> EngagementResult:
    """Re-enable promotional messaging."""
    return record_event(EVENT_ENABLE_PROMO, state_path=state_path)
