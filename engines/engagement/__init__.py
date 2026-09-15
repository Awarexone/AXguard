"""AXGuard human-centered engagement engine.

VALUE FIRST → RECOGNITION → STORY → COMMUNITY → OPTIONAL SUPPORT

All state is local. No network calls for stars, metadata, or telemetry.
"""

from __future__ import annotations

from engines.engagement.engine import (
    EngagementResult,
    about_content,
    disable_promo,
    dismiss_support,
    enable_promo,
    record_event,
    render_cli,
    render_html_section,
)
from engines.engagement.hooks import (
    emit_after_audit,
    emit_after_scan,
    emit_first_run_if_needed,
    emit_for_html_footer,
    emit_for_paths,
)
from engines.engagement.messages import EngagementCTA, EngagementMessage, MESSAGE_CATALOG
from engines.engagement.schema import (
    CTA_BUILD,
    CTA_CONTRIBUTE,
    CTA_EXPLORE,
    CTA_KINDS,
    CTA_LEARN,
    CTA_SHARE,
    CTA_SUPPORT,
    EVENT_CONTRIBUTION_DISMISSED,
    EVENT_CONTRIBUTION_SUGGESTED,
    EVENTS,
    GITHUB_URL,
    SIGNATURE,
    STATES,
    SUPPORT_SCORE_THRESHOLD,
)
from engines.engagement.state import DEFAULT_STATE_PATH, default_state, load_state, public_snapshot, save_state

__all__ = [
    # Core API
    "record_event",
    "render_cli",
    "render_html_section",
    "about_content",
    "disable_promo",
    "dismiss_support",
    "enable_promo",
    # CLI / report hooks
    "emit_after_audit",
    "emit_after_scan",
    "emit_for_paths",
    "emit_for_html_footer",
    "emit_first_run_if_needed",
    # Types
    "EngagementResult",
    "EngagementMessage",
    "EngagementCTA",
    "MESSAGE_CATALOG",
    # State helpers
    "DEFAULT_STATE_PATH",
    "default_state",
    "load_state",
    "save_state",
    "public_snapshot",
    # Constants
    "STATES",
    "EVENTS",
    "CTA_KINDS",
    "CTA_EXPLORE",
    "CTA_LEARN",
    "CTA_SUPPORT",
    "CTA_CONTRIBUTE",
    "CTA_SHARE",
    "CTA_BUILD",
    "SUPPORT_SCORE_THRESHOLD",
    "GITHUB_URL",
    "SIGNATURE",
    "EVENT_CONTRIBUTION_SUGGESTED",
    "EVENT_CONTRIBUTION_DISMISSED",
]
