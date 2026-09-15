"""Engagement engine constants — states, events, CTAs, scores, priorities.

Internal scoring is never shown to users. Security output always outranks
promotional messaging.
"""

from __future__ import annotations

# ---------------------------------------------------------------------------
# Journey states
# ---------------------------------------------------------------------------
STATE_NEW_USER = "NEW_USER"
STATE_FIRST_RUN = "FIRST_RUN"
STATE_FIRST_VALUE = "FIRST_VALUE"
STATE_FIRST_MILESTONE = "FIRST_MILESTONE"
STATE_REPEATED_VALUE = "REPEATED_VALUE"
STATE_COMMUNITY_INVITATION = "COMMUNITY_INVITATION"
STATE_SUPPORT_REQUEST = "SUPPORT_REQUEST"
STATE_COOLDOWN = "COOLDOWN"
STATE_DISABLED = "DISABLED"
STATE_DISMISSED = "DISMISSED"
STATE_MATURE_USER = "MATURE_USER"

STATES = frozenset(
    {
        STATE_NEW_USER,
        STATE_FIRST_RUN,
        STATE_FIRST_VALUE,
        STATE_FIRST_MILESTONE,
        STATE_REPEATED_VALUE,
        STATE_COMMUNITY_INVITATION,
        STATE_SUPPORT_REQUEST,
        STATE_COOLDOWN,
        STATE_DISABLED,
        STATE_DISMISSED,
        STATE_MATURE_USER,
    }
)

# ---------------------------------------------------------------------------
# Events
# ---------------------------------------------------------------------------
EVENT_FIRST_RUN = "FIRST_RUN"
EVENT_AUDIT_COMPLETE = "AUDIT_COMPLETE"
EVENT_SCAN_COMPLETE = "SCAN_COMPLETE"
EVENT_FP_REJECTED = "FP_REJECTED"
EVENT_ATTACK_PATH_CONFIRMED = "ATTACK_PATH_CONFIRMED"
EVENT_FIX_VERIFIED = "FIX_VERIFIED"
EVENT_HTML_REPORT = "HTML_REPORT"
EVENT_ABOUT_VIEWED = "ABOUT_VIEWED"
EVENT_SUPPORT_DISMISSED = "SUPPORT_DISMISSED"
EVENT_DISABLE_PROMO = "DISABLE_PROMO"
EVENT_ENABLE_PROMO = "ENABLE_PROMO"
EVENT_SESSION_RETURN = "SESSION_RETURN"

EVENTS = frozenset(
    {
        EVENT_FIRST_RUN,
        EVENT_AUDIT_COMPLETE,
        EVENT_SCAN_COMPLETE,
        EVENT_FP_REJECTED,
        EVENT_ATTACK_PATH_CONFIRMED,
        EVENT_FIX_VERIFIED,
        EVENT_HTML_REPORT,
        EVENT_ABOUT_VIEWED,
        EVENT_SUPPORT_DISMISSED,
        EVENT_DISABLE_PROMO,
        EVENT_ENABLE_PROMO,
        EVENT_SESSION_RETURN,
    }
)

# ---------------------------------------------------------------------------
# CTA kinds (at most one CTA per message)
# ---------------------------------------------------------------------------
CTA_EXPLORE = "EXPLORE"
CTA_LEARN = "LEARN"
CTA_SUPPORT = "SUPPORT"
CTA_CONTRIBUTE = "CONTRIBUTE"
CTA_SHARE = "SHARE"
CTA_BUILD = "BUILD"

CTA_KINDS = frozenset(
    {
        CTA_EXPLORE,
        CTA_LEARN,
        CTA_SUPPORT,
        CTA_CONTRIBUTE,
        CTA_SHARE,
        CTA_BUILD,
    }
)

# ---------------------------------------------------------------------------
# Internal score weights (never shown to the user)
# ---------------------------------------------------------------------------
SCORE_FIRST_SUCCESS = 10
SCORE_VERIFIED_FINDING = 10
SCORE_FIX_VERIFIED = 15
SCORE_ATTACK_PATH = 15
SCORE_SECOND_SESSION = 15
SCORE_HTML_REPORT = 5
SCORE_MULTIPLE_COMMANDS = 5

SUPPORT_SCORE_THRESHOLD = 40

# ---------------------------------------------------------------------------
# Message priority (security always wins — lower index = higher priority)
# ---------------------------------------------------------------------------
PRIORITY_CRITICAL_SECURITY = "CRITICAL_SECURITY"
PRIORITY_HIGH_SECURITY = "HIGH_SECURITY"
PRIORITY_USER_ACTION = "USER_ACTION"
PRIORITY_ANALYSIS_STATUS = "ANALYSIS_STATUS"
PRIORITY_PRODUCT_INFO = "PRODUCT_INFO"
PRIORITY_PROJECT_STORY = "PROJECT_STORY"
PRIORITY_COMMUNITY = "COMMUNITY"
PRIORITY_GITHUB = "GITHUB"
PRIORITY_AWAREXONE = "AWAREXONE"
PRIORITY_YC = "YC"

PRIORITY_ORDER: tuple[str, ...] = (
    PRIORITY_CRITICAL_SECURITY,
    PRIORITY_HIGH_SECURITY,
    PRIORITY_USER_ACTION,
    PRIORITY_ANALYSIS_STATUS,
    PRIORITY_PRODUCT_INFO,
    PRIORITY_PROJECT_STORY,
    PRIORITY_COMMUNITY,
    PRIORITY_GITHUB,
    PRIORITY_AWAREXONE,
    PRIORITY_YC,
)

PRIORITY_RANK = {name: idx for idx, name in enumerate(PRIORITY_ORDER)}

# Promotional priorities blocked when critical/high security is primary output
PROMO_PRIORITIES = frozenset(
    {
        PRIORITY_GITHUB,
        PRIORITY_AWAREXONE,
        PRIORITY_YC,
        PRIORITY_COMMUNITY,
        PRIORITY_PROJECT_STORY,
    }
)

# ---------------------------------------------------------------------------
# Identity / links
# ---------------------------------------------------------------------------
GITHUB_URL = "https://github.com/Awarexone/AXguard"
SIGNATURE = "ShuvonSec"

# Cooldown defaults (seconds)
COOLDOWN_AFTER_DISMISS_SEC = 7 * 24 * 3600  # 7 days
COOLDOWN_ESCALATED_SEC = 30 * 24 * 3600  # 30 days after repeated dismiss
MATURE_SESSION_THRESHOLD = 10
