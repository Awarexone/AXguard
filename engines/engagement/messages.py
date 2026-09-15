"""Contextual message catalog — ShuvonSec voice, not marketing spam.

Variants are selected by event/context, not random rotation.
Every message: body lines, optional signature, at most one CTA.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from engines.engagement.schema import (
    CTA_CONTRIBUTE,
    CTA_EXPLORE,
    CTA_LEARN,
    CTA_SUPPORT,
    EVENT_ABOUT_VIEWED,
    EVENT_ATTACK_PATH_CONFIRMED,
    EVENT_AUDIT_COMPLETE,
    EVENT_FIRST_RUN,
    EVENT_FIX_VERIFIED,
    EVENT_FP_REJECTED,
    EVENT_HTML_REPORT,
    EVENT_SCAN_COMPLETE,
    EVENT_SESSION_RETURN,
    GITHUB_URL,
    PRIORITY_ANALYSIS_STATUS,
    PRIORITY_AWAREXONE,
    PRIORITY_COMMUNITY,
    PRIORITY_GITHUB,
    PRIORITY_PRODUCT_INFO,
    PRIORITY_PROJECT_STORY,
    PRIORITY_YC,
    SIGNATURE,
    STATE_COMMUNITY_INVITATION,
    STATE_FIRST_MILESTONE,
    STATE_FIRST_RUN,
    STATE_FIRST_VALUE,
    STATE_REPEATED_VALUE,
    STATE_SUPPORT_REQUEST,
)


@dataclass(frozen=True)
class EngagementCTA:
    kind: str
    label: str
    url: str | None = None


@dataclass(frozen=True)
class EngagementMessage:
    id: str
    stage: str
    body_lines: tuple[str, ...]
    signature: str | None = SIGNATURE
    cta: EngagementCTA | None = None
    priority: str = PRIORITY_PRODUCT_INFO
    event: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "stage": self.stage,
            "body_lines": list(self.body_lines),
            "signature": self.signature,
            "cta": (
                {"kind": self.cta.kind, "label": self.cta.label, "url": self.cta.url}
                if self.cta
                else None
            ),
            "priority": self.priority,
            "event": self.event,
        }


def _cta(kind: str, label: str, url: str | None = None) -> EngagementCTA:
    return EngagementCTA(kind=kind, label=label, url=url)


# ---------------------------------------------------------------------------
# Catalog entries (keyed conceptually by stage / event)
# ---------------------------------------------------------------------------

FIRST_RUN_INTRO = EngagementMessage(
    id="first_run_intro",
    stage=STATE_FIRST_RUN,
    event=EVENT_FIRST_RUN,
    body_lines=(
        "AXGuard is built by AwareXone.",
        "",
        "We are building open-source security tools for the AI era.",
        "",
        "The idea is simple:",
        "Find → Explain → Fix → Verify.",
    ),
    signature=SIGNATURE,
    cta=None,
    priority=PRIORITY_PROJECT_STORY,
)

FIRST_VALUE_STORY = EngagementMessage(
    id="first_value_story",
    stage=STATE_FIRST_VALUE,
    event=EVENT_AUDIT_COMPLETE,
    body_lines=(
        "You just saw what we are building.",
        "",
        "AI can write the application.",
        "AXGuard tries to make sure it does not quietly ship the vulnerability.",
    ),
    signature=SIGNATURE,
    cta=None,
    priority=PRIORITY_PRODUCT_INFO,
)

FP_REJECTED = EngagementMessage(
    id="fp_rejected",
    stage=STATE_FIRST_MILESTONE,
    event=EVENT_FP_REJECTED,
    body_lines=(
        "AXGuard rejected this finding.",
        "",
        "The code looked dangerous at first, but the authorization control made the path safe.",
        "",
        "This is one of the things we care about most:",
        "knowing when NOT to report.",
    ),
    signature=SIGNATURE,
    cta=_cta(CTA_LEARN, "See why AXGuard rejected this finding."),
    priority=PRIORITY_PRODUCT_INFO,
)

ATTACK_PATH = EngagementMessage(
    id="attack_path_confirmed",
    stage=STATE_FIRST_MILESTONE,
    event=EVENT_ATTACK_PATH_CONFIRMED,
    body_lines=(
        "AXGuard connected separate steps into one attack path.",
        "",
        "The interesting part was not finding each bug.",
        "It was proving how they could be chained.",
    ),
    signature=SIGNATURE,
    cta=None,
    priority=PRIORITY_ANALYSIS_STATUS,
)

FIX_VERIFIED = EngagementMessage(
    id="fix_verified",
    stage=STATE_FIRST_MILESTONE,
    event=EVENT_FIX_VERIFIED,
    body_lines=(
        "Fixed and verified.",
        "",
        "That is the entire idea behind AXGuard:",
        "don't just find the problem.",
        "Prove that the fix actually worked.",
    ),
    signature=SIGNATURE,
    cta=None,
    priority=PRIORITY_PRODUCT_INFO,
)

REPEATED_VALUE_STAR = EngagementMessage(
    id="repeated_value_star",
    stage=STATE_SUPPORT_REQUEST,
    event=EVENT_AUDIT_COMPLETE,
    body_lines=(
        "You have used AXGuard across several analyses now.",
        "",
        "If you think this project is worth building further, a GitHub star helps other security engineers discover it.",
    ),
    signature=SIGNATURE,
    cta=_cta(CTA_SUPPORT, "Star AXGuard on GitHub", GITHUB_URL),
    priority=PRIORITY_GITHUB,
)

COMMUNITY_BELONGING = EngagementMessage(
    id="community_belonging",
    stage=STATE_COMMUNITY_INVITATION,
    event=EVENT_AUDIT_COMPLETE,
    body_lines=(
        "Every useful bug report, rule, test case, and contribution makes AXGuard better.",
        "",
        "You are now part of that feedback loop.",
    ),
    signature=SIGNATURE,
    cta=_cta(CTA_CONTRIBUTE, "Open an issue if a rule mishandled a case", GITHUB_URL),
    priority=PRIORITY_COMMUNITY,
)

COMMUNITY_OPEN_SOURCE = EngagementMessage(
    id="community_open_source",
    stage=STATE_COMMUNITY_INVITATION,
    event=EVENT_SCAN_COMPLETE,
    body_lines=(
        "Security tooling gets better when security engineers share what actually works.",
        "",
        "That is why AXGuard is open source.",
    ),
    signature=SIGNATURE,
    cta=None,
    priority=PRIORITY_COMMUNITY,
)

CURIOSITY_ATTACK_PATH = EngagementMessage(
    id="curiosity_attack_path",
    stage=STATE_FIRST_VALUE,
    event=EVENT_SCAN_COMPLETE,
    body_lines=(
        "One interesting thing AXGuard can do is follow a vulnerability beyond the first suspicious line.",
        "",
        "Try the attack-path analysis when you want to see how the pieces connect.",
    ),
    signature=SIGNATURE,
    cta=_cta(CTA_EXPLORE, "Try attack-path analysis."),
    priority=PRIORITY_PRODUCT_INFO,
)

MILESTONE_FIRST_VERIFIED = EngagementMessage(
    id="milestone_first_verified",
    stage=STATE_FIRST_MILESTONE,
    event=EVENT_AUDIT_COMPLETE,
    body_lines=(
        "First verified finding.",
        "",
        "AXGuard did not just flag it.",
        "It built the evidence chain.",
    ),
    signature=SIGNATURE,
    cta=None,
    priority=PRIORITY_PRODUCT_INFO,
)

MILESTONE_FIRST_ATTACK_PATH = EngagementMessage(
    id="milestone_first_attack_path",
    stage=STATE_FIRST_MILESTONE,
    event=EVENT_ATTACK_PATH_CONFIRMED,
    body_lines=(
        "First attack path confirmed.",
        "",
        "Now we are getting beyond isolated findings and into how vulnerabilities actually combine.",
    ),
    signature=SIGNATURE,
    cta=None,
    priority=PRIORITY_PRODUCT_INFO,
)

MILESTONE_FIRST_REMEDIATION = EngagementMessage(
    id="milestone_first_remediation",
    stage=STATE_FIRST_MILESTONE,
    event=EVENT_FIX_VERIFIED,
    body_lines=(
        "Fix verified.",
        "",
        "Finding the bug is only half the job.",
    ),
    signature=SIGNATURE,
    cta=None,
    priority=PRIORITY_PRODUCT_INFO,
)

SESSION_RETURN = EngagementMessage(
    id="session_return",
    stage=STATE_REPEATED_VALUE,
    event=EVENT_SESSION_RETURN,
    body_lines=(
        "Back again.",
        "",
        "That is usually a good sign for a security tool.",
    ),
    signature=SIGNATURE,
    cta=None,
    priority=PRIORITY_PRODUCT_INFO,
)

AWAREXONE_STORY = EngagementMessage(
    id="awarexone_story",
    stage=STATE_FIRST_VALUE,
    event=EVENT_AUDIT_COMPLETE,
    body_lines=(
        "AXGuard is one of the open-source security projects from AwareXone.",
        "",
        "We are building security tools for the AI era.",
    ),
    signature=SIGNATURE,
    cta=None,
    priority=PRIORITY_AWAREXONE,
)

FOUNDER_GAP = EngagementMessage(
    id="founder_gap",
    stage=STATE_REPEATED_VALUE,
    event=EVENT_AUDIT_COMPLETE,
    body_lines=(
        "AI made writing software much faster.",
        "",
        "It did not make securing that software faster.",
        "",
        "That is the gap we are trying to close.",
    ),
    signature=SIGNATURE,
    cta=None,
    priority=PRIORITY_PROJECT_STORY,
)

FOUNDER_PROVE_IT = EngagementMessage(
    id="founder_prove_it",
    stage=STATE_FIRST_VALUE,
    event=EVENT_SCAN_COMPLETE,
    body_lines=(
        "Security scanners are very good at saying 'this looks bad.'",
        "",
        "We want AXGuard to answer a harder question:",
        "",
        "'Can you prove it?'",
    ),
    signature=SIGNATURE,
    cta=None,
    priority=PRIORITY_PROJECT_STORY,
)

ABOUT_PAGE = EngagementMessage(
    id="about_page",
    stage="ABOUT",
    event=EVENT_ABOUT_VIEWED,
    body_lines=(
        "AXGuard — pre-ship security gate.",
        "",
        "Built by AwareXone / ShuvonSec and contributors.",
        "",
        "Find → Explain → Fix → Verify.",
        "",
        "Open source. Local analysis. No telemetry for marketing.",
    ),
    signature=SIGNATURE,
    cta=_cta(CTA_SUPPORT, "GitHub", GITHUB_URL),
    priority=PRIORITY_PROJECT_STORY,
)

YC_APPLYING = EngagementMessage(
    id="yc_applying",
    stage=STATE_SUPPORT_REQUEST,
    event=EVENT_ABOUT_VIEWED,
    body_lines=(
        "Building AXGuard at Awarexone.",
        "",
        "We are also applying to YC as we build this in public.",
        "",
        "If the idea resonates with you, supporting the project helps us reach more builders.",
    ),
    signature=SIGNATURE,
    cta=None,  # URL filled from configured yc_url when selected
    priority=PRIORITY_YC,
)

RECIPROCITY_SOFT_STAR = EngagementMessage(
    id="reciprocity_soft_star",
    stage=STATE_SUPPORT_REQUEST,
    event=EVENT_HTML_REPORT,
    body_lines=(
        "If this saved you some time, a GitHub star helps the project grow.",
    ),
    signature=SIGNATURE,
    cta=_cta(CTA_SUPPORT, "Star on GitHub", GITHUB_URL),
    priority=PRIORITY_GITHUB,
)

HTML_ABOUT_FOOTER = EngagementMessage(
    id="html_about_footer",
    stage="ABOUT",
    event=EVENT_HTML_REPORT,
    body_lines=(
        "About AXGuard",
        "",
        "Built by Awarexone.",
        "Built by ShuvonSec and contributors.",
    ),
    signature=SIGNATURE,
    cta=_cta(CTA_SUPPORT, "GitHub", GITHUB_URL),
    priority=PRIORITY_PROJECT_STORY,
)

# Contextual SSRF / dataflow variants (selected by context.variant / finding_class)
VARIANT_SSRF_PROVED = EngagementMessage(
    id="variant_ssrf_proved",
    stage=STATE_FIRST_MILESTONE,
    event=EVENT_ATTACK_PATH_CONFIRMED,
    body_lines=("AXGuard proved the SSRF path.",),
    signature=SIGNATURE,
    priority=PRIORITY_ANALYSIS_STATUS,
)

VARIANT_SSRF_FLOW = EngagementMessage(
    id="variant_ssrf_flow",
    stage=STATE_FIRST_MILESTONE,
    event=EVENT_ATTACK_PATH_CONFIRMED,
    body_lines=(
        "The SSRF was not just suspicious.",
        "The data flow confirmed the path.",
    ),
    signature=SIGNATURE,
    priority=PRIORITY_ANALYSIS_STATUS,
)

VARIANT_SSRF_CHAIN = EngagementMessage(
    id="variant_ssrf_chain",
    stage=STATE_FIRST_MILESTONE,
    event=EVENT_ATTACK_PATH_CONFIRMED,
    body_lines=(
        "Source → validation → network sink.",
        "AXGuard confirmed the chain.",
    ),
    signature=SIGNATURE,
    priority=PRIORITY_ANALYSIS_STATUS,
)

CONTROL_MATTERS = EngagementMessage(
    id="control_matters",
    stage=STATE_FIRST_MILESTONE,
    event=EVENT_FP_REJECTED,
    body_lines=(
        "AXGuard found the suspicious code.",
        "",
        "Then it found the control that made it safe.",
        "",
        "That second part matters.",
    ),
    signature=SIGNATURE,
    priority=PRIORITY_PRODUCT_INFO,
)


def _with_cta(msg: EngagementMessage, cta: EngagementCTA | None) -> EngagementMessage:
    return EngagementMessage(
        id=msg.id,
        stage=msg.stage,
        body_lines=msg.body_lines,
        signature=msg.signature,
        cta=cta,
        priority=msg.priority,
        event=msg.event,
    )


def _with_body(
    msg: EngagementMessage,
    body_lines: tuple[str, ...],
    *,
    message_id: str | None = None,
) -> EngagementMessage:
    return EngagementMessage(
        id=message_id or msg.id,
        stage=msg.stage,
        body_lines=body_lines,
        signature=msg.signature,
        cta=msg.cta,
        priority=msg.priority,
        event=msg.event,
    )


def reciprocity_summary(context: dict[str, Any]) -> EngagementMessage | None:
    """Build a value-first summary when analysis stats are present — no invented numbers."""
    files = context.get("files_analyzed")
    flows = context.get("data_flows")
    reviewed = context.get("candidates_reviewed")
    verified = context.get("verified_count")
    rejected = context.get("rejected_count")
    parts: list[str] = []
    if isinstance(files, int) and files >= 0:
        parts.append(f"{files} files analyzed")
    if isinstance(flows, int) and flows >= 0:
        parts.append(f"{flows} data flows traced")
    if isinstance(reviewed, int) and reviewed >= 0:
        parts.append(f"{reviewed} candidates reviewed")
    if isinstance(verified, int) and verified >= 0:
        parts.append(f"{verified} verified")
    if isinstance(rejected, int) and rejected >= 0:
        parts.append(f"{rejected} rejected")
    if not parts:
        return None
    lines = ("AXGuard completed.", "", *parts)
    return EngagementMessage(
        id="analysis_summary",
        stage=STATE_FIRST_VALUE,
        event=EVENT_AUDIT_COMPLETE,
        body_lines=tuple(lines),
        signature=None,
        cta=None,
        priority=PRIORITY_ANALYSIS_STATUS,
    )


def social_proof_message(state: dict[str, Any]) -> EngagementMessage | None:
    """Only when state.social_proof is explicitly configured with factual keys."""
    proof = state.get("social_proof")
    if not isinstance(proof, dict) or not proof:
        return None
    lines: list[str] = []
    if "community_note" in proof and isinstance(proof["community_note"], str):
        lines.append(proof["community_note"])
    else:
        # Factual fragments only from configured keys — no fabricated claims
        bits: list[str] = []
        if "contributors" in proof:
            bits.append(f"contributors: {proof['contributors']}")
        if "releases" in proof:
            bits.append(f"releases: {proof['releases']}")
        if "github_stars" in proof:
            bits.append(f"GitHub stars: {proof['github_stars']}")
        if "supported_agents" in proof:
            bits.append(f"supported agents: {proof['supported_agents']}")
        if "projects_using" in proof:
            bits.append(f"projects using AXGuard: {proof['projects_using']}")
        if not bits:
            return None
        lines.append("AXGuard is open source.")
        lines.append("")
        lines.extend(bits)
    return EngagementMessage(
        id="social_proof_configured",
        stage=STATE_COMMUNITY_INVITATION,
        body_lines=tuple(lines),
        signature=SIGNATURE,
        cta=None,
        priority=PRIORITY_COMMUNITY,
    )


def select_message(
    *,
    stage: str,
    event: str,
    state: dict[str, Any],
    context: dict[str, Any] | None = None,
    allow_support: bool = False,
    allow_yc: bool = False,
) -> EngagementMessage | None:
    """Pick one contextual message for stage/event — not random spam."""
    ctx = context or {}
    seen = set(state.get("last_message_ids") or [])
    milestones = set(state.get("milestones_seen") or [])

    # Explicit about
    if event == EVENT_ABOUT_VIEWED:
        if allow_yc and state.get("yc_messaging_enabled") and state.get("yc_url"):
            return _with_cta(
                YC_APPLYING,
                _cta(CTA_SUPPORT, "YC application profile", str(state["yc_url"])),
            )
        return ABOUT_PAGE

    # First run — once
    if event == EVENT_FIRST_RUN or (stage == STATE_FIRST_RUN and not state.get("first_run_shown")):
        return FIRST_RUN_INTRO

    # FP rejected variants
    if event == EVENT_FP_REJECTED:
        if ctx.get("variant") == "control_matters" or "fp_rejected" in seen:
            return CONTROL_MATTERS
        return FP_REJECTED

    # Attack path + SSRF contextual variants
    if event == EVENT_ATTACK_PATH_CONFIRMED:
        finding = (ctx.get("finding_class") or ctx.get("variant") or "").lower()
        if "ssrf" in finding:
            variant = ctx.get("variant") or "proved"
            if variant == "flow":
                return VARIANT_SSRF_FLOW
            if variant == "chain":
                return VARIANT_SSRF_CHAIN
            return VARIANT_SSRF_PROVED
        if "first_attack_path" not in milestones:
            return MILESTONE_FIRST_ATTACK_PATH
        return ATTACK_PATH

    if event == EVENT_FIX_VERIFIED:
        if "first_remediation" not in milestones:
            return MILESTONE_FIRST_REMEDIATION
        return FIX_VERIFIED

    if event == EVENT_SESSION_RETURN and SESSION_RETURN.id not in seen:
        return SESSION_RETURN

    # Support ask — only when policy already allowed
    if allow_support and stage in (STATE_SUPPORT_REQUEST, STATE_REPEATED_VALUE, STATE_COMMUNITY_INVITATION):
        summary = reciprocity_summary(ctx)
        if summary is not None and allow_support:
            return _with_body(
                RECIPROCITY_SOFT_STAR,
                summary.body_lines
                + (
                    "",
                    "If this saved you some time, a GitHub star helps the project grow.",
                ),
                message_id="reciprocity_with_stats",
            )
        return REPEATED_VALUE_STAR

    # Community invitation stage
    if stage == STATE_COMMUNITY_INVITATION:
        proof = social_proof_message(state)
        if proof is not None and proof.id not in seen:
            return proof
        if COMMUNITY_BELONGING.id not in seen:
            return COMMUNITY_BELONGING
        return COMMUNITY_OPEN_SOURCE

    # First milestone: verified finding
    if event in (EVENT_AUDIT_COMPLETE, EVENT_SCAN_COMPLETE):
        if ctx.get("first_verified") or (
            ctx.get("verified_count", 0) > 0 and "first_verified" not in milestones
        ):
            return MILESTONE_FIRST_VERIFIED
        if stage == STATE_FIRST_VALUE and FIRST_VALUE_STORY.id not in seen:
            return FIRST_VALUE_STORY
        if stage == STATE_FIRST_VALUE and CURIOSITY_ATTACK_PATH.id not in seen:
            if not ctx.get("used_attack_path"):
                return CURIOSITY_ATTACK_PATH
        if stage == STATE_REPEATED_VALUE and FOUNDER_GAP.id not in seen:
            return FOUNDER_GAP
        if stage in (STATE_FIRST_VALUE, STATE_FIRST_MILESTONE) and AWAREXONE_STORY.id not in seen:
            if ctx.get("show_project_story"):
                return AWAREXONE_STORY
        if FOUNDER_PROVE_IT.id not in seen and event == EVENT_SCAN_COMPLETE:
            return FOUNDER_PROVE_IT

    if event == EVENT_HTML_REPORT:
        if allow_support:
            return RECIPROCITY_SOFT_STAR
        return HTML_ABOUT_FOOTER

    # Fallback: concise analysis summary if stats present
    summary = reciprocity_summary(ctx)
    if summary is not None and summary.id not in seen:
        return _with_body(
            summary,
            summary.body_lines
            + (
                "",
                "Security should prove the problem, not just point at suspicious code.",
            ),
            message_id="analysis_summary_with_voice",
        )

    return None


# Public catalog registry (for tests / introspection)
MESSAGE_CATALOG: dict[str, EngagementMessage] = {
    m.id: m
    for m in (
        FIRST_RUN_INTRO,
        FIRST_VALUE_STORY,
        FP_REJECTED,
        ATTACK_PATH,
        FIX_VERIFIED,
        REPEATED_VALUE_STAR,
        COMMUNITY_BELONGING,
        COMMUNITY_OPEN_SOURCE,
        CURIOSITY_ATTACK_PATH,
        MILESTONE_FIRST_VERIFIED,
        MILESTONE_FIRST_ATTACK_PATH,
        MILESTONE_FIRST_REMEDIATION,
        SESSION_RETURN,
        AWAREXONE_STORY,
        FOUNDER_GAP,
        FOUNDER_PROVE_IT,
        ABOUT_PAGE,
        YC_APPLYING,
        RECIPROCITY_SOFT_STAR,
        HTML_ABOUT_FOOTER,
        VARIANT_SSRF_PROVED,
        VARIANT_SSRF_FLOW,
        VARIANT_SSRF_CHAIN,
        CONTROL_MATTERS,
    )
}
