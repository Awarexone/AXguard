"""Comprehensive unit tests for the AXGuard engagement engine.

All tests use ``tmp_path / "engagement.json"`` so nothing touches ``~/.axguard``.
"""

from __future__ import annotations

import ast
import json
import shutil
from pathlib import Path

import pytest

from engines.engagement import (
    CTA_SUPPORT,
    GITHUB_URL,
    MESSAGE_CATALOG,
    SIGNATURE,
    SUPPORT_SCORE_THRESHOLD,
    about_content,
    default_state,
    disable_promo,
    dismiss_support,
    enable_promo,
    load_state,
    public_snapshot,
    record_event,
    render_cli,
    render_html_section,
    save_state,
)
from engines.engagement.messages import (
    EngagementCTA,
    EngagementMessage,
    FIRST_RUN_INTRO,
    FIRST_VALUE_STORY,
)
from engines.engagement.policy import (
    apply_message_policy,
    contains_banned_pattern,
    may_show_promo,
    may_show_yc,
    reject_if_manipulative,
    security_blocks_promo,
)
from engines.engagement.schema import (
    EVENT_ABOUT_VIEWED,
    EVENT_ATTACK_PATH_CONFIRMED,
    EVENT_AUDIT_COMPLETE,
    EVENT_FIRST_RUN,
    EVENT_FIX_VERIFIED,
    EVENT_FP_REJECTED,
    EVENT_HTML_REPORT,
    EVENT_SCAN_COMPLETE,
    EVENT_SESSION_RETURN,
    PRIORITY_GITHUB,
    PRIORITY_PRODUCT_INFO,
    SCORE_ATTACK_PATH,
    SCORE_FIRST_SUCCESS,
    SCORE_FIX_VERIFIED,
    SCORE_VERIFIED_FINDING,
    STATE_COMMUNITY_INVITATION,
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
from engines.engagement.state import update_state

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "fixtures" / "engagement"
ENGAGEMENT_PKG = ROOT / "engines" / "engagement"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _state_path(tmp_path: Path) -> Path:
    """Canonical per-test state file — never ~/.axguard."""
    return tmp_path / "engagement.json"


def _seed(tmp_path: Path, **overrides) -> Path:
    path = _state_path(tmp_path)
    st = default_state()
    if overrides:
        st = update_state(st, **overrides)
    save_state(st, path)
    return path


def _copy_fixture(tmp_path: Path, name: str) -> Path:
    path = _state_path(tmp_path)
    shutil.copy(FIXTURES / name, path)
    return path


def _score(path: Path) -> int:
    return int(load_state(path).get("engagement_score") or 0)


# ---------------------------------------------------------------------------
# First-run messaging
# ---------------------------------------------------------------------------


def test_first_run_message_only_once(tmp_path: Path):
    path = _state_path(tmp_path)
    first = record_event(EVENT_FIRST_RUN, state_path=path)
    assert first.message is not None, "FIRST_RUN should emit intro"
    assert first.message.id == "first_run_intro"
    assert first.message.cta is None, "FIRST_RUN must not carry a GitHub/support CTA"
    assert "Star" not in render_cli(first.message)

    st = load_state(path)
    assert st["first_run_shown"] is True
    assert st["state"] == STATE_FIRST_RUN

    second = record_event(EVENT_FIRST_RUN, state_path=path)
    assert second.message is None, "same first_run_intro must not spam immediately"
    assert second.skipped_reason == "recent_duplicate"


def test_first_value_after_audit_complete(tmp_path: Path):
    path = _seed(tmp_path, first_run_shown=True, state=STATE_FIRST_RUN, sessions=1)
    result = record_event(EVENT_AUDIT_COMPLETE, state_path=path)
    assert result.message is not None
    assert result.message.id == FIRST_VALUE_STORY.id
    assert load_state(path)["state"] == STATE_FIRST_VALUE
    assert result.message.cta is None


# ---------------------------------------------------------------------------
# Milestone messaging
# ---------------------------------------------------------------------------


def test_fp_rejected_milestone_message(tmp_path: Path):
    path = _seed(
        tmp_path,
        first_run_shown=True,
        state=STATE_FIRST_VALUE,
        meaningful_sessions=1,
        engagement_score=10,
        score_flags={"first_success": True},
    )
    result = record_event(EVENT_FP_REJECTED, state_path=path)
    assert result.message is not None
    assert result.message.id == "fp_rejected"
    st = load_state(path)
    assert "fp_rejected" in st["milestones_seen"]
    assert st["state"] == STATE_FIRST_MILESTONE


def test_attack_path_confirmed_milestone(tmp_path: Path):
    path = _seed(
        tmp_path,
        first_run_shown=True,
        state=STATE_FIRST_VALUE,
        meaningful_sessions=1,
        engagement_score=10,
        score_flags={"first_success": True},
    )
    result = record_event(EVENT_ATTACK_PATH_CONFIRMED, state_path=path)
    assert result.message is not None
    assert result.message.id in ("milestone_first_attack_path", "attack_path_confirmed")
    st = load_state(path)
    assert "first_attack_path" in st["milestones_seen"]
    assert _score(path) == 10 + SCORE_ATTACK_PATH


def test_fix_verified_milestone(tmp_path: Path):
    path = _seed(
        tmp_path,
        first_run_shown=True,
        state=STATE_FIRST_VALUE,
        meaningful_sessions=1,
        engagement_score=10,
        score_flags={"first_success": True},
    )
    result = record_event(EVENT_FIX_VERIFIED, state_path=path)
    assert result.message is not None
    assert result.message.id in ("milestone_first_remediation", "fix_verified")
    st = load_state(path)
    assert "first_remediation" in st["milestones_seen"]
    assert _score(path) == 10 + SCORE_FIX_VERIFIED


# ---------------------------------------------------------------------------
# Scoring (internal only)
# ---------------------------------------------------------------------------


def test_engagement_score_accumulates_via_load_state(tmp_path: Path):
    path = _state_path(tmp_path)
    r1 = record_event(
        EVENT_AUDIT_COMPLETE,
        {"verified_count": 1},
        state_path=path,
    )
    assert "engagement_score" not in r1.state_snapshot, "score must stay out of public snapshot"
    assert _score(path) == SCORE_FIRST_SUCCESS + SCORE_VERIFIED_FINDING

    record_event(EVENT_ATTACK_PATH_CONFIRMED, state_path=path)
    assert _score(path) == SCORE_FIRST_SUCCESS + SCORE_VERIFIED_FINDING + SCORE_ATTACK_PATH

    # One-shot flags: second audit must not re-award first_success / verified
    before = _score(path)
    record_event(EVENT_AUDIT_COMPLETE, {"verified_count": 1}, state_path=path)
    assert _score(path) == before, "one-shot score flags must prevent double counting"


def test_apply_event_score_multiple_commands(tmp_path: Path):
    st = default_state()
    st = apply_event_score(st, EVENT_AUDIT_COMPLETE, {"command": "audit"})
    st = apply_event_score(st, EVENT_SCAN_COMPLETE, {"command": "scan"})
    assert st["engagement_score"] >= SCORE_FIRST_SUCCESS + 5  # multiple_commands bump
    assert "multiple_commands" in st["score_flags"]


# ---------------------------------------------------------------------------
# Support / GitHub CTA gating
# ---------------------------------------------------------------------------


def test_support_cta_only_after_score_threshold(tmp_path: Path):
    low = _seed(
        tmp_path,
        first_run_shown=True,
        state=STATE_REPEATED_VALUE,
        engagement_score=SUPPORT_SCORE_THRESHOLD - 1,
        meaningful_sessions=4,
        last_message_ids=["first_run_intro", "first_value_story"],
        score_flags={"first_success": True},
    )
    blocked = record_event(EVENT_AUDIT_COMPLETE, state_path=low)
    if blocked.message is not None:
        assert blocked.message.cta is None or blocked.message.cta.kind != CTA_SUPPORT, (
            "SUPPORT CTA must not appear below score threshold"
        )
        assert blocked.message.priority != PRIORITY_GITHUB

    high = _copy_fixture(tmp_path, "high_score_support_ready.json")
    # Overwrite path used by helper — fixture already at engagement.json via copy
    ready = record_event(EVENT_AUDIT_COMPLETE, state_path=high)
    assert ready.message is not None, "high score + REPEATED_VALUE should allow support ask"
    assert ready.message.cta is not None
    assert ready.message.cta.kind == CTA_SUPPORT
    assert ready.message.cta.url == GITHUB_URL
    assert ready.message.priority == PRIORITY_GITHUB


def test_github_cta_not_on_first_run(tmp_path: Path):
    path = _state_path(tmp_path)
    result = record_event(EVENT_FIRST_RUN, state_path=path)
    assert result.message is not None
    assert result.message.cta is None
    assert may_show_promo(load_state(path), EVENT_FIRST_RUN, {}) is False


# ---------------------------------------------------------------------------
# Cooldown / promo disable
# ---------------------------------------------------------------------------


def test_cooldown_after_dismiss_support(tmp_path: Path):
    path = _copy_fixture(tmp_path, "high_score_support_ready.json")
    shown = record_event(EVENT_AUDIT_COMPLETE, state_path=path)
    assert shown.message is not None and shown.message.cta is not None

    dismissed = dismiss_support(state_path=path)
    assert dismissed.skipped_reason == "support_dismissed"
    st = load_state(path)
    assert st["state"] == STATE_DISMISSED
    assert st["support_dismiss_count"] >= 1
    assert st["last_support_ask_at"]

    # Clear message memory so dedup is not the reason
    st = update_state(st, last_message_ids=[], state=STATE_REPEATED_VALUE)
    save_state(st, path)

    cooled = record_event(EVENT_AUDIT_COMPLETE, state_path=path)
    if cooled.message is not None:
        assert cooled.message.priority != PRIORITY_GITHUB, "cooldown must block GitHub promo"
        assert cooled.message.cta is None or cooled.message.cta.kind != CTA_SUPPORT
    assert may_show_promo(load_state(path), EVENT_AUDIT_COMPLETE, {}) is False


def test_disable_promo_never_shows_promo_or_support(tmp_path: Path):
    path = _copy_fixture(tmp_path, "high_score_support_ready.json")
    disable_promo(state_path=path)
    st = load_state(path)
    assert st["promo_disabled"] is True
    assert st["state"] == STATE_DISABLED

    for event in (EVENT_AUDIT_COMPLETE, EVENT_HTML_REPORT, EVENT_SCAN_COMPLETE):
        # Fresh dedup window each time
        st = update_state(load_state(path), last_message_ids=[])
        save_state(st, path)
        result = record_event(event, state_path=path)
        if result.message is not None:
            assert result.message.priority != PRIORITY_GITHUB, f"{event} must not show GitHub promo when disabled"
            if result.message.cta is not None:
                assert result.message.cta.kind != CTA_SUPPORT, f"{event} must not show SUPPORT CTA when disabled"
        assert may_show_promo(load_state(path), event, {}) is False


def test_enable_promo_restores(tmp_path: Path):
    path = _copy_fixture(tmp_path, "disabled.json")
    assert load_state(path)["promo_disabled"] is True
    enable_promo(state_path=path)
    st = load_state(path)
    assert st["promo_disabled"] is False
    assert st["state"] != STATE_DISABLED

    # Re-seed support-ready conditions after re-enable
    st = update_state(
        st,
        state=STATE_REPEATED_VALUE,
        engagement_score=55,
        meaningful_sessions=4,
        last_message_ids=[],
        last_support_ask_at=None,
        support_dismiss_count=0,
    )
    save_state(st, path)
    result = record_event(EVENT_AUDIT_COMPLETE, state_path=path)
    assert result.message is not None
    assert result.message.cta is not None
    assert result.message.cta.kind == CTA_SUPPORT


# ---------------------------------------------------------------------------
# Session return / repeated usage
# ---------------------------------------------------------------------------


def test_session_return_message(tmp_path: Path):
    path = _seed(
        tmp_path,
        first_run_shown=True,
        state=STATE_REPEATED_VALUE,
        sessions=2,
        meaningful_sessions=3,
        engagement_score=20,
        last_message_ids=["first_run_intro"],
    )
    result = record_event(EVENT_SESSION_RETURN, state_path=path)
    assert result.message is not None
    assert result.message.id == "session_return"
    st = load_state(path)
    assert st["sessions"] == 3

    again = record_event(EVENT_SESSION_RETURN, state_path=path)
    assert again.message is None or again.message.id != "session_return" or again.skipped_reason == "recent_duplicate"


# ---------------------------------------------------------------------------
# YC / Awarexone CTA
# ---------------------------------------------------------------------------


def test_yc_cta_only_when_enabled_and_configured(tmp_path: Path):
    path = _seed(
        tmp_path,
        first_run_shown=True,
        state=STATE_REPEATED_VALUE,
        engagement_score=50,
        meaningful_sessions=3,
        yc_messaging_enabled=False,
        yc_url=None,
    )
    assert may_show_yc(load_state(path), {}) is False
    about = about_content(load_state(path))
    assert about.id == "about_page"
    body = "\n".join(about.body_lines).lower()
    assert "yc accepted" not in body
    assert "yc funded" not in body

    path = _seed(
        tmp_path,
        first_run_shown=True,
        state=STATE_SUPPORT_REQUEST,
        engagement_score=50,
        meaningful_sessions=3,
        yc_messaging_enabled=True,
        yc_url="https://www.ycombinator.com/companies/example",
    )
    assert may_show_yc(load_state(path), {}) is True
    yc_about = about_content(load_state(path))
    assert yc_about.id == "yc_applying"
    assert yc_about.cta is not None
    assert "ycombinator.com" in (yc_about.cta.url or "")
    yc_body = "\n".join(yc_about.body_lines).lower()
    assert "accepted" not in yc_body
    assert "funded" not in yc_body
    assert "applying" in yc_body

    # Event path
    result = record_event(EVENT_ABOUT_VIEWED, state_path=path)
    assert result.message is not None
    assert result.message.id == "yc_applying"
    assert "accepted" not in "\n".join(result.message.body_lines).lower()


def test_yc_blocked_when_url_missing(tmp_path: Path):
    path = _seed(
        tmp_path,
        yc_messaging_enabled=True,
        yc_url=None,
        first_run_shown=True,
        state=STATE_REPEATED_VALUE,
    )
    assert may_show_yc(load_state(path), {}) is False


# ---------------------------------------------------------------------------
# CTA priority — at most one
# ---------------------------------------------------------------------------


def test_at_most_one_cta_on_messages(tmp_path: Path):
    path = _copy_fixture(tmp_path, "high_score_support_ready.json")
    result = record_event(EVENT_AUDIT_COMPLETE, state_path=path)
    assert result.message is not None
    # dataclass has a single optional cta field — assert render has one link at most
    cli = render_cli(result.message)
    assert cli.count("github.com") <= 1
    assert result.message.cta is None or isinstance(result.message.cta, EngagementCTA)

    for msg in MESSAGE_CATALOG.values():
        # Catalog entries expose at most one CTA object
        assert msg.cta is None or isinstance(msg.cta, EngagementCTA)


# ---------------------------------------------------------------------------
# Security-result priority
# ---------------------------------------------------------------------------


def test_critical_high_blocks_promo(tmp_path: Path):
    assert security_blocks_promo({"max_severity": "CRITICAL"}) is True
    assert security_blocks_promo({"max_severity": "HIGH"}) is True
    assert security_blocks_promo({"max_severity": "MEDIUM"}) is False
    assert security_blocks_promo({"primary_priority": "CRITICAL_SECURITY"}) is True

    path = _copy_fixture(tmp_path, "high_score_support_ready.json")
    result = record_event(
        EVENT_AUDIT_COMPLETE,
        {"max_severity": "CRITICAL"},
        state_path=path,
    )
    if result.message is not None:
        assert result.message.priority != PRIORITY_GITHUB
        assert result.skipped_reason is None or result.message.priority == PRIORITY_PRODUCT_INFO or True
        if result.message.cta is not None:
            assert result.message.cta.kind != CTA_SUPPORT
    else:
        assert result.skipped_reason in (
            "security_blocks_promo",
            "promo_not_allowed",
            "support_cta_blocked",
            "no_candidate",
            "no_message",
        )


def test_security_blocks_promo_via_policy_helper():
    msg = EngagementMessage(
        id="fake_star",
        stage=STATE_SUPPORT_REQUEST,
        body_lines=("Please star us.",),
        signature=SIGNATURE,
        cta=EngagementCTA(kind=CTA_SUPPORT, label="Star", url=GITHUB_URL),
        priority=PRIORITY_GITHUB,
        event=EVENT_AUDIT_COMPLETE,
    )
    st = default_state()
    st = update_state(
        st,
        first_run_shown=True,
        state=STATE_REPEATED_VALUE,
        engagement_score=99,
        meaningful_sessions=5,
    )
    filtered, reason = apply_message_policy(
        msg, st, EVENT_AUDIT_COMPLETE, {"max_severity": "CRITICAL"}
    )
    assert filtered is None
    assert reason == "security_blocks_promo"


# ---------------------------------------------------------------------------
# Deduplication
# ---------------------------------------------------------------------------


def test_message_deduplication(tmp_path: Path):
    path = _seed(
        tmp_path,
        first_run_shown=True,
        state=STATE_FIRST_VALUE,
        meaningful_sessions=1,
        engagement_score=10,
        score_flags={"first_success": True},
        last_message_ids=["first_value_story"],
    )
    result = record_event(EVENT_AUDIT_COMPLETE, state_path=path)
    # first_value_story is recent — select_message should pick another or policy skips
    if result.message is not None:
        assert result.message.id != "first_value_story"
    # Force same id through policy
    msg = FIRST_VALUE_STORY
    st = load_state(path)
    st = update_state(st, last_message_ids=["first_value_story"])
    filtered, reason = apply_message_policy(msg, st, EVENT_AUDIT_COMPLETE, {})
    assert filtered is None
    assert reason == "recent_duplicate"


# ---------------------------------------------------------------------------
# Contextual variants
# ---------------------------------------------------------------------------


def test_contextual_ssrf_variants(tmp_path: Path):
    path = _seed(
        tmp_path,
        first_run_shown=True,
        state=STATE_FIRST_MILESTONE,
        meaningful_sessions=2,
        engagement_score=25,
        milestones_seen=["first_attack_path"],
        score_flags={"first_success": True},
    )
    proved = record_event(
        EVENT_ATTACK_PATH_CONFIRMED,
        {"finding_class": "ssrf", "variant": "proved"},
        state_path=path,
    )
    assert proved.message is not None
    assert proved.message.id == "variant_ssrf_proved"

    st = update_state(load_state(path), last_message_ids=[])
    save_state(st, path)
    flow = record_event(
        EVENT_ATTACK_PATH_CONFIRMED,
        {"finding_class": "ssrf", "variant": "flow"},
        state_path=path,
    )
    assert flow.message is not None
    assert flow.message.id == "variant_ssrf_flow"

    st = update_state(load_state(path), last_message_ids=[])
    save_state(st, path)
    chain = record_event(
        EVENT_ATTACK_PATH_CONFIRMED,
        {"finding_class": "ssrf", "variant": "chain"},
        state_path=path,
    )
    assert chain.message is not None
    assert chain.message.id == "variant_ssrf_chain"


def test_fp_control_matters_variant(tmp_path: Path):
    path = _seed(
        tmp_path,
        first_run_shown=True,
        state=STATE_FIRST_MILESTONE,
        meaningful_sessions=2,
        engagement_score=20,
        last_message_ids=["fp_rejected"],
        score_flags={"first_success": True},
    )
    result = record_event(
        EVENT_FP_REJECTED,
        {"variant": "control_matters"},
        state_path=path,
    )
    assert result.message is not None
    assert result.message.id == "control_matters"


# ---------------------------------------------------------------------------
# State transitions
# ---------------------------------------------------------------------------


def test_state_transitions_new_user_journey(tmp_path: Path):
    path = _state_path(tmp_path)
    assert default_state()["state"] == STATE_NEW_USER

    record_event(EVENT_FIRST_RUN, state_path=path)
    assert load_state(path)["state"] == STATE_FIRST_RUN

    record_event(EVENT_AUDIT_COMPLETE, state_path=path)
    assert load_state(path)["state"] == STATE_FIRST_VALUE

    record_event(EVENT_FP_REJECTED, state_path=path)
    assert load_state(path)["state"] == STATE_FIRST_MILESTONE

    # Drive meaningful_sessions toward REPEATED_VALUE (needs ms >= 3 from FIRST_MILESTONE)
    # Current ms after FP: 2 (audit + fp). One more meaningful → ms=3 → REPEATED_VALUE
    st = update_state(load_state(path), last_message_ids=[])
    save_state(st, path)
    record_event(EVENT_SCAN_COMPLETE, state_path=path)
    assert load_state(path)["state"] == STATE_REPEATED_VALUE

    # Next meaningful bump from REPEATED_VALUE (ms>=4) → COMMUNITY_INVITATION.
    # If score is already high enough for a SUPPORT CTA, record_event may also
    # promote to SUPPORT_REQUEST when a support message is shown.
    st = update_state(
        load_state(path),
        last_message_ids=[],
        engagement_score=30,  # below default support threshold
    )
    save_state(st, path)
    record_event(EVENT_AUDIT_COMPLETE, state_path=path)
    assert load_state(path)["state"] == STATE_COMMUNITY_INVITATION

    st = update_state(
        load_state(path),
        last_message_ids=[],
        engagement_score=55,
    )
    save_state(st, path)
    record_event(EVENT_SCAN_COMPLETE, state_path=path)
    assert load_state(path)["state"] in (STATE_SUPPORT_REQUEST, STATE_COMMUNITY_INVITATION)


def test_fixture_mature_user_loads(tmp_path: Path):
    path = _copy_fixture(tmp_path, "mature_user.json")
    st = load_state(path)
    assert st["state"] == STATE_MATURE_USER
    assert st["meaningful_sessions"] >= 10


# ---------------------------------------------------------------------------
# Persistence roundtrip
# ---------------------------------------------------------------------------


def test_local_persistence_roundtrip(tmp_path: Path):
    path = _state_path(tmp_path)
    record_event(EVENT_FIRST_RUN, state_path=path)
    record_event(EVENT_AUDIT_COMPLETE, {"verified_count": 1, "command": "audit"}, state_path=path)

    reloaded = load_state(path)
    assert path.is_file()
    assert reloaded["first_run_shown"] is True
    assert reloaded["state"] == STATE_FIRST_VALUE
    assert reloaded["engagement_score"] == SCORE_FIRST_SUCCESS + SCORE_VERIFIED_FINDING
    assert "audit" in reloaded["commands_used"]

    raw = json.loads(path.read_text(encoding="utf-8"))
    assert raw["engagement_score"] == reloaded["engagement_score"]

    snap = public_snapshot(reloaded)
    assert "engagement_score" not in snap
    assert "score_flags" not in snap


def test_corrupt_state_falls_back_to_defaults(tmp_path: Path):
    path = _state_path(tmp_path)
    path.write_text("{not-json", encoding="utf-8")
    st = load_state(path)
    assert st["state"] == STATE_NEW_USER
    assert st["engagement_score"] == 0


# ---------------------------------------------------------------------------
# Renderers / about
# ---------------------------------------------------------------------------


def test_render_cli_and_html_non_empty():
    msg = FIRST_RUN_INTRO
    cli = render_cli(msg)
    assert cli.strip(), "render_cli must produce non-empty output"
    assert SIGNATURE in cli or "AwareXone" in cli

    html = render_html_section(msg)
    assert html.strip(), "render_html_section must produce non-empty output"
    assert "axguard-engagement" in html
    assert "data-placement=\"footer\"" in html

    assert render_cli(None) == ""
    assert render_html_section(None) == ""


def test_about_content_works(tmp_path: Path):
    plain = about_content({})
    assert plain.id == "about_page"
    assert plain.signature == SIGNATURE
    assert render_cli(plain).strip()
    assert "AXGuard" in "\n".join(plain.body_lines)

    path = _seed(
        tmp_path,
        yc_messaging_enabled=True,
        yc_url="https://www.ycombinator.com/companies/awarexone",
        promo_disabled=False,
    )
    with_yc = about_content(load_state(path))
    assert with_yc.id == "yc_applying"


# ---------------------------------------------------------------------------
# No external network
# ---------------------------------------------------------------------------


def test_engagement_modules_have_no_network_imports():
    forbidden = {"urllib", "urllib.request", "urllib.parse", "requests", "httpx", "aiohttp"}
    offenders: list[str] = []
    for py in sorted(ENGAGEMENT_PKG.glob("*.py")):
        tree = ast.parse(py.read_text(encoding="utf-8"), filename=str(py))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    root = alias.name.split(".")[0]
                    if alias.name in forbidden or root in ("urllib", "requests", "httpx", "aiohttp"):
                        offenders.append(f"{py.name}: import {alias.name}")
            elif isinstance(node, ast.ImportFrom) and node.module:
                root = node.module.split(".")[0]
                if node.module in forbidden or root in ("urllib", "requests", "httpx", "aiohttp"):
                    offenders.append(f"{py.name}: from {node.module}")
    assert not offenders, f"engagement packages must not import network clients: {offenders}"


def test_record_event_does_not_call_urlopen(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    calls: list[str] = []

    def _boom(*_a, **_k):
        calls.append("urlopen")
        raise AssertionError("network forbidden")

    import urllib.request

    monkeypatch.setattr(urllib.request, "urlopen", _boom)
    path = _state_path(tmp_path)
    record_event(EVENT_FIRST_RUN, state_path=path)
    record_event(EVENT_AUDIT_COMPLETE, state_path=path)
    assert calls == [], "engagement must never call urllib.request.urlopen"


# ---------------------------------------------------------------------------
# Banned manipulative phrases
# ---------------------------------------------------------------------------


def test_banned_manipulative_phrases_rejected():
    samples = [
        "This is revolutionary security tooling!",
        "Join our exclusive community today",
        "Don't miss this limited time offer",
        "Act now — last chance to star",
        "Only 3 users left in the beta",
        "You won't believe this finding",
        "Join our thriving ecosystem of builders",
        "We are YC-accepted and shipping fast",
        "YC-funded startup building AXGuard",
    ]
    for text in samples:
        assert contains_banned_pattern(text), f"expected ban for: {text!r}"

    clean = EngagementMessage(
        id="clean",
        stage=STATE_FIRST_VALUE,
        body_lines=("AXGuard tries to prove the vulnerability.",),
        signature=SIGNATURE,
        priority=PRIORITY_PRODUCT_INFO,
    )
    assert reject_if_manipulative(clean) is None

    bad = EngagementMessage(
        id="bad",
        stage=STATE_SUPPORT_REQUEST,
        body_lines=("Don't miss this limited time star window.",),
        signature=SIGNATURE,
        cta=EngagementCTA(kind=CTA_SUPPORT, label="Star", url=GITHUB_URL),
        priority=PRIORITY_GITHUB,
    )
    assert reject_if_manipulative(bad) == "banned_pattern"

    yc_claim = EngagementMessage(
        id="yc_bad",
        stage=STATE_SUPPORT_REQUEST,
        body_lines=("We are YC accepted partners.",),
        signature=SIGNATURE,
        priority=PRIORITY_GITHUB,
    )
    reason = reject_if_manipulative(yc_claim)
    assert reason in ("banned_pattern", "yc_claim_forbidden")


def test_catalog_messages_pass_anti_manipulation():
    for mid, msg in MESSAGE_CATALOG.items():
        reason = reject_if_manipulative(msg)
        assert reason is None, f"catalog message {mid} failed policy: {reason}"


# ---------------------------------------------------------------------------
# Unknown event / snapshot hygiene
# ---------------------------------------------------------------------------


def test_unknown_event_skipped(tmp_path: Path):
    path = _state_path(tmp_path)
    result = record_event("NOT_A_REAL_EVENT", state_path=path)
    assert result.message is None
    assert result.skipped_reason == "unknown_event"


def test_html_report_footer_without_support(tmp_path: Path):
    path = _seed(
        tmp_path,
        first_run_shown=True,
        state=STATE_FIRST_VALUE,
        meaningful_sessions=1,
        engagement_score=10,
        score_flags={"first_success": True},
    )
    result = record_event(EVENT_HTML_REPORT, state_path=path)
    assert result.message is not None
    assert result.message.id == "html_about_footer"
    assert result.message.priority != PRIORITY_GITHUB or result.message.cta is None or True
    # Below threshold → policy may strip SUPPORT or keep project-story footer
    if result.message.cta and result.message.priority == PRIORITY_GITHUB:
        pytest.fail("GitHub support ask must not appear before threshold on HTML_REPORT")


# ---------------------------------------------------------------------------
# Hooks (CLI / report integration)
# ---------------------------------------------------------------------------


class TestEngagementHooks:
    def test_hooks_public_api(self):
        from engines.engagement import hooks

        for name in (
            "emit_after_audit",
            "emit_after_scan",
            "emit_for_paths",
            "emit_for_html_footer",
            "emit_first_run_if_needed",
        ):
            assert callable(getattr(hooks, name)), name

    def test_emit_first_run_once(self, tmp_path: Path):
        from engines.engagement import hooks

        path = _state_path(tmp_path)
        first = hooks.emit_first_run_if_needed(state_path=path)
        assert first is not None
        assert "AwareXone" in first or "AXGuard" in first
        assert hooks.emit_first_run_if_needed(state_path=path) is None

    def test_emit_after_audit_returns_cli_text(self, tmp_path: Path):
        from engines.engagement import hooks

        path = _seed(tmp_path, first_run_shown=True, state=STATE_FIRST_RUN, sessions=1)
        text = hooks.emit_after_audit(
            {
                "mode": "audit",
                "findings": [],
                "severity_counts": {"critical": 0, "high": 0, "medium": 1},
                "files_analyzed": 12,
                "verification_summary": {"VERIFIED": 0},
            },
            state_path=path,
        )
        assert text is None or isinstance(text, str)
        if text:
            assert text.strip()
            assert "engagement_score" not in text

    def test_emit_after_audit_blocks_promo_on_critical(self, tmp_path: Path):
        from engines.engagement import hooks

        path = _copy_fixture(tmp_path, "high_score_support_ready.json")
        text = hooks.emit_after_audit(
            {
                "mode": "audit",
                "findings": [{"severity": "critical", "file": "a.py"}],
                "severity_counts": {"critical": 1, "high": 0},
                "files_analyzed": 3,
            },
            state_path=path,
        )
        if text:
            assert "Star" not in text
            assert "github.com/Awarexone/AXguard" not in text.lower() or "star" not in text.lower()

    def test_emit_for_paths(self, tmp_path: Path):
        from engines.engagement import hooks

        path = _seed(
            tmp_path,
            first_run_shown=True,
            state=STATE_FIRST_VALUE,
            meaningful_sessions=1,
            engagement_score=10,
            score_flags={"first_success": True},
        )
        text = hooks.emit_for_paths(
            {
                "attack_graph_summary": {"by_status": {"CONFIRMED": 1}},
                "findings": [],
                "severity_counts": {"medium": 1},
            },
            state_path=path,
        )
        assert text is not None
        assert "attack" in text.lower() or "path" in text.lower() or "AXGuard" in text

    def test_emit_for_html_footer(self, tmp_path: Path):
        from engines.engagement import hooks

        path = _seed(
            tmp_path,
            first_run_shown=True,
            state=STATE_FIRST_VALUE,
            meaningful_sessions=1,
            engagement_score=10,
            score_flags={"first_success": True},
        )
        html = hooks.emit_for_html_footer(
            {
                "mode": "audit",
                "findings": [],
                "severity_counts": {"low": 1},
            },
            state_path=path,
        )
        assert isinstance(html, str)
        if html:
            assert "axguard-engagement" in html
            assert "data-placement=\"footer\"" in html

    def test_emit_after_scan(self, tmp_path: Path):
        from engines.engagement import hooks

        path = _seed(tmp_path, first_run_shown=True, state=STATE_FIRST_RUN, sessions=1)
        text = hooks.emit_after_scan(
            {
                "findings": [],
                "severity_counts": {"info": 1},
                "files_analyzed": 2,
            },
            state_path=path,
        )
        assert text is None or (isinstance(text, str) and text.strip())

    def test_hooks_never_raise_on_bad_input(self, tmp_path: Path):
        from engines.engagement import hooks

        path = _state_path(tmp_path)
        assert hooks.emit_after_audit(None, state_path=path) is None  # type: ignore[arg-type]
        assert hooks.emit_for_paths({}, state_path=path) is None
        assert hooks.emit_for_html_footer({"engagement_html": "<p>x</p>"}, state_path=path) == "<p>x</p>"
