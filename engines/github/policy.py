"""Map AXGuard finding statuses → PASS / PASS_WITH_NOTES / REVIEW_REQUIRED / FAIL."""

from __future__ import annotations

from typing import Any

from engines.github.config import GitHubBotConfig, PolicyConfig
from engines.github.models import FindingView, PolicyVerdict


_VERIFIED = frozenset({"CONFIRMED", "VERIFIED"})
_LIKELY = frozenset({"LIKELY"})
_UNVERIFIED = frozenset({"UNVERIFIED", "UNKNOWN", "CANDIDATE"})
_FP = frozenset({"FALSE_POSITIVE"})
_REVIEW = frozenset({"REQUIRES_REVIEW"})


def _sev(f: FindingView) -> str:
    return (f.severity or "info").lower()


def _status(f: FindingView) -> str:
    return (f.status or "").upper()


def map_policy_verdict(
    findings: list[FindingView],
    config: GitHubBotConfig | PolicyConfig | None = None,
    *,
    analysis_failed: bool = False,
    regressions: list[str] | None = None,
) -> PolicyVerdict:
    """Never fail on unverified suspicion; analysis errors do not fail by default."""
    policy: PolicyConfig
    if isinstance(config, GitHubBotConfig):
        policy = config.policy
    elif isinstance(config, PolicyConfig):
        policy = config
    else:
        policy = PolicyConfig()

    if analysis_failed:
        return PolicyVerdict.FAIL if policy.fail_on_analysis_error else PolicyVerdict.PASS_WITH_NOTES

    fail_sevs = {s.lower() for s in (policy.fail_on or [])}
    open_findings = [f for f in findings if _status(f) not in _FP]

    # Verified critical/high (configurable) → FAIL
    for f in open_findings:
        st = _status(f)
        if st in _VERIFIED and _sev(f) in fail_sevs:
            return PolicyVerdict.FAIL
        if st in _VERIFIED and policy.medium_fail and _sev(f) == "medium":
            return PolicyVerdict.FAIL

    # Regressions of verified issues → FAIL or REVIEW
    if regressions:
        return PolicyVerdict.FAIL if fail_sevs else PolicyVerdict.REVIEW_REQUIRED

    # LIKELY / REQUIRES_REVIEW → REVIEW_REQUIRED
    for f in open_findings:
        st = _status(f)
        if st in _LIKELY or st in _REVIEW:
            return PolicyVerdict.REVIEW_REQUIRED

    # UNVERIFIED only → PASS_WITH_NOTES (never FAIL unless configured)
    has_unverified = any(_status(f) in _UNVERIFIED for f in open_findings)
    if has_unverified:
        if policy.fail_on_unverified:
            return PolicyVerdict.FAIL
        return PolicyVerdict.PASS_WITH_NOTES

    # Verified medium/low not in fail_on → notes
    verified_notes = [
        f for f in open_findings if _status(f) in _VERIFIED and _sev(f) not in fail_sevs
    ]
    if verified_notes:
        return PolicyVerdict.PASS_WITH_NOTES

    return PolicyVerdict.PASS


def verdict_to_check_conclusion(verdict: PolicyVerdict) -> str:
    from engines.github.checks import github_conclusion

    return github_conclusion(verdict)


def finding_should_annotate(f: FindingView) -> bool:
    """Only annotate verified / strong evidence / meaningful regressions."""
    st = _status(f)
    if st in _FP:
        return False
    if st in _UNVERIFIED:
        return False
    if f.lifecycle and f.lifecycle.value == "REGRESSED":
        return True
    if st in _VERIFIED:
        return True
    if st in _LIKELY and _sev(f) in ("critical", "high"):
        return True
    return bool(f.annotate)
