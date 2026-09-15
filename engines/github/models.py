"""Dataclasses for GitHub adapter events, findings, and check results."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Mode(str, Enum):
    """Product modes — never active production attack testing."""

    REVIEW = "REVIEW"
    PRESHIP = "PRESHIP"
    WATCH = "WATCH"


class PolicyVerdict(str, Enum):
    PASS = "PASS"
    PASS_WITH_NOTES = "PASS_WITH_NOTES"
    REVIEW_REQUIRED = "REVIEW_REQUIRED"
    FAIL = "FAIL"


class FindingLifecycle(str, Enum):
    NEW = "NEW"
    RESOLVED = "RESOLVED"
    REGRESSED = "REGRESSED"
    RECONFIRMED = "RECONFIRMED"
    UNCHANGED = "UNCHANGED"
    UNKNOWN = "UNKNOWN"


@dataclass(frozen=True)
class RepoRef:
    owner: str
    name: str
    full_name: str
    installation_id: int | None = None
    private: bool = False
    default_branch: str | None = None

    @property
    def slug(self) -> str:
        return self.full_name or f"{self.owner}/{self.name}"


@dataclass(frozen=True)
class PullRequestRef:
    number: int
    base_sha: str
    head_sha: str
    base_ref: str = ""
    head_ref: str = ""
    title: str = ""
    html_url: str = ""
    draft: bool = False


@dataclass
class WebhookDelivery:
    event: str
    action: str | None
    delivery_id: str
    installation_id: int | None
    repository: RepoRef | None
    pull_request: PullRequestRef | None
    payload: dict[str, Any]
    received_at: float


@dataclass
class FindingView:
    """Normalized finding for Checks / PR UX (never includes raw secrets)."""

    finding_id: str
    title: str
    severity: str
    status: str
    confidence: str
    file: str | None = None
    line: int | None = None
    message: str = ""
    evidence: str = ""
    attack_path: str = ""
    recommended_action: str = ""
    lifecycle: FindingLifecycle = FindingLifecycle.UNKNOWN
    annotate: bool = False
    raw: dict[str, Any] = field(default_factory=dict, repr=False)


@dataclass
class AnalysisFailure:
    reason: str
    retryable: bool = True
    details: str = ""


@dataclass
class PipelineResult:
    mode: Mode
    verdict: PolicyVerdict
    findings: list[FindingView] = field(default_factory=list)
    rejected_count: int = 0
    regressions: list[str] = field(default_factory=list)
    summary_lines: list[str] = field(default_factory=list)
    check_output_title: str = "AXGuard Security Review"
    check_output_summary: str = ""
    check_output_text: str = ""
    analysis_failed: bool = False
    failure: AnalysisFailure | None = None
    memory_summary: dict[str, Any] = field(default_factory=dict)
    twin_summary: dict[str, Any] = field(default_factory=dict)
    meta: dict[str, Any] = field(default_factory=dict)
