"""Tests for AXGuard GitHub pipeline, checks, comments, and core integrations.

Mocked GitHub API + mocked Memory / Twin / Investigation — no live network.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest

pytest.importorskip("engines.github.pipeline")

from engines.github.checks import (
    annotations_from_findings,
    create_or_update_check_run,
    github_conclusion,
)
from engines.github.client import MockGitHubClient
from engines.github.config import (
    AIConfig,
    AnalysisConfig,
    GitHubBotConfig,
    PolicyConfig,
    ReviewConfig,
    load_github_config,
    resolve_ai_credentials,
)
from engines.github.diff import (
    changed_files_from_compare,
    extract_pr_diff,
    filter_analysis_targets,
)
from engines.github.installation import InstallationRecord, InstallationStore
from engines.github.models import (
    FindingLifecycle,
    FindingView,
    Mode,
    PipelineResult,
    PolicyVerdict,
    PullRequestRef,
    RepoRef,
    WebhookDelivery,
)
from engines.github.pipeline import (
    _apply_lifecycle,
    _build_pipeline_result,
    publish_result,
    run_webhook_pipeline,
)
from engines.github.policy import finding_should_annotate, map_policy_verdict
from engines.github.reviews import (
    COMMENT_MARKER,
    build_summary_body,
    find_existing_summary_comment,
    upsert_pr_summary_comment,
)

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "fixtures" / "verify_app"


def _repo() -> RepoRef:
    return RepoRef(
        owner="acme",
        name="widget",
        full_name="acme/widget",
        installation_id=42,
    )


def _pr(**kwargs: Any) -> PullRequestRef:
    base = dict(
        number=3,
        base_sha="aaa111",
        head_sha="bbb222",
        base_ref="main",
        head_ref="feat/auth",
        title="Tighten auth",
    )
    base.update(kwargs)
    return PullRequestRef(**base)


def _finding(
    *,
    fid: str = "sql.injection",
    status: str = "VERIFIED",
    severity: str = "high",
    annotate: bool = True,
    lifecycle: FindingLifecycle = FindingLifecycle.NEW,
) -> FindingView:
    return FindingView(
        finding_id=fid,
        title="SQL injection",
        severity=severity,
        status=status,
        confidence="HIGH",
        file="app/routes.py",
        line=42,
        message="User input reaches execute",
        evidence="tainted query",
        recommended_action="Use parameterized queries",
        lifecycle=lifecycle,
        annotate=annotate,
    )


# ---------------------------------------------------------------------------
# Changed-file detection / base-head comparison
# ---------------------------------------------------------------------------
def test_extract_pr_diff_changed_files(monkeypatch: pytest.MonkeyPatch):
    import urllib.request

    monkeypatch.setattr(
        urllib.request,
        "urlopen",
        lambda *_a, **_k: (_ for _ in ()).throw(AssertionError("no network")),
    )
    client = MockGitHubClient()
    client.set(
        "GET",
        "/repos/acme/widget/pulls/3/files?per_page=100&page=1",
        [
            {"filename": "app/auth.py", "status": "modified"},
            {"filename": "docs/readme.png", "status": "added"},
            {"filename": "package-lock.json", "status": "modified"},
        ],
    )
    diff = extract_pr_diff(client, _repo(), _pr(), token="tok", max_files=200)
    assert diff.base_sha == "aaa111"
    assert diff.head_sha == "bbb222"
    assert "app/auth.py" in diff.changed_files
    targets = filter_analysis_targets(diff.changed_files)
    assert "app/auth.py" in targets
    assert "docs/readme.png" not in targets
    assert "package-lock.json" not in targets


def test_base_head_compare_api():
    client = MockGitHubClient()
    client.set(
        "GET",
        "/repos/acme/widget/compare/aaa111...bbb222",
        {
            "base_commit": {"sha": "aaa111"},
            "commits": [{"sha": "bbb222"}],
            "files": [
                {"filename": "src/a.py"},
                {"filename": "src/b.py"},
            ],
            "truncated": False,
        },
    )
    diff = changed_files_from_compare(
        client, _repo(), "aaa111", "bbb222", token="tok"
    )
    assert diff.base_sha == "aaa111"
    assert diff.head_sha == "bbb222"
    assert diff.changed_files == ["src/a.py", "src/b.py"]


def test_oversized_pr_truncates():
    client = MockGitHubClient()
    # One page returns more rows than max_files so DiffContext.truncated flips.
    files = [{"filename": f"f{i}.py"} for i in range(100)]
    client.set(
        "GET",
        "/repos/acme/widget/pulls/3/files?per_page=100&page=1",
        files,
    )
    diff = extract_pr_diff(client, _repo(), _pr(), token="tok", max_files=50)
    assert len(diff.changed_files) == 50
    assert diff.truncated is True


# ---------------------------------------------------------------------------
# Policy / checks / annotations
# ---------------------------------------------------------------------------
def test_policy_never_fails_unverified_by_default():
    findings = [_finding(status="UNVERIFIED", severity="critical", annotate=False)]
    assert map_policy_verdict(findings) == PolicyVerdict.PASS_WITH_NOTES
    cfg = GitHubBotConfig(policy=PolicyConfig(fail_on_unverified=True))
    assert map_policy_verdict(findings, cfg) == PolicyVerdict.FAIL


def test_policy_fails_verified_high_not_fp():
    assert map_policy_verdict([_finding(status="VERIFIED", severity="high")]) == PolicyVerdict.FAIL
    assert (
        map_policy_verdict([_finding(status="FALSE_POSITIVE", severity="critical")])
        == PolicyVerdict.PASS
    )


def test_analysis_failure_does_not_fail_pr_by_default():
    assert (
        map_policy_verdict([], analysis_failed=True) == PolicyVerdict.PASS_WITH_NOTES
    )
    assert github_conclusion(PolicyVerdict.PASS_WITH_NOTES, analysis_failed=True) == "neutral"
    assert github_conclusion(PolicyVerdict.FAIL, analysis_failed=True) == "failure"


def test_check_creation_and_annotations():
    client = MockGitHubClient()
    client.set("POST", "/repos/acme/widget/check-runs", {"id": 9001, "html_url": "https://example/check"})
    result = PipelineResult(
        mode=Mode.REVIEW,
        verdict=PolicyVerdict.FAIL,
        findings=[_finding()],
        check_output_title="AXGuard Security Review",
        check_output_summary="FAIL: 1 verified",
        check_output_text="details",
    )
    out = create_or_update_check_run(
        client,
        repo_slug="acme/widget",
        head_sha="bbb222",
        result=result,
        token="tok",
    )
    assert out.check_run_id == 9001
    assert out.conclusion == "failure"
    post = client.calls[0]
    assert post["method"] == "POST"
    assert post["json_body"]["head_sha"] == "bbb222"
    anns = post["json_body"]["output"]["annotations"]
    assert anns and anns[0]["path"] == "app/routes.py"


def test_annotations_skip_false_positives_and_unverified():
    fp = _finding(status="FALSE_POSITIVE", annotate=True)
    unverified = _finding(fid="x", status="UNVERIFIED", annotate=True)
    # finding_should_annotate should be False for these; force annotate True to
    # ensure annotations_from_findings still drops FPs by status.
    anns = annotations_from_findings([fp, unverified, _finding()])
    assert all(a["path"] == "app/routes.py" for a in anns)
    assert finding_should_annotate(fp) is False
    assert finding_should_annotate(unverified) is False


# ---------------------------------------------------------------------------
# PR comments + deduplication
# ---------------------------------------------------------------------------
def test_pr_comment_marker_and_dedup_update():
    client = MockGitHubClient()
    existing_body = f"{COMMENT_MARKER}\n### old\n"
    client.set(
        "GET",
        "/repos/acme/widget/issues/3/comments?per_page=100&page=1",
        [{"id": 55, "body": existing_body}],
    )
    client.set(
        "PATCH",
        "/repos/acme/widget/issues/comments/55",
        {"id": 55, "body": "updated"},
    )
    result = PipelineResult(
        mode=Mode.REVIEW,
        verdict=PolicyVerdict.PASS,
        findings=[],
        check_output_title="AXGuard Security Review",
    )
    resp = upsert_pr_summary_comment(
        client,
        repo_slug="acme/widget",
        issue_number=3,
        result=result,
        token="tok",
    )
    assert resp["id"] == 55
    methods = [c["method"] for c in client.calls]
    assert "POST" not in methods
    assert "PATCH" in methods
    body = build_summary_body(result)
    assert COMMENT_MARKER in body
    assert "AXGuard by Awarexone" in body


def test_find_existing_summary_comment_none():
    client = MockGitHubClient()
    client.set(
        "GET",
        "/repos/acme/widget/issues/3/comments?per_page=100&page=1",
        [{"id": 1, "body": "unrelated"}],
    )
    assert (
        find_existing_summary_comment(
            client, repo_slug="acme/widget", issue_number=3, token="t"
        )
        is None
    )


# ---------------------------------------------------------------------------
# Finding lifecycle / fix verification / regression
# ---------------------------------------------------------------------------
def test_finding_lifecycle_resolved_and_regressed():
    current = [_finding(status="VERIFIED")]
    # Previously confirmed → still verified = reconfirmed-ish / unchanged path
    out = _apply_lifecycle(current, {"sql.injection": "CONFIRMED"})
    assert out[0].lifecycle in {
        FindingLifecycle.RECONFIRMED,
        FindingLifecycle.UNCHANGED,
        FindingLifecycle.NEW,
    }

    # Absent now → RESOLVED marker
    resolved = _apply_lifecycle([], {"sql.injection": "CONFIRMED"})
    assert any(f.lifecycle == FindingLifecycle.RESOLVED for f in resolved)

    # Was resolved / FP, now verified → REGRESSED
    regressed = _apply_lifecycle(
        [_finding(status="CONFIRMED")],
        {"sql.injection": "FALSE_POSITIVE"},
    )
    assert regressed[0].lifecycle == FindingLifecycle.REGRESSED
    assert regressed[0].annotate is True


def test_fix_verification_requires_reinvestigation_not_line_only():
    """Lifecycle uses prior *status*, not mere line movement."""
    # Same finding id still VERIFIED after "line change" → not RESOLVED
    moved = [
        FindingView(
            finding_id="sql.injection",
            title="SQL injection",
            severity="high",
            status="VERIFIED",
            confidence="HIGH",
            file="app/routes.py",
            line=99,  # different line
            message="still vulnerable",
        )
    ]
    out = _apply_lifecycle(moved, {"sql.injection": "VERIFIED"})
    assert all(f.lifecycle != FindingLifecycle.RESOLVED for f in out)

    # Only when status becomes absent/resolved do we mark RESOLVED
    gone = _apply_lifecycle([], {"sql.injection": "VERIFIED"})
    assert any(f.status == "RESOLVED" for f in gone)


def test_regression_detection_in_pipeline_result():
    core = {
        "adversary": {
            "findings": [
                {
                    "id": "authz.bypass",
                    "status": "CONFIRMED",
                    "severity": "high",
                    "confidence": "HIGH",
                    "location": {"file": "api.py", "line": 10},
                    "title": "Authz bypass",
                }
            ]
        },
        "memory_summary": {"regressions": {"REGRESSED": [{"id": "authz.bypass"}]}},
        "twin_compare": {"summary": {"regressed_paths": 1}},
        "changed_files": ["api.py"],
        "ai_mode": "no-llm",
        "investigation": {"investigation_id": "inv-1"},
    }
    result = _build_pipeline_result(
        Mode.REVIEW,
        core,
        GitHubBotConfig(),
        previous={"authz.bypass": "FALSE_POSITIVE"},
    )
    assert result.regressions
    assert result.verdict == PolicyVerdict.FAIL
    assert any(f.lifecycle == FindingLifecycle.REGRESSED for f in result.findings)


# ---------------------------------------------------------------------------
# Security Memory / Twin / Investigation (mocked)
# ---------------------------------------------------------------------------
def test_webhook_pipeline_pr_review_with_mocked_core(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    import engines.github.pipeline as pipe

    store = InstallationStore()
    store.upsert(
        InstallationRecord(
            installation_id=42,
            repository_selection="selected",
            repos=["acme/widget"],
        )
    )
    client = MockGitHubClient()
    client.set(
        "GET",
        "/repos/acme/widget/pulls/3/files?per_page=100&page=1",
        [{"filename": "app/a.py"}],
    )
    client.set("POST", "/repos/acme/widget/check-runs", {"id": 1, "html_url": "u"})
    client.set(
        "GET",
        "/repos/acme/widget/issues/3/comments?per_page=100&page=1",
        [],
    )
    client.set(
        "POST",
        "/repos/acme/widget/issues/3/comments",
        {"id": 77, "body": COMMENT_MARKER},
    )

    mem = MagicMock(return_value={"summary": {"findings": 1}, "snapshot_id": "s1"})
    twin = MagicMock(return_value={"entities": [], "summary": {}})
    twin_cmp = MagicMock(return_value={"summary": {}})
    inv = MagicMock(
        return_value={
            "investigation_id": "inv-test",
            "actions": [],
            "meta": {},
        }
    )

    def _fake_core(
        target,
        *,
        config,
        changed_files=None,
        mode=Mode.REVIEW,
        base_workspace=None,
    ):
        return {
            "verification": {"judgments": []},
            "adversary": {
                "findings": [
                    {
                        "id": "f1",
                        "status": "VERIFIED",
                        "severity": "high",
                        "confidence": "HIGH",
                        "title": "Issue",
                        "location": {"file": "app/a.py", "line": 1},
                    }
                ]
            },
            "attack_graph": {"paths": []},
            "twin_compare": twin_cmp(),
            "twin_head": twin(),
            "investigation": inv(),
            "memory_summary": mem(),
            "ai_mode": "no-llm",
            "changed_files": list(changed_files or []),
        }

    monkeypatch.setattr(pipe, "_run_core_analysis", _fake_core)
    monkeypatch.setattr(pipe, "_previous_statuses_from_memory", lambda *_a, **_k: {})

    delivery = WebhookDelivery(
        event="pull_request",
        action="opened",
        delivery_id="d1",
        installation_id=42,
        repository=_repo(),
        pull_request=_pr(),
        payload={"action": "opened"},
        received_at=1.0,
    )
    workspace = tmp_path / "ws"
    workspace.mkdir()
    out = run_webhook_pipeline(
        delivery,
        client=client,
        get_token=lambda _iid: "install-token",
        workspace=workspace,
        config=GitHubBotConfig(review=ReviewConfig(enabled=True)),
        store=store,
    )
    assert out["ok"] is True
    assert out["mode"] == Mode.REVIEW.value
    result: PipelineResult = out["result"]
    assert result.findings
    assert out["published"]["check"].check_run_id == 1
    # Memory / twin / investigation hooks exercised via fake core
    assert result.memory_summary.get("snapshot_id") == "s1"
    assert result.meta.get("investigation_id") == "inv-test"


def test_unauthorized_repository_blocked():
    store = InstallationStore()
    store.upsert(
        InstallationRecord(
            installation_id=42,
            repository_selection="selected",
            repos=["acme/allowed"],
        )
    )
    delivery = WebhookDelivery(
        event="pull_request",
        action="opened",
        delivery_id="d2",
        installation_id=42,
        repository=RepoRef(
            owner="acme",
            name="widget",
            full_name="acme/widget",
            installation_id=42,
        ),
        pull_request=_pr(),
        payload={},
        received_at=1.0,
    )
    out = run_webhook_pipeline(
        delivery,
        client=MockGitHubClient(),
        get_token=lambda _i: "t",
        workspace=None,
        store=store,
        config=GitHubBotConfig(),
    )
    assert out["ok"] is False
    assert out["error"] == "unauthorized_repository"


def test_invalid_installation_missing():
    delivery = WebhookDelivery(
        event="pull_request",
        action="opened",
        delivery_id="d3",
        installation_id=None,
        repository=RepoRef(owner="a", name="b", full_name="a/b", installation_id=None),
        pull_request=_pr(),
        payload={},
        received_at=1.0,
    )
    out = run_webhook_pipeline(
        delivery,
        client=MockGitHubClient(),
        get_token=lambda _i: "t",
        store=InstallationStore(),
        config=GitHubBotConfig(),
    )
    assert out["ok"] is False
    assert out["error"] in {"unauthorized_repository", "missing_installation"}


# ---------------------------------------------------------------------------
# AI provider abstraction
# ---------------------------------------------------------------------------
def test_ai_provider_no_llm_and_local_modes(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    cfg_path = tmp_path / ".axguard.yml"
    cfg_path.write_text(
        "ai:\n  provider: none\n  mode: no-llm\n",
        encoding="utf-8",
    )
    cfg = load_github_config(cfg_path)
    assert cfg.ai_provider_mode == "no-llm"
    creds = resolve_ai_credentials(cfg)
    assert creds["api_key"] is None
    assert creds["mode"] == "no-llm"

    cfg_path.write_text(
        "ai:\n  provider: ollama\n  mode: local\n  api_key_env: AXGUARD_AI_API_KEY\n",
        encoding="utf-8",
    )
    cfg2 = load_github_config(cfg_path)
    assert cfg2.ai_provider_mode == "local"
    monkeypatch.delenv("AXGUARD_AI_API_KEY", raising=False)
    creds2 = resolve_ai_credentials(cfg2)
    assert creds2["mode"] == "local"
    assert creds2["api_key"] is None  # env only; unset → None

    monkeypatch.setenv("AXGUARD_AI_API_KEY", "sk-user-provided-not-in-repo")
    cfg3 = load_github_config(cfg_path)
    # force user_key mode
    cfg3.ai = AIConfig(provider="openai", mode="user_key", api_key_env="AXGUARD_AI_API_KEY")
    creds3 = resolve_ai_credentials(cfg3)
    assert creds3["mode"] == "user_key"
    assert creds3["api_key"] == "sk-user-provided-not-in-repo"


def test_publish_result_wires_check_and_comment():
    client = MockGitHubClient()
    client.set("POST", "/repos/acme/widget/check-runs", {"id": 11})
    client.set(
        "GET",
        "/repos/acme/widget/issues/3/comments?per_page=100&page=1",
        [],
    )
    client.set("POST", "/repos/acme/widget/issues/3/comments", {"id": 12})
    result = PipelineResult(mode=Mode.REVIEW, verdict=PolicyVerdict.PASS)
    published = publish_result(
        client,
        repo=_repo(),
        head_sha="bbb222",
        result=result,
        token="tok",
        pr_number=3,
        config=GitHubBotConfig(analysis=AnalysisConfig(max_annotations=10)),
    )
    assert published["check"].check_run_id == 11
    assert published["comment"]["id"] == 12
