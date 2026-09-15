"""PR review / pre-ship / watch orchestration over AXGuard core engines.

Pipeline (thin adapter)::

    webhook → validate → fetch diff → Security Memory → Security Twin base/head
    → Investigation scaffold → Judge (via verify) → FP Adversary → attack paths
    → Check + annotations + one summary comment

Never executes repository code. Diff-first when a workspace is available.
"""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from typing import Any, Callable

from engines.github.checks import (
    CHECK_NAME,
    create_or_update_check_run,
    start_in_progress_check,
)
from engines.github.client import GitHubClient
from engines.github.config import GitHubBotConfig, load_github_config, resolve_ai_credentials
from engines.github.diff import DiffContext, extract_pr_diff, filter_analysis_targets
from engines.github.installation import InstallationStore, handle_installation_event, repo_ref_authorized
from engines.github.models import (
    AnalysisFailure,
    FindingLifecycle,
    FindingView,
    Mode,
    PipelineResult,
    PolicyVerdict,
    PullRequestRef,
    RepoRef,
    WebhookDelivery,
)
from engines.github.policy import finding_should_annotate, map_policy_verdict
from engines.github.privacy import redact_secrets, should_retain_source
from engines.github.reviews import upsert_pr_summary_comment
from engines.github.untrusted import as_data_context
from engines.github.webhooks import PR_REVIEW_ACTIONS, SUPPORTED_EVENTS
from engines.memory.lifecycle import transition_finding
from engines.memory.schema import LIFE_NEW, LIFE_REGRESSED, LIFE_RESOLVED

try:
    from engines.investigation.budget import budget_limits
    from engines.investigation.schema import BUDGET_BALANCED, empty_investigation
except ImportError:  # Investigation Agent optional until merged
    BUDGET_BALANCED = "BALANCED"

    def budget_limits(budget: str) -> dict[str, Any]:
        return {"budget": budget, "max_actions": 0, "optional": True}

    def empty_investigation(*, budget: str = BUDGET_BALANCED) -> dict[str, Any]:
        return {"budget": budget, "status": "SKIPPED", "optional": True}


CoreRunner = Callable[..., dict[str, Any]]


def _analysis_budget(config: GitHubBotConfig) -> str:
    mode = (config.analysis.mode or "balanced").upper()
    if mode == "FAST":
        return "FAST"
    if mode == "DEEP":
        return "DEEP"
    return BUDGET_BALANCED


def _normalize_findings_from_adversary(adversary: dict[str, Any]) -> list[FindingView]:
    findings: list[FindingView] = []
    for raw in adversary.get("findings") or adversary.get("final_findings") or []:
        if not isinstance(raw, dict):
            continue
        loc = raw.get("location") if isinstance(raw.get("location"), dict) else {}
        file_ = (
            loc.get("file")
            or raw.get("file")
            or (raw.get("candidate") or {}).get("file")
        )
        line = loc.get("line") or raw.get("line")
        status = str(
            raw.get("status")
            or raw.get("final_status")
            or raw.get("adversary_status")
            or "UNVERIFIED"
        ).upper()
        title = str(
            raw.get("title")
            or raw.get("summary")
            or raw.get("vulnerability_type")
            or raw.get("id")
            or "finding"
        )
        fid = str(raw.get("id") or raw.get("finding_id") or title)
        conf = str(raw.get("confidence") or raw.get("confidence_level") or "UNKNOWN")
        sev = str(raw.get("severity") or "medium").lower()
        evidence = ""
        for ev in raw.get("evidence") or raw.get("surviving_evidence") or []:
            if isinstance(ev, dict) and ev.get("snippet"):
                evidence = str(ev.get("snippet"))
                break
            if isinstance(ev, str):
                evidence = ev
                break
        view = FindingView(
            finding_id=fid,
            title=title,
            severity=sev,
            status=status,
            confidence=conf,
            file=str(file_) if file_ else None,
            line=int(line) if line else None,
            message=str(raw.get("message") or raw.get("reasoning") or "")[:800],
            evidence=evidence[:800],
            attack_path=str(raw.get("attack_path") or "")[:500],
            recommended_action=str(
                raw.get("recommended_action")
                or raw.get("recommended_next_step")
                or raw.get("fix")
                or ""
            )[:400],
            raw=raw,
        )
        view.annotate = finding_should_annotate(view)
        findings.append(view)
    return findings


def _apply_lifecycle(
    findings: list[FindingView],
    previous_by_id: dict[str, str],
) -> list[FindingView]:
    """Attach NEW/RESOLVED/REGRESSED via Security Memory transition rules."""
    seen_ids = {f.finding_id for f in findings}
    updated: list[FindingView] = []
    for f in findings:
        prev = previous_by_id.get(f.finding_id)
        life, _validity = transition_finding(prev, f.status)
        if life == LIFE_NEW:
            lc = FindingLifecycle.NEW
        elif life == LIFE_REGRESSED:
            lc = FindingLifecycle.REGRESSED
        elif life == LIFE_RESOLVED:
            lc = FindingLifecycle.RESOLVED
        elif prev and prev.upper() == f.status.upper():
            lc = FindingLifecycle.RECONFIRMED
        else:
            lc = FindingLifecycle.UNCHANGED if prev else FindingLifecycle.NEW
        f.lifecycle = lc
        if lc == FindingLifecycle.REGRESSED:
            f.annotate = True
        updated.append(f)

    # Previous findings absent now → RESOLVED markers (for summary)
    for fid, prev_status in previous_by_id.items():
        if fid in seen_ids:
            continue
        life, _ = transition_finding(prev_status, "RESOLVED")
        if life == LIFE_RESOLVED:
            updated.append(
                FindingView(
                    finding_id=fid,
                    title=fid,
                    severity="info",
                    status="RESOLVED",
                    confidence="UNKNOWN",
                    message="Finding no longer present after re-investigation.",
                    lifecycle=FindingLifecycle.RESOLVED,
                    annotate=False,
                )
            )
    return updated


def _previous_statuses_from_memory(memory_dir: Path) -> dict[str, str]:
    try:
        from engines.memory import get_findings

        rows = get_findings(memory_dir) or []
        out: dict[str, str] = {}
        if isinstance(rows, dict):
            rows = rows.get("findings") or rows.get("items") or []
        for row in rows:
            if not isinstance(row, dict):
                continue
            fid = str(row.get("id") or row.get("finding_id") or row.get("fingerprint") or "")
            st = str(row.get("status") or row.get("lifecycle") or "")
            if fid and st:
                out[fid] = st
        return out
    except Exception:  # noqa: BLE001 — memory soft-optional
        return {}


def _run_core_analysis(
    target: Path,
    *,
    config: GitHubBotConfig,
    changed_files: list[str] | None = None,
    mode: Mode = Mode.REVIEW,
    base_workspace: Path | None = None,
) -> dict[str, Any]:
    """Call AXGuard engines on a local checkout. Never executes repo code."""
    ai = resolve_ai_credentials(config)
    # Always use deterministic verify/adversary today; LLM stubs stay inert.
    _ = ai

    limits = budget_limits(_analysis_budget(config))
    files = list(changed_files or [])[: limits["max_files"]]

    # Soft investigation scaffold (no full agent loop yet)
    investigation = empty_investigation(budget=_analysis_budget(config))
    investigation["meta"] = {
        "mode": mode.value,
        "changed_files": files,
        "note": "Investigation Agent pipeline is scaffold-only; engines drive analysis.",
    }
    # Record that we considered git change analysis
    investigation.setdefault("actions", []).append(
        {
            "type": "ANALYZE_GIT_CHANGE",
            "status": "COMPLETED",
            "files": files[: limits["max_files"]],
        }
    )

    from engines.verify import run_verification

    verification = run_verification(target)

    from engines.adversary import run_adversary

    adversary = run_adversary(target, verification)

    attack_graph = None
    twin_base = None
    twin_head = None
    twin_compare = None
    try:
        from engines.attack_graph import run_attack_graph

        # Diff-first: still builds graph from target; callers should pass a
        # narrowed workspace when possible. Full-repo graph only for PRESHIP.
        attack_graph = run_attack_graph(target)
    except Exception as exc:  # noqa: BLE001
        attack_graph = {"error": redact_secrets(str(exc))}

    try:
        from engines.twin import build_security_twin, run_twin_compare

        twin_head = build_security_twin(
            target,
            attack_graph=attack_graph if isinstance(attack_graph, dict) else None,
        )
        if base_workspace is not None and Path(base_workspace).is_dir():
            try:
                base_graph = run_attack_graph(Path(base_workspace))
            except Exception:  # noqa: BLE001
                base_graph = None
            twin_base = build_security_twin(
                Path(base_workspace),
                attack_graph=base_graph if isinstance(base_graph, dict) else None,
            )
            twin_compare = run_twin_compare(twin_base, twin_head)
        else:
            # Do not compare a twin to itself — that hides regressions.
            twin_base = None
            twin_compare = {
                "status": "base_unavailable",
                "note": (
                    "Provide base_workspace (checkout of the PR base SHA) "
                    "to enable Security Twin base/head comparison."
                ),
            }
    except Exception as exc:  # noqa: BLE001
        twin_compare = {"error": redact_secrets(str(exc))}

    memory_summary: dict[str, Any] = {}
    try:
        from engines.memory import run_memory_record, run_memory_regressions

        memory_dir = Path(target) / ".findings" / "axguard" / "memory"
        # Prefer recording adversary/audit-shaped results
        payload = {
            "mode": "audit",
            "findings": adversary.get("findings") or [],
            "phases": [],
            "attack_graph": attack_graph,
            "adversary": adversary,
        }
        recorded = run_memory_record(payload, memory_dir=memory_dir)
        memory_summary = dict(recorded.get("summary") or {})
        memory_summary["snapshot_id"] = recorded.get("snapshot_id")
        regs = run_memory_regressions(memory_dir)
        memory_summary["regressions"] = regs
    except Exception as exc:  # noqa: BLE001
        memory_summary = {"error": redact_secrets(str(exc))}

    # Soft Predictive Security — additive; never fails the review pipeline
    predictive: dict[str, Any] = {}
    try:
        from engines.predictive import run_predict

        base_ag = None
        if twin_base and isinstance(twin_base, dict):
            base_ag = twin_base.get("attack_graph")
        predictive = run_predict(
            target,
            mode="pr" if mode == Mode.REVIEW else "architecture",
            attack_graph=attack_graph if isinstance(attack_graph, dict) else None,
            twin=twin_head if isinstance(twin_head, dict) else None,
            base_attack_graph=base_ag if isinstance(base_ag, dict) else None,
            base_twin=twin_base if isinstance(twin_base, dict) else None,
            memory_dir=Path(target) / ".findings" / "axguard" / "memory",
            write_report=False,
            with_twin=False,  # already built above
            with_memory=True,
        )
        predictive = redact_secrets(predictive)
    except Exception as exc:  # noqa: BLE001
        predictive = {"available": False, "error": redact_secrets(str(exc))}

    return {
        "verification": verification,
        "adversary": adversary,
        "attack_graph": attack_graph,
        "twin_compare": twin_compare,
        "twin_head": twin_head,
        "investigation": investigation,
        "memory_summary": memory_summary,
        "predictive": predictive,
        "ai_mode": ai.get("mode"),
        "changed_files": files,
    }


def _build_pipeline_result(
    mode: Mode,
    core: dict[str, Any],
    config: GitHubBotConfig,
    *,
    previous: dict[str, str] | None = None,
    check_name: str | None = None,
) -> PipelineResult:
    findings = _normalize_findings_from_adversary(core.get("adversary") or {})
    prev = previous or {}
    findings = _apply_lifecycle(findings, prev)

    rejected = sum(1 for f in findings if (f.status or "").upper() == "FALSE_POSITIVE")
    regressions: list[str] = []
    mem = core.get("memory_summary") or {}
    reg_blob = mem.get("regressions") if isinstance(mem, dict) else None
    if isinstance(reg_blob, dict):
        for item in reg_blob.get("REGRESSED") or []:
            if isinstance(item, dict):
                regressions.append(str(item.get("id") or item.get("summary") or item))
            else:
                regressions.append(str(item))
    for f in findings:
        if f.lifecycle == FindingLifecycle.REGRESSED:
            regressions.append(f"{f.finding_id}: regressed ({f.title})")

    twin = core.get("twin_compare") or {}
    twin_summary: dict[str, Any] = {}
    if isinstance(twin, dict):
        twin_summary = redact_secrets(twin.get("regression") or twin.get("summary") or {})

    analysis_failed = bool(
        (isinstance(core.get("adversary"), dict) and core["adversary"].get("error"))
        or (isinstance(mem, dict) and mem.get("fatal"))
    )
    failure = None
    if analysis_failed:
        failure = AnalysisFailure(reason="core_analysis_error", details="See meta")

    verdict = map_policy_verdict(
        findings,
        config,
        analysis_failed=analysis_failed,
        regressions=[r for r in regressions if "regressed" in r.lower()] or None,
    )

    verified_n = sum(
        1
        for f in findings
        if (f.status or "").upper() in ("CONFIRMED", "VERIFIED")
        and f.lifecycle != FindingLifecycle.RESOLVED
    )
    title = check_name or {
        Mode.REVIEW: config.review.check_name,
        Mode.PRESHIP: config.preship.check_name,
        Mode.WATCH: config.watch.check_name,
    }.get(mode, CHECK_NAME)

    summary = f"{verdict.value}: {verified_n} verified issue(s)"
    if rejected:
        summary += f"; {rejected} rejected"
    if regressions:
        summary += f"; {len(regressions)} regression(s)"

    predictive = core.get("predictive") if isinstance(core.get("predictive"), dict) else {}
    pred_n = len(predictive.get("risks") or [])
    if pred_n:
        summary += f"; {pred_n} predictive signal(s)"

    try:
        from engines.predictive.github_output import (
            format_github_check_text,
            merge_predictive_into_summary_lines,
        )

        check_text = format_github_check_text(
            verified_findings=findings,
            predictive=predictive if predictive.get("risks") is not None else None,
            comparisons=list(predictive.get("comparisons") or []),
            extra_lines=[
                f"Mode: {mode.value}",
                f"AI: {core.get('ai_mode') or 'no-llm'}",
                f"Changed files analyzed: {len(core.get('changed_files') or [])}",
            ],
        )
        summary_lines = merge_predictive_into_summary_lines([], predictive)
    except Exception:  # noqa: BLE001
        text_lines = [
            f"Mode: {mode.value}",
            f"AI: {core.get('ai_mode') or 'no-llm'}",
            f"Changed files analyzed: {len(core.get('changed_files') or [])}",
            "",
        ]
        for f in findings:
            if f.lifecycle == FindingLifecycle.RESOLVED:
                text_lines.append(f"RESOLVED: {f.finding_id}")
                continue
            if (f.status or "").upper() == "FALSE_POSITIVE":
                continue
            text_lines.append(
                f"{f.severity.upper()} {f.status} {f.title} ({f.file or '?'}:{f.line or '?'})"
            )
        check_text = "\n".join(text_lines)
        summary_lines = []

    return PipelineResult(
        mode=mode,
        verdict=verdict,
        findings=findings,
        rejected_count=rejected,
        regressions=regressions,
        summary_lines=summary_lines,
        check_output_title=title,
        check_output_summary=summary,
        check_output_text=check_text,
        analysis_failed=analysis_failed,
        failure=failure,
        memory_summary=mem if isinstance(mem, dict) else {},
        twin_summary=twin_summary if isinstance(twin_summary, dict) else {},
        meta={
            "investigation_id": (core.get("investigation") or {}).get("investigation_id"),
            "untrusted_pr_title": None,
            "predictive": predictive,
        },
    )


def analyze_local(
    target: Path | str,
    *,
    mode: Mode = Mode.REVIEW,
    config: GitHubBotConfig | None = None,
    changed_files: list[str] | None = None,
    base_workspace: Path | str | None = None,
) -> PipelineResult:
    """Run core analysis on a local path (CLI / Actions / tests)."""
    cfg = config or load_github_config()
    root = Path(target).resolve()
    if should_retain_source(cfg):
        # still never execute
        pass
    prev = _previous_statuses_from_memory(root / ".findings" / "axguard" / "memory")
    base = Path(base_workspace).resolve() if base_workspace else None
    core = _run_core_analysis(
        root,
        config=cfg,
        changed_files=changed_files,
        mode=mode,
        base_workspace=base,
    )
    return _build_pipeline_result(mode, core, cfg, previous=prev)


def run_review(
    target: Path | str,
    *,
    config: GitHubBotConfig | None = None,
    changed_files: list[str] | None = None,
    base_workspace: Path | str | None = None,
) -> PipelineResult:
    return analyze_local(
        target,
        mode=Mode.REVIEW,
        config=config,
        changed_files=changed_files,
        base_workspace=base_workspace,
    )


def run_preship(
    target: Path | str,
    *,
    config: GitHubBotConfig | None = None,
) -> PipelineResult:
    """Broader pre-release analysis (full twin / attack paths)."""
    cfg = config or load_github_config()
    # Force deeper budget for preship when left at default balanced
    if (cfg.analysis.mode or "").lower() == "balanced":
        cfg = replace(cfg, analysis=replace(cfg.analysis, mode="deep"))
    return analyze_local(target, mode=Mode.PRESHIP, config=cfg, changed_files=None)


def run_watch(
    target: Path | str,
    *,
    config: GitHubBotConfig | None = None,
    changed_files: list[str] | None = None,
) -> PipelineResult:
    """Post-ship regression watch — no active production attacks."""
    return analyze_local(target, mode=Mode.WATCH, config=config, changed_files=changed_files)


def publish_result(
    client: GitHubClient,
    *,
    repo: RepoRef,
    head_sha: str,
    result: PipelineResult,
    token: str,
    pr_number: int | None = None,
    config: GitHubBotConfig | None = None,
    check_run_id: int | None = None,
) -> dict[str, Any]:
    """Write Check Run (+ optional PR summary comment)."""
    cfg = config or load_github_config()
    check = create_or_update_check_run(
        client,
        repo_slug=repo.slug,
        head_sha=head_sha,
        result=result,
        token=token,
        name=result.check_output_title,
        check_run_id=check_run_id,
        max_annotations=cfg.analysis.max_annotations,
    )
    comment: dict[str, Any] | None = None
    if pr_number is not None:
        comment = upsert_pr_summary_comment(
            client,
            repo_slug=repo.slug,
            issue_number=pr_number,
            result=result,
            token=token,
            include_footer=cfg.review.include_footer,
        )
    return {"check": check, "comment": comment}


def run_webhook_pipeline(
    delivery: WebhookDelivery,
    *,
    client: GitHubClient,
    get_token: Callable[[int], str],
    workspace: Path | None = None,
    config: GitHubBotConfig | None = None,
    store: InstallationStore | None = None,
) -> dict[str, Any]:
    """Route a verified webhook delivery to the appropriate mode.

    ``workspace`` must be a local checkout already populated by the caller
    (Actions checkout or self-hosted fetch). This adapter never clones via
    shell and never executes repository code.
    """
    cfg = config or load_github_config()
    inst_store = store or InstallationStore()

    if delivery.event not in SUPPORTED_EVENTS:
        return {"ok": True, "skipped": True, "reason": "unsupported_event"}

    if delivery.event in ("installation", "installation_repositories"):
        return {"ok": True, "installation": handle_installation_event(delivery, inst_store)}

    if delivery.event == "ping":
        return {"ok": True, "pong": True}

    repo = delivery.repository
    if repo is None:
        return {"ok": False, "error": "missing_repository"}

    if not repo_ref_authorized(inst_store, repo):
        return {"ok": False, "error": "unauthorized_repository"}

    installation_id = delivery.installation_id or repo.installation_id
    if installation_id is None:
        return {"ok": False, "error": "missing_installation"}

    token = get_token(int(installation_id))

    # --- REVIEW (pull_request) ---
    if delivery.event == "pull_request":
        action = delivery.action or ""
        if action not in PR_REVIEW_ACTIONS:
            return {"ok": True, "skipped": True, "reason": f"pr_action_{action}"}
        if not cfg.review.enabled or not cfg.review.on_pull_request:
            return {"ok": True, "skipped": True, "reason": "review_disabled"}
        pr = delivery.pull_request
        if pr is None or not pr.head_sha:
            return {"ok": False, "error": "missing_pull_request"}

        # Capture untrusted title as data only
        _title_ctx = as_data_context("pull_request.title", pr.title)

        diff = DiffContext(base_sha=pr.base_sha, head_sha=pr.head_sha)
        try:
            diff = extract_pr_diff(
                client,
                repo,
                pr,
                token=token,
                max_files=cfg.analysis.max_changed_files,
            )
        except Exception:  # noqa: BLE001
            # Still proceed if workspace provided
            diff.truncated = True

        changed = filter_analysis_targets(
            diff.changed_files, max_files=cfg.analysis.max_changed_files
        )

        check_id = None
        try:
            started = start_in_progress_check(
                client,
                repo_slug=repo.slug,
                head_sha=pr.head_sha,
                token=token,
                name=cfg.review.check_name,
            )
            check_id = started.check_run_id
        except Exception:  # noqa: BLE001
            check_id = None

        if workspace is None:
            result = PipelineResult(
                mode=Mode.REVIEW,
                verdict=PolicyVerdict.PASS_WITH_NOTES,
                analysis_failed=True,
                failure=AnalysisFailure(
                    reason="no_workspace",
                    details=(
                        "Webhook received but no local checkout was provided. "
                        "Self-host with a workspace or run via GitHub Actions."
                    ),
                ),
                check_output_title=cfg.review.check_name,
                check_output_summary="Analysis incomplete: no workspace",
                check_output_text="Provide a checkout path to analyze.",
            )
        else:
            try:
                result = run_review(workspace, config=cfg, changed_files=changed)
                result.meta["untrusted_pr_title"] = _title_ctx
                result.meta["diff"] = {
                    "base_sha": diff.base_sha,
                    "head_sha": diff.head_sha,
                    "files": changed,
                    "truncated": diff.truncated,
                }
            except Exception as exc:  # noqa: BLE001 — never fail PR by default
                result = PipelineResult(
                    mode=Mode.REVIEW,
                    verdict=map_policy_verdict([], cfg, analysis_failed=True),
                    analysis_failed=True,
                    failure=AnalysisFailure(
                        reason="analysis_exception",
                        details=redact_secrets(str(exc))[:500],
                    ),
                    check_output_title=cfg.review.check_name,
                    check_output_summary="AXGuard could not complete analysis",
                    check_output_text=redact_secrets(str(exc))[:1000],
                )

        published = publish_result(
            client,
            repo=repo,
            head_sha=pr.head_sha,
            result=result,
            token=token,
            pr_number=pr.number,
            config=cfg,
            check_run_id=check_id,
        )
        return {"ok": True, "mode": Mode.REVIEW.value, "result": result, "published": published}

    # --- WATCH (push / release) ---
    if delivery.event in ("push", "release"):
        if not cfg.watch.enabled:
            return {"ok": True, "skipped": True, "reason": "watch_disabled"}
        if delivery.event == "push" and not cfg.watch.on_push:
            return {"ok": True, "skipped": True, "reason": "watch_push_disabled"}
        if delivery.event == "release" and not cfg.watch.on_release:
            return {"ok": True, "skipped": True, "reason": "watch_release_disabled"}

        head_sha = str(
            (delivery.payload.get("after")
             or (delivery.payload.get("release") or {}).get("target_commitish")
             or "")
        )
        if workspace is None:
            return {
                "ok": True,
                "mode": Mode.WATCH.value,
                "skipped": True,
                "reason": "no_workspace",
            }
        result = run_watch(workspace, config=cfg)
        if head_sha:
            published = publish_result(
                client,
                repo=repo,
                head_sha=head_sha,
                result=result,
                token=token,
                pr_number=None,
                config=cfg,
            )
        else:
            published = None
        return {"ok": True, "mode": Mode.WATCH.value, "result": result, "published": published}

    # --- PRE-SHIP via check_run rerequest / manual ---
    if delivery.event == "check_run":
        action = delivery.action or ""
        if action not in ("rerequested", "requested_action") or not cfg.preship.enabled:
            return {"ok": True, "skipped": True, "reason": "check_run_ignored"}
        if workspace is None:
            return {"ok": True, "skipped": True, "reason": "no_workspace"}
        result = run_preship(workspace, config=cfg)
        head_sha = str(
            ((delivery.payload.get("check_run") or {}).get("head_sha")) or ""
        )
        published = None
        if head_sha:
            published = publish_result(
                client,
                repo=repo,
                head_sha=head_sha,
                result=result,
                token=token,
                config=cfg,
            )
        return {"ok": True, "mode": Mode.PRESHIP.value, "result": result, "published": published}

    return {"ok": True, "skipped": True, "reason": "unhandled"}
