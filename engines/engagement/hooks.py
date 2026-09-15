"""Thin CLI/report hooks around the engagement engine.

Never raises into callers. Never performs network I/O.
Security output stays primary — these helpers only return engagement text.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from engines.engagement.engine import record_event, render_cli, render_html_section
from engines.engagement.messages import EngagementMessage
from engines.engagement.policy import security_blocks_promo
from engines.engagement.schema import (
    CTA_SUPPORT,
    EVENT_ATTACK_PATH_CONFIRMED,
    EVENT_AUDIT_COMPLETE,
    EVENT_FIRST_RUN,
    EVENT_FIX_VERIFIED,
    EVENT_FP_REJECTED,
    EVENT_HTML_REPORT,
    EVENT_SCAN_COMPLETE,
    PRIORITY_GITHUB,
    PRIORITY_RANK,
    PROMO_PRIORITIES,
)
from engines.engagement.state import load_state


def emit_after_audit(
    result: dict,
    *,
    state_path: Path | None = None,
) -> str | None:
    """Record audit milestones; return best single CLI engagement string (or None)."""
    try:
        ctx = _context_from_result(result, command="audit")
        messages: list[EngagementMessage] = []

        if ctx.get("fp_rejected", 0) > 0:
            msg = _safe_record(
                EVENT_FP_REJECTED,
                {**ctx, "count_meaningful": False, "rejected_count": ctx["fp_rejected"]},
                state_path,
            )
            if msg is not None:
                messages.append(msg)

        if ctx.get("attack_paths_confirmed", 0) > 0:
            msg = _safe_record(
                EVENT_ATTACK_PATH_CONFIRMED,
                {**ctx, "count_meaningful": False, "used_attack_path": True},
                state_path,
            )
            if msg is not None:
                messages.append(msg)

        if ctx.get("fix_verified", 0) > 0:
            msg = _safe_record(
                EVENT_FIX_VERIFIED,
                {**ctx, "count_meaningful": False},
                state_path,
            )
            if msg is not None:
                messages.append(msg)

        if _html_report_written(result):
            msg = _safe_record(
                EVENT_HTML_REPORT,
                {**ctx, "count_meaningful": False},
                state_path,
            )
            if msg is not None:
                messages.append(msg)

        msg = _safe_record(
            EVENT_AUDIT_COMPLETE,
            {**ctx, "count_meaningful": True},
            state_path,
        )
        if msg is not None:
            messages.append(msg)

        best = _best_message(messages, ctx)
        text = render_cli(best).strip() if best is not None else ""
        return text or None
    except Exception:  # noqa: BLE001 — never break audit CLI
        return None


def emit_after_scan(
    result: dict,
    *,
    state_path: Path | None = None,
    html_written: bool = False,
) -> str | None:
    """Record scan completion; return best CLI engagement string (or None)."""
    try:
        ctx = _context_from_result(result, command="scan")
        messages: list[EngagementMessage] = []

        if html_written or _html_report_written(result):
            msg = _safe_record(
                EVENT_HTML_REPORT,
                {**ctx, "count_meaningful": False},
                state_path,
            )
            if msg is not None:
                messages.append(msg)

        msg = _safe_record(
            EVENT_SCAN_COMPLETE,
            {**ctx, "count_meaningful": True},
            state_path,
        )
        if msg is not None:
            messages.append(msg)

        best = _best_message(messages, ctx)
        text = render_cli(best).strip() if best is not None else ""
        return text or None
    except Exception:  # noqa: BLE001
        return None


def emit_for_paths(
    result: dict,
    *,
    state_path: Path | None = None,
) -> str | None:
    """Record confirmed attack paths; return CLI engagement string (or None)."""
    try:
        ctx = _context_from_result(result, command="paths")
        confirmed = int(ctx.get("attack_paths_confirmed") or 0)
        if confirmed <= 0:
            # Also accept paths-shaped results (standalone `axguard paths`)
            summary = result.get("summary") or result.get("attack_graph_summary") or {}
            by_status = summary.get("by_status") or {}
            confirmed = int(by_status.get("CONFIRMED") or 0)
            ctx = {
                **ctx,
                "attack_paths_confirmed": confirmed,
                "used_attack_path": confirmed > 0,
            }

        if confirmed <= 0:
            return None

        msg = _safe_record(
            EVENT_ATTACK_PATH_CONFIRMED,
            {**ctx, "count_meaningful": True, "used_attack_path": True},
            state_path,
        )
        if msg is None or _promo_blocked_for_cli(msg, ctx):
            return None
        text = render_cli(msg).strip()
        return text or None
    except Exception:  # noqa: BLE001
        return None


def emit_for_html_footer(
    result: dict,
    *,
    state_path: Path | None = None,
) -> str:
    """HTML engagement section for report footer (may be empty string)."""
    try:
        if result.get("engagement_html"):
            return str(result["engagement_html"])

        ctx = _context_from_result(result, command=str(result.get("mode") or "report"))
        msg = _safe_record(
            EVENT_HTML_REPORT,
            {**ctx, "count_meaningful": True},
            state_path,
        )
        if msg is None:
            return ""
        # Critical/high: keep about footer without SUPPORT/GITHUB CTA asks
        if _promo_blocked_for_cli(msg, ctx):
            if msg.id == "html_about_footer" or msg.priority not in PROMO_PRIORITIES:
                # Strip CTA for about-style footers when security is primary
                from engines.engagement.messages import EngagementMessage as EM

                msg = EM(
                    id=msg.id,
                    stage=msg.stage,
                    body_lines=msg.body_lines,
                    signature=msg.signature,
                    cta=None,
                    priority=msg.priority,
                    event=msg.event,
                )
            else:
                return ""
        return render_html_section(msg, about=True)
    except Exception:  # noqa: BLE001
        return ""


def emit_first_run_if_needed(
    *,
    state_path: Path | None = None,
) -> str | None:
    """Show first-run intro once; return CLI text or None."""
    try:
        state = load_state(state_path)
        if state.get("first_run_shown"):
            return None
        msg = _safe_record(EVENT_FIRST_RUN, {"command": "first_run"}, state_path)
        if msg is None:
            return None
        text = render_cli(msg).strip()
        return text or None
    except Exception:  # noqa: BLE001
        return None


# ---------------------------------------------------------------------------
# Internals
# ---------------------------------------------------------------------------


def _safe_record(
    event: str,
    context: dict[str, Any],
    state_path: Path | None,
) -> EngagementMessage | None:
    try:
        outcome = record_event(event, context, state_path=state_path)
        return outcome.message
    except Exception:  # noqa: BLE001
        return None


def _promo_blocked_for_cli(message: EngagementMessage, context: dict[str, Any]) -> bool:
    """True when SUPPORT/GITHUB-style promo must not be returned to CLI."""
    if not security_blocks_promo(context):
        return False
    if message.priority in PROMO_PRIORITIES or message.priority == PRIORITY_GITHUB:
        return True
    if message.cta is not None and message.cta.kind == CTA_SUPPORT:
        return True
    return False


def _best_message(
    messages: list[EngagementMessage],
    context: dict[str, Any],
) -> EngagementMessage | None:
    eligible = [m for m in messages if not _promo_blocked_for_cli(m, context)]
    if not eligible:
        return None
    return min(eligible, key=lambda m: PRIORITY_RANK.get(m.priority, 99))


def _html_report_written(result: dict) -> bool:
    if result.get("html_report") or result.get("html_written"):
        return True
    paths = result.get("report_paths") or result.get("paths") or {}
    if isinstance(paths, dict) and paths.get("html"):
        return True
    # Full audit always writes HTML under out_dir
    if str(result.get("mode") or "").lower() == "audit" and result.get("out_dir"):
        return True
    return False


def _context_from_result(result: dict, *, command: str) -> dict[str, Any]:
    findings = list(result.get("findings") or [])
    counts = result.get("severity_counts") or _severity_counts(findings)
    critical = int(counts.get("critical") or 0)
    high = int(counts.get("high") or 0)
    max_sev = _max_severity(counts, findings)

    fp_rejected = _fp_rejected_count(result)
    verified = _verified_count(result)
    attack_confirmed = _attack_paths_confirmed(result)
    files = _files_analyzed(result)
    flows = _data_flows(result)

    ctx: dict[str, Any] = {
        "command": command,
        "files_analyzed": files,
        "flows": flows,
        "data_flows": flows,
        "fp_rejected": fp_rejected,
        "rejected_count": fp_rejected,
        "verified_count": verified,
        "max_severity": max_sev,
        "critical_count": critical,
        "high_count": high,
        "security_primary": True,
        "attack_paths_confirmed": attack_confirmed,
        "used_attack_path": attack_confirmed > 0,
        "finding_count": int(result.get("finding_count") or len(findings)),
    }
    if critical > 0:
        ctx["showing_critical"] = True
        ctx["primary_priority"] = "CRITICAL_SECURITY"
    elif high > 0:
        ctx["showing_high"] = True
        ctx["primary_priority"] = "HIGH_SECURITY"
    if verified > 0:
        ctx["verified_finding"] = True
        ctx["first_verified"] = True
    fix_n = _fix_verified_count(result)
    if fix_n > 0:
        ctx["fix_verified"] = fix_n
    return ctx


def _severity_counts(findings: list[dict]) -> dict[str, int]:
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        sev = str(f.get("severity", "info")).lower()
        if sev not in counts:
            sev = "info"
        counts[sev] += 1
    return counts


def _max_severity(counts: dict[str, Any], findings: list[dict]) -> str | None:
    for sev in ("critical", "high", "medium", "low", "info"):
        if int(counts.get(sev) or 0) > 0:
            return sev.upper()
    if findings:
        return str(findings[0].get("severity") or "INFO").upper()
    return None


def _fp_rejected_count(result: dict) -> int:
    adv = result.get("adversary_summary") or {}
    n = int(adv.get("FALSE_POSITIVE") or 0)
    if n:
        return n
    # Final findings may carry adversary status
    findings = result.get("findings") or []
    tagged = sum(
        1
        for f in findings
        if str(f.get("adversary_status") or f.get("status") or "").upper()
        == "FALSE_POSITIVE"
    )
    if tagged:
        return tagged
    vs = result.get("verification_summary") or {}
    return int(vs.get("FALSE_POSITIVE") or 0)


def _verified_count(result: dict) -> int:
    vs = result.get("verification_summary") or {}
    n = int(vs.get("VERIFIED") or 0)
    if n:
        return n
    findings = result.get("findings") or []
    return sum(
        1
        for f in findings
        if str(f.get("verification_status") or f.get("status") or "").upper() == "VERIFIED"
    )


def _fix_verified_count(result: dict) -> int:
    """Optional remediations signal — never invent."""
    rem = result.get("remediation_summary") or result.get("fix_summary") or {}
    return int(rem.get("verified") or rem.get("FIX_VERIFIED") or 0)


def _attack_paths_confirmed(result: dict) -> int:
    summary = result.get("attack_graph_summary") or {}
    if not summary and isinstance(result.get("attack_graph"), dict):
        summary = (result["attack_graph"] or {}).get("summary") or {}
    if not summary:
        summary = result.get("summary") or {}
    by_status = summary.get("by_status") or {}
    return int(by_status.get("CONFIRMED") or 0)


def _files_analyzed(result: dict) -> int | None:
    for key in ("files_analyzed", "file_count"):
        if isinstance(result.get(key), int):
            return int(result[key])
    ams = result.get("application_model_summary")
    if isinstance(ams, dict) and isinstance(ams.get("file_count"), int):
        return int(ams["file_count"])
    files = {
        str(f.get("file"))
        for f in (result.get("findings") or [])
        if f.get("file")
    }
    return len(files) if files else None


def _data_flows(result: dict) -> int | None:
    dfs = result.get("dataflow_summary") or {}
    if isinstance(dfs.get("path_count"), int):
        return int(dfs["path_count"])
    if isinstance(result.get("flows"), int):
        return int(result["flows"])
    if isinstance(result.get("data_flows"), int):
        return int(result["data_flows"])
    return None
