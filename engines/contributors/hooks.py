"""Soft hooks after audit / adversary / memory signals.

Respects contributions.prompts, invite cooldown, engage disable, and --no-engage.
Never weakens security-first promo blocking.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from engines.contributors.privacy import prompts_allowed
from engines.contributors.recognize import build_recognition_message
from engines.contributors.suggest import suggest
from engines.engagement.hooks import _context_from_result, _promo_blocked_for_cli
from engines.engagement.engine import render_cli
from engines.engagement.state import load_state


def _engage_disabled(state_path: Path | None = None) -> bool:
    try:
        state = load_state(state_path)
        return bool(state.get("promo_disabled")) or state.get("state") == "DISABLED"
    except Exception:  # noqa: BLE001
        return False


def emit_after_audit_soft(
    result: dict[str, Any],
    *,
    state_path: Path | None = None,
    privacy_path: Path | None = None,
    no_engage: bool = False,
    session_id: str | None = None,
) -> str | None:
    """Soft contribute recognition/invite after audit. Never raises."""
    try:
        if no_engage:
            return None
        if _engage_disabled(state_path):
            return None
        if not prompts_allowed(privacy_path):
            return None

        ctx = _context_from_result(result, command="audit")
        # Prefer invite when quality is strong; else quiet recognition
        invite = suggest(
            ctx,
            privacy_path=privacy_path,
            session_id=session_id or "audit",
        )
        if invite is not None:
            return invite.message

        msg = build_recognition_message(ctx, with_cta=True)
        if msg is None:
            return None
        if _promo_blocked_for_cli(msg, ctx):
            # Still allow non-SUPPORT recognition; only block if policy says so
            # Contribute CTA is not a star ask — keep product-info recognition.
            if msg.priority in {"GITHUB", "YC", "AWAREXONE"}:
                return None
        text = render_cli(msg).strip()
        return text or None
    except Exception:  # noqa: BLE001
        return None


def emit_after_adversary_soft(
    result: dict[str, Any],
    *,
    state_path: Path | None = None,
    privacy_path: Path | None = None,
    no_engage: bool = False,
    session_id: str | None = None,
) -> str | None:
    """Soft hook when adversary rejects FPs."""
    try:
        if no_engage or _engage_disabled(state_path) or not prompts_allowed(privacy_path):
            return None
        ctx = _context_from_result(result, command="adversary")
        if int(ctx.get("fp_rejected") or 0) <= 0:
            return None
        invite = suggest(ctx, privacy_path=privacy_path, session_id=session_id or "adversary")
        if invite is not None:
            return invite.message
        msg = build_recognition_message(ctx)
        return render_cli(msg).strip() or None if msg else None
    except Exception:  # noqa: BLE001
        return None


def emit_after_memory_soft(
    result: dict[str, Any],
    *,
    state_path: Path | None = None,
    privacy_path: Path | None = None,
    no_engage: bool = False,
    session_id: str | None = None,
) -> str | None:
    """Soft hook for memory regressions / longitudinal signals."""
    try:
        if no_engage or _engage_disabled(state_path) or not prompts_allowed(privacy_path):
            return None
        ctx = dict(result or {})
        regs = result.get("regressions") or result.get("regression_summary") or {}
        if isinstance(regs, dict):
            count = int(regs.get("count") or regs.get("regression_count") or len(regs.get("items") or []))
        elif isinstance(regs, list):
            count = len(regs)
        else:
            count = int(result.get("regression_count") or 0)
        if count <= 0 and not result.get("regression"):
            return None
        ctx["regression"] = True
        ctx["regression_count"] = count
        invite = suggest(ctx, privacy_path=privacy_path, session_id=session_id or "memory")
        if invite is not None:
            return invite.message
        msg = build_recognition_message(ctx)
        return render_cli(msg).strip() or None if msg else None
    except Exception:  # noqa: BLE001
        return None
