"""Prepare a local contribution package — never push or open a PR.

Packages land under ``.findings/axguard/contribute/<id>/``.
Requires an explicit prepare call. Learning export requires privacy opt-in.
"""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4

_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")

from engines.contributors.extract import extract_pattern
from engines.contributors.milestones import record_prepare_milestone
from engines.contributors.privacy import (
    is_contribute_opted_in,
    is_learning_opted_in,
    learning_data_dir,
)
from engines.contributors.quality import assess_quality
from engines.contributors.sanitize import sanitize_example, sanitize_text
from engines.contributors.schema import (
    CONTRIBUTE_PACKAGE_DIRNAME,
    PROVENANCE_LOCAL_ONLY,
    PROVENANCE_SANITIZED,
    PROVENANCE_USER_APPROVED,
    TYPE_LABELS,
)
from engines.contributors.signals import best_opportunity
from engines.contributors.templates import render_template_files


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def default_package_root(project_root: Path | None = None) -> Path:
    root = Path(project_root) if project_root is not None else Path.cwd()
    return root / ".findings" / "axguard" / CONTRIBUTE_PACKAGE_DIRNAME


def prepare(
    context: dict[str, Any] | None = None,
    *,
    contribution_type: str | None = None,
    project_root: Path | None = None,
    package_id: str | None = None,
    privacy_path: Path | None = None,
    contribute_state_path: Path | None = None,
    require_opt_in: bool = True,
    write_learning_copy: bool = False,
) -> dict[str, Any]:
    """Prepare a local contribution package. Never opens sockets or pushes.

    ``require_opt_in``: when True, contribute opt-in is required.
    Learning export copy also requires learning opt-in.
    """
    ctx = dict(context or {})
    if require_opt_in and not is_contribute_opted_in(privacy_path):
        return {
            "ok": False,
            "error": "contribute_opt_in_required",
            "hint": "Run: axguard privacy opt-in",
        }

    signal = best_opportunity(ctx)
    ctype = contribution_type or (signal.contribution_type if signal else None)
    if not ctype:
        ctype = "DOCUMENTATION"
    difficulty = signal.difficulty if signal and signal.contribution_type == ctype else "MEDIUM"
    reason = signal.reason if signal else "Manual local contribution package."

    qa = None
    if signal is not None:
        qa = assess_quality(signal, ctx)

    pattern = extract_pattern(ctx)
    known_private = []
    for key in ("repo", "repo_name", "org", "project_name"):
        val = ctx.get(key)
        if isinstance(val, str) and val.strip():
            known_private.append(val.strip())

    example = {
        "contribution_type": ctype,
        "difficulty": difficulty,
        "reason": reason,
        "pattern": pattern,
        "code": ctx.get("snippet") or ctx.get("code") or "",
        "title": ctx.get("title") or TYPE_LABELS.get(ctype, ctype),
        "repo": ctx.get("repo") or ctx.get("repo_name") or "",
        "file": ctx.get("file") or ctx.get("path") or "",
        "provenance": PROVENANCE_LOCAL_ONLY,
        "created_at": _utc_now_iso(),
    }
    sanitized, hits = sanitize_example(example, known_private_names=known_private)
    sanitized["provenance"] = PROVENANCE_SANITIZED
    if is_contribute_opted_in(privacy_path):
        sanitized["provenance"] = PROVENANCE_USER_APPROVED
        # Keep sanitized marker alongside approval for transparency
        sanitized["sanitized"] = True
        sanitized["scrub_hits"] = list(dict.fromkeys(hits))[:20]

    if qa is not None:
        sanitized["quality_scores"] = qa.as_dict()

    pkg_id = package_id or f"c_{uuid4().hex[:12]}"
    if not _SAFE_ID.match(pkg_id) or ".." in pkg_id or "/" in pkg_id or "\\" in pkg_id:
        return {
            "ok": False,
            "error": "invalid_package_id",
            "hint": "package_id must be a short alphanumeric id (no path separators).",
        }
    root = default_package_root(project_root).resolve()
    out_dir = (root / pkg_id).resolve()
    if not out_dir.is_relative_to(root):
        return {
            "ok": False,
            "error": "invalid_package_id",
            "hint": "package_id must stay under the contribute package directory.",
        }
    out_dir.mkdir(parents=True, exist_ok=True)

    # Template stubs
    files = render_template_files(
        ctype,
        substitutions={
            "pattern": str(pattern.get("pattern") or "pattern"),
            "case": str(pattern.get("pattern") or ctype.lower()),
            "name": str(sanitized.get("title") or ctype),
            "topic": str(sanitized.get("title") or ctype),
            "framework": str(pattern.get("framework") or "framework"),
            "behavior": reason[:80],
            "path": "path",
            "workflow": "workflow",
        },
    )
    written: list[str] = []
    for name, body in files.items():
        # Flat filenames only — reject path traversal in template names
        if not name or name != Path(name).name or ".." in name:
            continue
        clean_body, _ = sanitize_text(body, known_private_names=known_private)
        target = (out_dir / name).resolve()
        if not target.is_relative_to(out_dir):
            continue
        target.write_text(clean_body, encoding="utf-8")
        written.append(str(target))

    meta_path = out_dir / "contribution.json"
    meta_path.write_text(
        json.dumps(sanitized, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    written.append(str(meta_path))

    note_path = out_dir / "LOCAL_ONLY.txt"
    note_path.write_text(
        "This package was prepared locally by AXGuard.\n"
        "Nothing was pushed to GitHub.\n"
        "Nothing was opened as a pull request.\n"
        "Review, edit, and share only if you choose to.\n",
        encoding="utf-8",
    )
    written.append(str(note_path))

    learning_copy = None
    if write_learning_copy or ctx.get("export_learning"):
        if not is_learning_opted_in(privacy_path):
            return {
                "ok": False,
                "error": "learning_opt_in_required",
                "hint": "Run: axguard privacy opt-in --learning",
                "package_dir": str(out_dir),
                "files": written,
            }
        learn_dir = learning_data_dir(privacy_path)
        learn_dir.mkdir(parents=True, exist_ok=True)
        learning_copy = learn_dir / f"{pkg_id}.json"
        learning_copy.write_text(
            json.dumps(sanitized, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        written.append(str(learning_copy))

    record_prepare_milestone(ctype, path=contribute_state_path)

    return {
        "ok": True,
        "id": pkg_id,
        "package_dir": str(out_dir),
        "contribution_type": ctype,
        "difficulty": difficulty,
        "files": written,
        "learning_copy": str(learning_copy) if learning_copy else None,
        "network": False,
        "pushed": False,
        "pr_opened": False,
        "provenance": sanitized.get("provenance"),
    }
