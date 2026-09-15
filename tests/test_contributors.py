"""Tests for the Contributor Engagement & Learning System."""

from __future__ import annotations

import ast
import json
import socket
from pathlib import Path

import pytest

from engines.contributors.milestones import clear_state as clear_contribute_state
from engines.contributors.prepare import prepare
from engines.contributors.privacy import (
    delete_learning_data,
    is_contribute_opted_in,
    is_learning_opted_in,
    learning_data_dir,
    opt_in,
    reset as privacy_reset,
    status as privacy_status,
)
from engines.contributors.quality import filter_strong
from engines.contributors.recognize import (
    CONTRIBUTE_MESSAGE_CATALOG,
    build_recognition_message,
)
from engines.contributors.sanitize import sanitize_example, sanitize_text
from engines.contributors.schema import FORBIDDEN_CONTRIBUTE_PHRASES
from engines.contributors.signals import signals_from_context
from engines.contributors.suggest import dismiss, suggest
from engines.engagement.messages import MESSAGE_CATALOG
from engines.engagement.policy import contains_banned_pattern, reject_if_manipulative

ROOT = Path(__file__).resolve().parents[1]
CONTRIB_PKG = ROOT / "engines" / "contributors"


@pytest.fixture
def privacy_path(tmp_path: Path) -> Path:
    return tmp_path / "privacy.json"


@pytest.fixture
def contribute_state_path(tmp_path: Path) -> Path:
    return tmp_path / "contribute-state.json"


# ---------------------------------------------------------------------------
# Recognition
# ---------------------------------------------------------------------------


def test_recognition_on_meaningful_fp_discovery():
    msg = build_recognition_message({"fp_rejected": 2, "rejected_count": 2})
    assert msg is not None
    text = "\n".join(msg.body_lines).lower()
    assert "false positive" in text
    assert msg.cta is not None
    assert msg.cta.kind == "CONTRIBUTE"


def test_recognition_on_verified_finding():
    msg = build_recognition_message({"verified_count": 1, "novel_finding": True})
    assert msg is not None
    text = "\n".join(msg.body_lines).lower()
    assert "verified" in text


# ---------------------------------------------------------------------------
# Suggest / cooldown / dismissal
# ---------------------------------------------------------------------------


def test_suggest_type_cooldown_and_dismissal(
    privacy_path: Path,
    contribute_state_path: Path,
):
    ctx = {"fp_rejected": 3, "security_primary": True}
    invite = suggest(
        ctx,
        privacy_path=privacy_path,
        state_path=contribute_state_path,
        session_id="s1",
    )
    assert invite is not None
    assert invite.contribution_type == "FALSE_POSITIVE_FIX"
    assert "Suggested contribution" in invite.message

    # Cooldown / max 1 per session — no spam
    second = suggest(
        ctx,
        privacy_path=privacy_path,
        state_path=contribute_state_path,
        session_id="s1",
    )
    assert second is None

    dismiss("not_now", privacy_path=privacy_path, state_path=contribute_state_path)
    third = suggest(
        ctx,
        privacy_path=privacy_path,
        state_path=contribute_state_path,
        session_id="s2",
        force=False,
    )
    assert third is None  # still in cooldown from not_now

    # Type dismiss — even with force, type stays suppressed
    # Reset cooldown by clearing last_invite (simulate) via dismiss type on fresh state
    clear_contribute_state(contribute_state_path)
    invite2 = suggest(
        ctx,
        privacy_path=privacy_path,
        state_path=contribute_state_path,
        session_id="s3",
        force=True,
    )
    assert invite2 is not None
    dismiss(
        "type",
        contribution_type="FALSE_POSITIVE_FIX",
        privacy_path=privacy_path,
        state_path=contribute_state_path,
    )
    clear_contribute_state(contribute_state_path)
    suppressed = suggest(
        ctx,
        privacy_path=privacy_path,
        state_path=contribute_state_path,
        session_id="s4",
        force=True,
    )
    assert suppressed is None

    dismiss("never_prompts", privacy_path=privacy_path, state_path=contribute_state_path)
    never = suggest(
        {"verified_count": 2, "novel_finding": True, "test_gap": True},
        privacy_path=privacy_path,
        state_path=contribute_state_path,
        force=False,
    )
    assert never is None


# ---------------------------------------------------------------------------
# Privacy / learning opt-in
# ---------------------------------------------------------------------------


def test_privacy_opt_in_required_for_pack_and_learning(privacy_path: Path, tmp_path: Path):
    assert is_contribute_opted_in(privacy_path) is False
    blocked = prepare(
        {"fp_rejected": 2, "snippet": "x = 1"},
        project_root=tmp_path,
        privacy_path=privacy_path,
        require_opt_in=True,
    )
    assert blocked["ok"] is False
    assert blocked["error"] == "contribute_opt_in_required"

    opt_in(contribute=True, learning=False, path=privacy_path)
    assert is_contribute_opted_in(privacy_path) is True
    assert is_learning_opted_in(privacy_path) is False

    learning_blocked = prepare(
        {"fp_rejected": 2, "snippet": "ok"},
        project_root=tmp_path,
        privacy_path=privacy_path,
        write_learning_copy=True,
    )
    assert learning_blocked["ok"] is False
    assert learning_blocked["error"] == "learning_opt_in_required"

    opt_in(contribute=True, learning=True, path=privacy_path)
    assert is_learning_opted_in(privacy_path) is True
    ok = prepare(
        {"fp_rejected": 2, "snippet": "ok"},
        contribution_type="FALSE_POSITIVE_FIX",
        project_root=tmp_path,
        privacy_path=privacy_path,
        write_learning_copy=True,
    )
    assert ok["ok"] is True
    assert ok["learning_copy"]
    assert Path(ok["learning_copy"]).is_file()


def test_delete_reset_clears_learning_data(privacy_path: Path, tmp_path: Path):
    # Point learning dir under tmp by placing privacy.json under tmp_path
    opt_in(contribute=True, learning=True, path=privacy_path)
    learn = learning_data_dir(privacy_path)
    learn.mkdir(parents=True, exist_ok=True)
    sample = learn / "sample.json"
    sample.write_text("{}\n", encoding="utf-8")
    assert sample.is_file()

    assert delete_learning_data(privacy_path) is True
    assert not learn.is_dir()

    # recreate and reset
    opt_in(contribute=True, learning=True, path=privacy_path)
    learn.mkdir(parents=True, exist_ok=True)
    (learn / "x.json").write_text("{}\n", encoding="utf-8")
    st = privacy_reset(path=privacy_path)
    assert st["contribute_opt_in"] is False
    assert st["learning"]["contribution_data"]["enabled"] is False
    assert not learning_data_dir(privacy_path).is_dir()


# ---------------------------------------------------------------------------
# Sanitize
# ---------------------------------------------------------------------------


def test_secrets_scrubbed_and_private_repo_minimized():
    text, hits = sanitize_text(
        "token=sk-abcdefghijklmnopqrstuvwxyz012345 "
        "path=/Users/alice/secret-project/app.py "
        "see github.com/acme-corp/private-app",
        known_private_names=["private-app", "acme-corp"],
    )
    assert "sk-" not in text or "REDACTED" in text
    assert "/Users/alice" not in text
    assert "REDACTED_PATH" in text or "REDACTED_DIR" in text
    assert "private-app" not in text.lower() or "REDACTED" in text
    assert hits or "REDACTED" in text

    cleaned, _ = sanitize_example(
        {
            "code": "password = 'hunter2'\napi_key=sk-abcdefghijklmnopqrstuvwxyz012345",
            "repo": "acme-corp/private-app",
            "file": "/Users/alice/work/private-app/main.py",
            "author_email": "alice@example.com",
        },
        known_private_names=["acme-corp", "private-app"],
    )
    assert "author_email" not in cleaned
    blob = json.dumps(cleaned)
    assert "hunter2" not in blob
    assert "sk-abcdef" not in blob
    assert "/Users/alice" not in blob


# ---------------------------------------------------------------------------
# Prepare local only
# ---------------------------------------------------------------------------


def test_prepare_creates_files_locally_only(privacy_path: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    opt_in(contribute=True, path=privacy_path)

    opened: list[tuple] = []

    def _boom(*a, **k):
        opened.append((a, k))
        raise AssertionError("network forbidden")

    monkeypatch.setattr(socket, "socket", _boom)
    monkeypatch.setattr(socket, "create_connection", _boom)

    result = prepare(
        {
            "fp_rejected": 2,
            "snippet": "if user.is_admin: return",
            "file": "app/views.py",
            "repo": "acme/secret",
        },
        contribution_type="FALSE_POSITIVE_FIX",
        project_root=tmp_path,
        privacy_path=privacy_path,
    )
    assert result["ok"] is True
    assert result["network"] is False
    assert result["pushed"] is False
    assert result["pr_opened"] is False
    assert opened == []

    pkg = Path(result["package_dir"])
    assert pkg.is_dir()
    assert (pkg / "contribution.json").is_file()
    assert (pkg / "LOCAL_ONLY.txt").is_file()
    assert (pkg / "COMMIT_MSG.txt").is_file()
    assert (pkg / "PR_DRAFT.md").is_file()
    assert str(pkg).startswith(str(tmp_path / ".findings" / "axguard" / "contribute"))
    assert result["id"]


def test_prepare_rejects_path_traversal_package_id(privacy_path: Path, tmp_path: Path):
    opt_in(contribute=True, path=privacy_path)
    bad = prepare(
        {"fp_rejected": 1},
        contribution_type="DOCUMENTATION",
        project_root=tmp_path,
        privacy_path=privacy_path,
        package_id="../escape",
    )
    assert bad["ok"] is False
    assert bad["error"] == "invalid_package_id"
    assert not (tmp_path / "escape").exists()
    assert not list((tmp_path / ".findings").rglob("*")) if not (tmp_path / ".findings").exists() else True


def test_suggest_prepare_do_not_open_sockets(privacy_path: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    opt_in(contribute=True, path=privacy_path)
    state_path = tmp_path / "cstate.json"
    calls: list[str] = []

    def _boom(*_a, **_k):
        calls.append("socket")
        raise AssertionError("socket forbidden")

    monkeypatch.setattr(socket, "socket", _boom)
    monkeypatch.setattr(socket, "create_connection", _boom)

    invite = suggest(
        {"attack_paths_confirmed": 2},
        privacy_path=privacy_path,
        state_path=state_path,
        session_id="sock",
        force=True,
    )
    assert invite is not None
    prepare(
        {"attack_paths_confirmed": 2},
        contribution_type="ATTACK_PATH_PATTERN",
        project_root=tmp_path,
        privacy_path=privacy_path,
    )
    assert calls == []


# ---------------------------------------------------------------------------
# No manipulative copy
# ---------------------------------------------------------------------------


def test_no_manipulative_copy_in_catalogs():
    for mid, msg in {**MESSAGE_CATALOG, **CONTRIBUTE_MESSAGE_CATALOG}.items():
        reason = reject_if_manipulative(msg)
        assert reason is None, f"{mid}: {reason}"
        text = "\n".join(msg.body_lines).lower()
        for phrase in FORBIDDEN_CONTRIBUTE_PHRASES:
            assert phrase not in text, f"{mid} contains forbidden phrase {phrase!r}"
        assert not contains_banned_pattern(text)


def test_quality_gate_filters_weak_noise():
    weak = signals_from_context({})
    assert filter_strong(weak, {}) == []
    strong = filter_strong(signals_from_context({"fp_rejected": 4, "security_primary": True}), {"fp_rejected": 4})
    assert strong
    assert strong[0][0].contribution_type == "FALSE_POSITIVE_FIX"


# ---------------------------------------------------------------------------
# AST: no network imports in contributors package
# ---------------------------------------------------------------------------


def test_contributors_modules_have_no_network_imports():
    forbidden = {"urllib", "urllib.request", "requests", "httpx", "aiohttp"}
    offenders: list[str] = []
    for py in sorted(CONTRIB_PKG.glob("*.py")):
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
    assert not offenders, offenders


def test_privacy_status_explains_fields(privacy_path: Path):
    st = privacy_status(privacy_path)
    assert "included" in st["fields"]
    assert "excluded" in st["fields"]
    assert "author_email" in st["fields"]["excluded"]
    assert st["contributions"]["auto_push"] is False
    assert st["contributions"]["auto_pr"] is False
    assert st["learning"]["contribution_data"]["enabled"] is False
