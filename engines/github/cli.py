"""Thin CLI helpers for ``axguard github …`` (setup / validate / test / status).

Prefers ``engines.github.cli_runners`` when present (pipeline-owned runners).
Falls back to local config/permission checks so docs + CLI stay usable while
the adapter lands. Does not own webhook/pipeline internals.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any

EXAMPLE_AXGUARD_YML = """\
# AXGuard project config (optional)
# Docs: docs/github/config.md

github:
  # Env var *names* only — never put secrets in this file
  app_id_env: AXGUARD_GITHUB_APP_ID
  private_key_path_env: AXGUARD_GITHUB_PRIVATE_KEY_PATH
  private_key_env: AXGUARD_GITHUB_PRIVATE_KEY
  webhook_secret_env: AXGUARD_GITHUB_WEBHOOK_SECRET
  webhook_host: 127.0.0.1
  webhook_port: 8787

review:
  enabled: true
  on_pull_request: true
  on_push: false
  check_name: "AXGuard Security Review"
  include_footer: true

preship:
  enabled: true
  check_name: "AXGuard Pre-Ship"

watch:
  enabled: false
  on_push: true
  on_release: true
  check_name: "AXGuard Watch"

policy:
  fail_on: [critical, high]
  review_on: [likely]
  fail_on_analysis_error: false
  fail_on_unverified: false
  medium_fail: false

analysis:
  mode: balanced   # fast | balanced | deep
  max_changed_files: 200
  max_annotations: 50

ai:
  provider: none   # none | local | openai | anthropic | openrouter | ollama
  mode: no-llm     # no-llm | local | user_key
  model: null
  api_key_env: AXGUARD_AI_API_KEY
  base_url_env: AXGUARD_AI_BASE_URL

privacy:
  retain_source: false
  log_source: false
"""


def _print(msg: str = "") -> None:
    print(msg)


def _err(msg: str) -> None:
    print(f"error: {msg}", file=sys.stderr)


def _runners():
    try:
        from engines.github import cli_runners as runners

        return runners
    except ImportError:
        return None


def setup_github(
    *,
    target: Path | None = None,
    force: bool = False,
    write_example: bool = True,
) -> int:
    """Print setup steps and optionally write ``.axguard.yml`` example."""
    root = (target or Path.cwd()).resolve()
    _print("AXGuard GitHub Security Bot — setup")
    _print()
    _print("1. Create a GitHub App (dev) with minimum permissions:")
    try:
        from engines.github.permissions import MINIMUM_PERMISSIONS, REASONS

        for name, level in MINIMUM_PERMISSIONS.items():
            reason = (REASONS.get(name) or "").split(".")[0]
            _print(f"   - {name}: {level}  # {reason}")
    except Exception:  # noqa: BLE001
        _print("   - contents: read")
        _print("   - metadata: read")
        _print("   - pull_requests: write  # summary comment only")
        _print("   - checks: write")
    _print()
    _print("2. Subscribe to pull_request (opened, synchronize, reopened).")
    _print()
    _print("3. Set secrets in the environment (never commit them):")
    _print("   export AXGUARD_GITHUB_APP_ID=...")
    _print("   export AXGUARD_GITHUB_WEBHOOK_SECRET=...")
    _print("   export AXGUARD_GITHUB_PRIVATE_KEY_PATH=/path/to/app.pem")
    _print("   # or: export AXGUARD_GITHUB_PRIVATE_KEY=\"$(cat app.pem)\"")
    _print()
    _print("4. Point the App webhook at your self-hosted adapter URL.")
    _print("   See docs/github/self-hosting.md and docs/github/install.md")
    _print()
    _print("Research: docs/research/github-security-bot.md")
    _print("Docs index: docs/github/README.md")

    if write_example:
        out = root / ".axguard.yml"
        runners = _runners()
        if runners is not None and not out.exists():
            # cli_runners expects the *file* path
            info = runners.cmd_setup(out, write=True)
            _print()
            if info.get("created"):
                _print(f"wrote example config: {out}")
            else:
                _print(f"config: {out} (exists={info.get('exists')})")
        elif out.exists() and not force:
            _print()
            _print(f"config: {out} already exists (use --force to overwrite example)")
        else:
            out.write_text(EXAMPLE_AXGUARD_YML, encoding="utf-8")
            _print()
            _print(f"wrote example config: {out}")
    return 0


def validate_github(*, path: Path | None = None, config_path: Path | None = None) -> int:
    """Validate config + credential env presence (does not call GitHub)."""
    root = (path or Path.cwd()).resolve()
    runners = _runners()
    if runners is not None:
        try:
            from engines.github.config import find_config_path

            cfg_file = Path(config_path) if config_path else find_config_path(root)
            data = runners.cmd_validate(cfg_file)
        except Exception as exc:  # noqa: BLE001
            _err(f"validate failed: {exc}")
            return 2
        _print("AXGuard GitHub — validate")
        _print(f"  config file: {data.get('config_path') or '(defaults)'}")
        _print(f"  ai mode:     {data.get('ai_mode')}")
        _print(f"  review:      {data.get('review_enabled')}")
        problems = data.get("problems") or []
        if problems:
            _print("problems:")
            for p in problems:
                _print(f"  - {p}")
            return 1
        _print("ok: config and credential presence look valid (no live API call)")
        return 0 if data.get("ok", False) else 1

    # Fallback (no cli_runners)
    problems: list[str] = []
    notes: list[str] = []
    try:
        from engines.github.config import find_config_path, load_github_config
    except ImportError as exc:
        _err(f"engines.github.config unavailable: {exc}")
        return 2

    cfg_file = Path(config_path) if config_path else find_config_path(root)
    try:
        cfg = load_github_config(cfg_file)
    except Exception as exc:  # noqa: BLE001
        _err(f"failed to load config: {exc}")
        return 2

    notes.append(f"config file: {cfg_file or '(none — using defaults)'}")
    env = cfg.github
    if not os.environ.get(env.app_id_env, "").strip():
        problems.append(f"missing env {env.app_id_env}")
    if not os.environ.get(env.webhook_secret_env, "").strip():
        problems.append(f"missing env {env.webhook_secret_env}")
    pem = os.environ.get(env.private_key_env, "").strip()
    pem_path = os.environ.get(env.private_key_path_env, "").strip()
    if not pem and not pem_path:
        problems.append(
            f"missing private key ({env.private_key_env} or {env.private_key_path_env})"
        )
    elif pem_path and not Path(pem_path).expanduser().is_file():
        problems.append(f"private key path not found: {pem_path}")

    if cfg.privacy.log_source:
        problems.append("privacy.log_source must be false (never log source)")

    _print("AXGuard GitHub — validate")
    for n in notes:
        _print(f"  {n}")
    _print(f"  ai mode: {cfg.ai_provider_mode}")
    if problems:
        _print("problems:")
        for p in problems:
            _print(f"  - {p}")
        return 1
    _print("ok: config and credential presence look valid (no live API call)")
    return 0


def test_github(*, path: Path | None = None, config_path: Path | None = None) -> int:
    """Local dry-run: prefer cli_runners.run_review when available."""
    root = (path or Path.cwd()).resolve()
    runners = _runners()
    if runners is not None:
        try:
            data = runners.cmd_test(
                root, config=Path(config_path) if config_path else None
            )
        except Exception as exc:  # noqa: BLE001
            _err(f"local review failed: {exc}")
            return 2
        _print("AXGuard GitHub — test (local REVIEW, no GitHub network)")
        _print(f"  verdict    {data.get('verdict')}")
        _print(f"  mode       {data.get('mode')}")
        _print(f"  findings   {data.get('findings')}")
        _print(f"  rejected   {data.get('rejected')}")
        _print(f"  regressions {data.get('regressions')}")
        _print(f"  ai         {data.get('ai_mode')}")
        if data.get("summary"):
            _print("  summary:")
            for line in str(data["summary"]).splitlines()[:12]:
                _print(f"    {line}")
        return 0 if data.get("ok", False) else 1

    # Soft fallback
    try:
        from engines.github.config import find_config_path, load_github_config
    except ImportError as exc:
        _err(f"engines.github.config unavailable: {exc}")
        return 2
    cfg_file = Path(config_path) if config_path else find_config_path(root)
    cfg = load_github_config(cfg_file)
    _print("AXGuard GitHub — test (local dry-run)")
    _print(f"  review.enabled   {cfg.review.enabled}")
    _print(f"  analysis.mode    {cfg.analysis.mode}")
    _print(f"  ai               {cfg.ai_provider_mode}")
    _print("ok: config loaded (pipeline runners not available for full REVIEW)")
    return 0


def status_github(*, path: Path | None = None, config_path: Path | None = None) -> int:
    """Print adapter/config status summary (no secrets)."""
    root = (path or Path.cwd()).resolve()
    runners = _runners()
    if runners is not None:
        try:
            from engines.github.config import find_config_path

            cfg_file = Path(config_path) if config_path else find_config_path(root)
            data = runners.cmd_status(cfg_file)
        except Exception as exc:  # noqa: BLE001
            _err(f"status failed: {exc}")
            return 2
        env_present = data.get("env_present") or {}
        _print("AXGuard GitHub — status")
        _print(f"  config           {data.get('config_path') or '(defaults)'}")
        review = data.get("review") or {}
        watch = data.get("watch") or {}
        preship = data.get("preship") or {}
        _print(
            f"  modes            review={review.get('enabled')} "
            f"preship={preship.get('enabled')} watch={watch.get('enabled')}"
        )
        policy = data.get("policy") or {}
        _print(f"  policy.fail_on   {policy.get('fail_on')}")
        ai = data.get("ai") or {}
        _print(f"  ai               {ai.get('mode')} ({ai.get('provider')})")
        privacy = data.get("privacy") or {}
        _print(f"  privacy          retain_source={privacy.get('retain_source')}")
        _print(
            "  credentials      "
            + " ".join(f"{k}={'yes' if v else 'no'}" for k, v in env_present.items())
        )
        ready = all(bool(v) for v in env_present.values()) if env_present else False
        try:
            from engines.github import server as _server  # noqa: F401

            _print("  adapter server   module present")
        except ImportError:
            _print("  adapter server   not loaded")
        _print(
            f"  ready            "
            f"{'yes' if ready else 'no — run: axguard github setup'}"
        )
        return 0 if ready else 1

    # Fallback
    try:
        from engines.github.config import find_config_path, load_github_config
    except ImportError as exc:
        _err(f"engines.github.config unavailable: {exc}")
        return 2
    cfg_file = Path(config_path) if config_path else find_config_path(root)
    cfg = load_github_config(cfg_file)
    env = cfg.github
    app_set = bool(os.environ.get(env.app_id_env, "").strip())
    secret_set = bool(os.environ.get(env.webhook_secret_env, "").strip())
    key_set = bool(
        os.environ.get(env.private_key_env, "").strip()
        or (
            os.environ.get(env.private_key_path_env, "").strip()
            and Path(os.environ.get(env.private_key_path_env, "")).expanduser().is_file()
        )
    )
    _print("AXGuard GitHub — status")
    _print(f"  config           {cfg_file or '(defaults)'}")
    _print(f"  webhook bind     {env.webhook_host}:{env.webhook_port}")
    _print(
        f"  credentials      app_id={'yes' if app_set else 'no'} "
        f"webhook_secret={'yes' if secret_set else 'no'} "
        f"private_key={'yes' if key_set else 'no'}"
    )
    ready = app_set and secret_set and key_set
    _print(f"  ready            {'yes' if ready else 'no — run: axguard github setup'}")
    return 0 if ready else 1


def run_github_command(action: str, args: Any) -> int:
    """Dispatch ``axguard github <action>``."""
    path = Path(getattr(args, "path", ".") or ".").resolve()
    config_path = getattr(args, "config", None)
    cfg = Path(config_path) if config_path else None

    if getattr(args, "json", False):
        runners = _runners()
        if runners is None:
            _err("--json requires engines.github.cli_runners")
            return 2
        if action == "setup":
            data = runners.cmd_setup(
                path / ".axguard.yml",
                write=not bool(getattr(args, "no_write", False)),
            )
        elif action == "validate":
            from engines.github.config import find_config_path

            data = runners.cmd_validate(cfg or find_config_path(path))
        elif action == "test":
            data = runners.cmd_test(path, config=cfg)
        elif action == "status":
            from engines.github.config import find_config_path

            data = runners.cmd_status(cfg or find_config_path(path))
        else:
            _err(f"unknown github command: {action}")
            return 2
        print(json.dumps(data, indent=2, default=str))
        if action in {"validate", "test", "status"}:
            return 0 if data.get("ok", action == "status") else 1
        return 0

    if action == "setup":
        return setup_github(
            target=path,
            force=bool(getattr(args, "force", False)),
            write_example=not bool(getattr(args, "no_write", False)),
        )
    if action == "validate":
        return validate_github(path=path, config_path=cfg)
    if action == "test":
        return test_github(path=path, config_path=cfg)
    if action == "status":
        return status_github(path=path, config_path=cfg)

    _err(f"unknown github command: {action}")
    return 2


__all__ = [
    "EXAMPLE_AXGUARD_YML",
    "run_github_command",
    "setup_github",
    "status_github",
    "test_github",
    "validate_github",
]
