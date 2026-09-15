"""CLI runners for ``axguard github {setup,validate,test,status}``.

Kept separate so ``cli/main.py`` can stay thin and conflict-free.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from engines.github.config import (
    CONFIG_FILENAMES,
    GitHubBotConfig,
    find_config_path,
    load_github_config,
    resolve_ai_credentials,
)
from engines.github.permissions import MINIMUM_PERMISSIONS, as_manifest_permissions
from engines.github.pipeline import run_review


EXAMPLE_CONFIG = """\
# AXGuard GitHub Security Bot — repository config
review:
  enabled: true
  on_pull_request: true
  include_footer: true

preship:
  enabled: true

watch:
  enabled: false
  on_push: true
  on_release: true

policy:
  fail_on: [critical, high]
  fail_on_analysis_error: false
  fail_on_unverified: false

analysis:
  mode: balanced
  max_changed_files: 200

ai:
  provider: none
  mode: no-llm

privacy:
  retain_source: false
  log_source: false

github:
  webhook_host: 127.0.0.1
  webhook_port: 8787
"""


def cmd_setup(path: Path | None = None, *, write: bool = True) -> dict[str, Any]:
    """Print/write example ``.axguard.yml`` and env var checklist."""
    target = (path or Path.cwd() / ".axguard.yml").resolve()
    created = False
    if write and not target.exists():
        target.write_text(EXAMPLE_CONFIG, encoding="utf-8")
        created = True
    env_needed = [
        "AXGUARD_GITHUB_APP_ID",
        "AXGUARD_GITHUB_WEBHOOK_SECRET",
        "AXGUARD_GITHUB_PRIVATE_KEY_PATH  (or AXGUARD_GITHUB_PRIVATE_KEY)",
    ]
    return {
        "config_path": str(target),
        "created": created,
        "exists": target.exists(),
        "permissions": MINIMUM_PERMISSIONS,
        "env": env_needed,
        "manifest": as_manifest_permissions(),
        "example": EXAMPLE_CONFIG if not created else None,
    }


def cmd_validate(path: Path | None = None) -> dict[str, Any]:
    """Validate config + environment (no network)."""
    cfg_path = Path(path) if path else find_config_path()
    problems: list[str] = []
    cfg: GitHubBotConfig | None = None
    try:
        cfg = load_github_config(cfg_path)
    except Exception as exc:  # noqa: BLE001
        problems.append(f"config: {exc}")
        return {"ok": False, "problems": problems, "config_path": str(cfg_path) if cfg_path else None}

    assert cfg is not None
    for env_name in (
        cfg.github.app_id_env,
        cfg.github.webhook_secret_env,
    ):
        if not os.environ.get(env_name):
            problems.append(f"missing_env:{env_name}")
    key = os.environ.get(cfg.github.private_key_env)
    key_path = os.environ.get(cfg.github.private_key_path_env)
    if not key and not (key_path and Path(key_path).expanduser().is_file()):
        problems.append("missing_env:private_key")

    ai = resolve_ai_credentials(cfg)
    if ai["mode"] != "no-llm" and not ai.get("api_key") and ai["mode"] == "user_key":
        problems.append(f"missing_env:{cfg.ai.api_key_env}")

    return {
        "ok": not problems,
        "problems": problems,
        "config_path": str(cfg_path) if cfg_path else None,
        "ai_mode": ai["mode"],
        "review_enabled": cfg.review.enabled,
        "watch_enabled": cfg.watch.enabled,
        "fail_on_analysis_error": cfg.policy.fail_on_analysis_error,
    }


def cmd_test(target: Path | str = ".", *, config: Path | None = None) -> dict[str, Any]:
    """Run a local REVIEW-mode analysis (no GitHub network)."""
    cfg = load_github_config(config)
    result = run_review(target, config=cfg)
    return {
        "ok": not result.analysis_failed,
        "verdict": result.verdict.value,
        "mode": result.mode.value,
        "findings": len(result.findings),
        "rejected": result.rejected_count,
        "regressions": len(result.regressions),
        "ai_mode": resolve_ai_credentials(cfg)["mode"],
        "summary": result.check_output_summary,
    }


def cmd_status(path: Path | None = None) -> dict[str, Any]:
    """Show config discovery + credential presence (secrets redacted)."""
    cfg_path = Path(path) if path else find_config_path()
    cfg = load_github_config(cfg_path)
    return {
        "config_path": str(cfg_path) if cfg_path else None,
        "config_candidates": list(CONFIG_FILENAMES),
        "review": {"enabled": cfg.review.enabled, "check_name": cfg.review.check_name},
        "preship": {"enabled": cfg.preship.enabled},
        "watch": {"enabled": cfg.watch.enabled},
        "policy": {
            "fail_on": cfg.policy.fail_on,
            "fail_on_analysis_error": cfg.policy.fail_on_analysis_error,
        },
        "ai": {"mode": resolve_ai_credentials(cfg)["mode"], "provider": cfg.ai.provider},
        "privacy": {"retain_source": cfg.privacy.retain_source},
        "env_present": {
            cfg.github.app_id_env: bool(os.environ.get(cfg.github.app_id_env)),
            cfg.github.webhook_secret_env: bool(os.environ.get(cfg.github.webhook_secret_env)),
            "private_key": bool(
                os.environ.get(cfg.github.private_key_env)
                or (
                    os.environ.get(cfg.github.private_key_path_env)
                    and Path(os.environ.get(cfg.github.private_key_path_env, "")).expanduser().is_file()
                )
            ),
        },
        "permissions": MINIMUM_PERMISSIONS,
    }


def format_cli_json(data: dict[str, Any]) -> str:
    return json.dumps(data, indent=2, default=str)
