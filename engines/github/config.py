"""Additive ``.axguard.yml`` loader for the GitHub bot (stdlib-first).

There is no prior central AXGuard config schema. This module introduces an
optional github/review/preship/watch/policy/ai/privacy section. Missing file
→ safe defaults (no-LLM, retain_source=false, fail only on verified critical/high).
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field, fields
from pathlib import Path
from typing import Any

CONFIG_FILENAMES = (".axguard.yml", ".axguard.yaml", ".axguard.json")


@dataclass
class PrivacyConfig:
    retain_source: bool = False
    log_source: bool = False


@dataclass
class AIConfig:
    """Provider selection — never hard-code API keys.

    Modes:
    - ``none`` / ``no-llm``: DeterministicJudge only (default)
    - ``local``: user-local model endpoint via env (optional)
    - ``user_key``: user-provided key via env; never from repo source
    """

    provider: str = "none"  # none | local | openai | anthropic | openrouter | ollama | …
    mode: str = "no-llm"  # no-llm | local | user_key
    model: str | None = None
    # Env var names only — never literal secrets
    api_key_env: str = "AXGUARD_AI_API_KEY"
    base_url_env: str = "AXGUARD_AI_BASE_URL"


@dataclass
class PolicyConfig:
    fail_on: list[str] = field(default_factory=lambda: ["critical", "high"])
    review_on: list[str] = field(default_factory=lambda: ["likely"])
    fail_on_analysis_error: bool = False
    fail_on_unverified: bool = False
    medium_fail: bool = False


@dataclass
class ReviewConfig:
    enabled: bool = True
    on_pull_request: bool = True
    on_push: bool = False
    check_name: str = "AXGuard Security Review"
    include_footer: bool = True


@dataclass
class PreshipConfig:
    enabled: bool = True
    check_name: str = "AXGuard Pre-Ship"


@dataclass
class WatchConfig:
    enabled: bool = False
    on_push: bool = True
    on_release: bool = True
    check_name: str = "AXGuard Watch"


@dataclass
class AnalysisConfig:
    mode: str = "balanced"  # fast | balanced | deep
    max_changed_files: int = 200
    max_annotations: int = 50


@dataclass
class GitHubAppEnvConfig:
    """Credentials from environment / local secrets — never from repo YAML secrets."""

    app_id_env: str = "AXGUARD_GITHUB_APP_ID"
    private_key_path_env: str = "AXGUARD_GITHUB_PRIVATE_KEY_PATH"
    private_key_env: str = "AXGUARD_GITHUB_PRIVATE_KEY"
    webhook_secret_env: str = "AXGUARD_GITHUB_WEBHOOK_SECRET"
    webhook_host: str = "127.0.0.1"
    webhook_port: int = 8787


@dataclass
class GitHubBotConfig:
    review: ReviewConfig = field(default_factory=ReviewConfig)
    preship: PreshipConfig = field(default_factory=PreshipConfig)
    watch: WatchConfig = field(default_factory=WatchConfig)
    policy: PolicyConfig = field(default_factory=PolicyConfig)
    analysis: AnalysisConfig = field(default_factory=AnalysisConfig)
    ai: AIConfig = field(default_factory=AIConfig)
    privacy: PrivacyConfig = field(default_factory=PrivacyConfig)
    github: GitHubAppEnvConfig = field(default_factory=GitHubAppEnvConfig)
    raw: dict[str, Any] = field(default_factory=dict, repr=False)

    @property
    def ai_provider_mode(self) -> str:
        mode = (self.ai.mode or "no-llm").lower().replace("_", "-")
        provider = (self.ai.provider or "none").lower()
        if mode in ("no-llm", "none") or provider in ("none", "no-llm", "deterministic"):
            return "no-llm"
        if mode == "local" or provider in ("local", "ollama"):
            return "local"
        return "user_key"


# ---------------------------------------------------------------------------
# Minimal YAML subset (no PyYAML dependency)
# ---------------------------------------------------------------------------

_KEY_RE = re.compile(r"^(\s*)([A-Za-z0-9_.-]+):\s*(.*)$")


def _parse_scalar(raw: str) -> Any:
    s = raw.strip()
    if not s:
        return None
    if s.startswith(("'", '"')) and len(s) >= 2 and s[0] == s[-1]:
        return s[1:-1]
    low = s.lower()
    if low in ("true", "yes", "on"):
        return True
    if low in ("false", "no", "off"):
        return False
    if low in ("null", "~", "none"):
        return None
    if re.fullmatch(r"-?\d+", s):
        return int(s)
    if re.fullmatch(r"-?\d+\.\d+", s):
        return float(s)
    if s.startswith("[") and s.endswith("]"):
        inner = s[1:-1].strip()
        if not inner:
            return []
        return [_parse_scalar(p.strip()) for p in inner.split(",")]
    return s


def _simple_yaml_load(text: str) -> dict[str, Any]:
    """Parse a restricted indentation-based YAML subset into nested dicts/lists."""
    root: dict[str, Any] = {}
    stack: list[tuple[int, Any]] = [(-1, root)]
    pending_list_key: tuple[Any, str] | None = None

    for lineno, line in enumerate(text.splitlines(), 1):
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        # list item
        m_list = re.match(r"^(\s*)-\s+(.*)$", line)
        if m_list:
            indent = len(m_list.group(1))
            val = _parse_scalar(m_list.group(2))
            while stack and stack[-1][0] >= indent:
                stack.pop()
            parent = stack[-1][1]
            if pending_list_key is not None and pending_list_key[0] is parent:
                lst = parent.setdefault(pending_list_key[1], [])
                if not isinstance(lst, list):
                    raise ValueError(f"line {lineno}: expected list for {pending_list_key[1]}")
                lst.append(val)
            elif isinstance(parent, list):
                parent.append(val)
            else:
                raise ValueError(f"line {lineno}: list item without key")
            continue

        m = _KEY_RE.match(line)
        if not m:
            raise ValueError(f"line {lineno}: cannot parse: {line!r}")
        indent = len(m.group(1))
        key = m.group(2)
        rest = m.group(3)
        while stack and stack[-1][0] >= indent:
            stack.pop()
        parent = stack[-1][1]
        if not isinstance(parent, dict):
            raise ValueError(f"line {lineno}: invalid nesting for key {key}")
        pending_list_key = None
        if rest == "" or rest == "|" or rest == ">":
            # nested mapping or upcoming list
            child: dict[str, Any] = {}
            parent[key] = child
            stack.append((indent, child))
            pending_list_key = (child, "")  # unused marker cleared below
            pending_list_key = (parent, key)
            # Fix: for nested maps, parent[key]=child and stack points to child;
            # list items under this key need parent[key] to become a list.
            # Detect empty value → dict; list items replace with list on first '-'.
            pending_list_key = (parent, key)
            continue
        parent[key] = _parse_scalar(rest)

    # Post-process: keys that only received list items via pending — handled inline
    return root


def _merge_dataclass(dc_cls: type, data: dict[str, Any] | None) -> Any:
    if not data:
        return dc_cls()
    allowed = {f.name for f in fields(dc_cls)}
    kwargs = {k: v for k, v in data.items() if k in allowed}
    return dc_cls(**kwargs)


def _load_raw(path: Path) -> dict[str, Any]:
    text = path.read_text(encoding="utf-8")
    if path.suffix.lower() == ".json":
        data = json.loads(text)
        if not isinstance(data, dict):
            raise ValueError("config root must be a mapping")
        return data
    try:
        import yaml  # type: ignore

        data = yaml.safe_load(text) or {}
    except ImportError:
        data = _simple_yaml_load(text) if text.strip() else {}
    if not isinstance(data, dict):
        raise ValueError("config root must be a mapping")
    return data


def find_config_path(start: Path | None = None) -> Path | None:
    root = (start or Path.cwd()).resolve()
    for base in [root, *root.parents]:
        for name in CONFIG_FILENAMES:
            candidate = base / name
            if candidate.is_file():
                return candidate
        # stop at filesystem root
        if base.parent == base:
            break
    return None


def load_github_config(path: Path | str | None = None) -> GitHubBotConfig:
    """Load GitHub bot config from ``.axguard.yml`` or defaults."""
    cfg_path: Path | None
    if path is not None:
        cfg_path = Path(path)
    else:
        cfg_path = find_config_path()

    raw: dict[str, Any] = {}
    if cfg_path and cfg_path.is_file():
        raw = _load_raw(cfg_path)

    gh_block = raw.get("github") if isinstance(raw.get("github"), dict) else {}
    # Allow top-level review/policy/… or nested under github:
    def section(name: str) -> dict[str, Any]:
        top = raw.get(name)
        nested = gh_block.get(name) if gh_block else None
        if isinstance(top, dict) and isinstance(nested, dict):
            merged = dict(nested)
            merged.update(top)
            return merged
        if isinstance(top, dict):
            return top
        if isinstance(nested, dict):
            return nested
        return {}

    app_env = section("app") or {
        k: v
        for k, v in (gh_block or {}).items()
        if k
        in {
            "app_id_env",
            "private_key_path_env",
            "private_key_env",
            "webhook_secret_env",
            "webhook_host",
            "webhook_port",
        }
    }

    return GitHubBotConfig(
        review=_merge_dataclass(ReviewConfig, section("review")),
        preship=_merge_dataclass(PreshipConfig, section("preship")),
        watch=_merge_dataclass(WatchConfig, section("watch") or section("post_ship")),
        policy=_merge_dataclass(PolicyConfig, section("policy")),
        analysis=_merge_dataclass(AnalysisConfig, section("analysis")),
        ai=_merge_dataclass(AIConfig, section("ai")),
        privacy=_merge_dataclass(PrivacyConfig, section("privacy")),
        github=_merge_dataclass(GitHubAppEnvConfig, app_env),
        raw=raw,
    )


def resolve_ai_credentials(config: GitHubBotConfig) -> dict[str, str | None]:
    """Resolve AI credentials from environment only (never from repo files)."""
    mode = config.ai_provider_mode
    if mode == "no-llm":
        return {"mode": "no-llm", "api_key": None, "base_url": None, "provider": "none"}
    api_key = os.environ.get(config.ai.api_key_env)
    base_url = os.environ.get(config.ai.base_url_env)
    return {
        "mode": mode,
        "api_key": api_key,
        "base_url": base_url,
        "provider": config.ai.provider,
        "model": config.ai.model,
    }


# Back-compat alias
AnalysisMode = str  # fast | balanced | deep
AIProviderMode = str  # no-llm | local | user_key
