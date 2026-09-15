"""Local API settings — env-driven, no cloud defaults."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


def _env(name: str, default: str | None = None) -> str | None:
    value = os.environ.get(name)
    if value is None or value == "":
        return default
    return value


def _env_bool(name: str, default: bool = False) -> bool:
    raw = _env(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _env_int(name: str, default: int) -> int:
    raw = _env(name)
    if raw is None:
        return default
    try:
        return int(raw)
    except ValueError:
        return default


@dataclass(frozen=True)
class Settings:
    host: str = "127.0.0.1"
    port: int = 8787
    data_dir: Path = Path.home() / ".axguard" / "api"
    require_auth: bool = False
    max_concurrent_jobs: int = 2
    max_request_body_bytes: int = 8 * 1024 * 1024
    ai_mode: str = "no-llm"
    ai_provider: str = "none"
    ai_model: str | None = None
    ai_api_key: str | None = None
    ai_base_url: str | None = None

    @property
    def db_path(self) -> Path:
        return self.data_dir / "api.db"

    @property
    def is_loopback(self) -> bool:
        h = self.host.strip().lower()
        return h in {"127.0.0.1", "localhost", "::1"}


def load_settings(
    *,
    host: str | None = None,
    port: int | None = None,
    data_dir: str | Path | None = None,
) -> Settings:
    dd = data_dir or _env("AXGUARD_API_DATA_DIR") or (Path.home() / ".axguard" / "api")
    return Settings(
        host=host or _env("AXGUARD_API_HOST", "127.0.0.1") or "127.0.0.1",
        port=port if port is not None else _env_int("AXGUARD_API_PORT", 8787),
        data_dir=Path(dd).expanduser().resolve(),
        require_auth=_env_bool("AXGUARD_API_REQUIRE_AUTH", False),
        max_concurrent_jobs=_env_int("AXGUARD_API_MAX_CONCURRENT_JOBS", 2),
        max_request_body_bytes=_env_int("AXGUARD_API_MAX_BODY", 8 * 1024 * 1024),
        ai_mode=(_env("AXGUARD_AI_MODE", "no-llm") or "no-llm").strip().lower(),
        ai_provider=(_env("AXGUARD_AI_PROVIDER", "none") or "none").strip().lower(),
        ai_model=_env("AXGUARD_AI_MODEL"),
        ai_api_key=_env("AXGUARD_AI_API_KEY"),
        ai_base_url=_env("AXGUARD_AI_BASE_URL"),
    )
