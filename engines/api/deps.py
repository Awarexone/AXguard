"""Shared FastAPI dependencies."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from engines.api.auth import (
    AuthContext,
    is_loopback_host,
    parse_bearer,
)
from engines.api.errors import ApiError
from engines.api.jobs import JobWorker
from engines.api.settings import Settings
from engines.api.storage import Store


@dataclass
class AppDeps:
    settings: Settings
    store: Store
    worker: JobWorker | None = None
    provider: Any | None = None


def resolve_auth(
    deps: AppDeps,
    *,
    authorization: str | None,
    client_host: str | None,
) -> AuthContext:
    """Resolve auth: optional loopback trust, else Bearer axg_ key."""
    settings = deps.settings
    raw = parse_bearer(authorization)

    if raw:
        if not raw.startswith("axg_"):
            raise ApiError(
                "INVALID_API_KEY",
                "API keys must use the axg_ prefix.",
                status_code=401,
            )
        record = deps.store.find_api_key_by_raw(raw)
        if not record:
            raise ApiError(
                "UNAUTHORIZED",
                "Invalid or revoked API key.",
                status_code=401,
            )
        deps.store.touch_api_key(record["id"])
        return AuthContext(
            authenticated=True,
            via="api_key",
            key_id=record["id"],
            scopes=list(record.get("scopes") or ["*"]),
            name=record.get("name"),
        )

    loopback = is_loopback_host(client_host) and settings.is_loopback
    if settings.require_auth:
        raise ApiError(
            "UNAUTHORIZED",
            "Bearer API key required (AXGUARD_API_REQUIRE_AUTH=1).",
            status_code=401,
        )

    if loopback:
        return AuthContext(
            authenticated=True,
            via="loopback",
            scopes=["*"],
            name="loopback",
        )

    return AuthContext(
        authenticated=True,
        via="none",
        scopes=["*"],
        name="anonymous",
    )
