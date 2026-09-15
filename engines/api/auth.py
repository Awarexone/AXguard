"""Loopback-friendly auth and hashed local API keys (axg_ prefix)."""

from __future__ import annotations

import hashlib
import hmac
import secrets
import time
from dataclasses import dataclass
from typing import Any, Iterable

# Never log raw keys or LLM credentials.
KEY_PREFIX = "axg_"

KNOWN_SCOPES: frozenset[str] = frozenset(
    {
        "projects:read",
        "projects:write",
        "scans:read",
        "scans:write",
        "findings:read",
        "evidence:read",
        "flows:read",
        "attack_paths:read",
        "investigations:read",
        "investigations:write",
        "memory:read",
        "twin:read",
        "twin:write",
        "reports:read",
        "reports:write",
        "webhooks:read",
        "webhooks:write",
        "keys:read",
        "keys:write",
        "reviews:write",
        "posture:read",
        "*",
    }
)


def is_loopback_host(host: str | None) -> bool:
    if not host:
        return False
    h = host.strip().lower().split("%")[0]
    if h.startswith("[") and h.endswith("]"):
        h = h[1:-1]
    if ":" in h and h.count(":") == 1:
        h = h.rsplit(":", 1)[0]
    return h in {"127.0.0.1", "localhost", "::1", "0:0:0:0:0:0:0:1"}


def generate_api_key() -> str:
    return KEY_PREFIX + secrets.token_urlsafe(32)


def hash_api_key(raw_key: str, *, salt: str | None = None) -> tuple[str, str]:
    """Return (salt, hex_digest)."""
    use_salt = salt or secrets.token_hex(16)
    digest = hashlib.sha256(f"{use_salt}:{raw_key}".encode("utf-8")).hexdigest()
    return use_salt, digest


def verify_api_key(raw_key: str, salt: str, key_hash: str) -> bool:
    if not raw_key or not salt or not key_hash:
        return False
    _, digest = hash_api_key(raw_key, salt=salt)
    return hmac.compare_digest(digest, key_hash)


def normalize_scopes(scopes: Iterable[str] | str | None) -> list[str]:
    if scopes is None:
        return ["*"]
    if isinstance(scopes, str):
        parts = [p.strip() for p in scopes.replace(" ", ",").split(",") if p.strip()]
    else:
        parts = [str(s).strip() for s in scopes if str(s).strip()]
    if not parts:
        return ["*"]
    if "*" in parts:
        return ["*"]
    return sorted(set(parts))


def scope_allows(granted: Iterable[str], required: str) -> bool:
    g = set(granted)
    if "*" in g:
        return True
    if required in g:
        return True
    if required.endswith(":read"):
        write = required[:-5] + ":write"
        if write in g:
            return True
    return False


@dataclass
class AuthContext:
    authenticated: bool
    via: str  # loopback | api_key | none
    key_id: str | None = None
    scopes: list[str] | None = None
    name: str | None = None

    def require_scope(self, scope: str) -> None:
        from engines.api.errors import ApiError

        if not self.authenticated:
            raise ApiError(
                "UNAUTHORIZED",
                "Authentication required.",
                status_code=401,
            )
        if self.via == "loopback" and (not self.scopes or "*" in (self.scopes or [])):
            return
        if not scope_allows(self.scopes or [], scope):
            raise ApiError(
                "FORBIDDEN",
                f"Missing required scope: {scope}",
                status_code=403,
                details={"required_scope": scope},
            )


def parse_bearer(authorization: str | None) -> str | None:
    if not authorization:
        return None
    parts = authorization.strip().split(None, 1)
    if len(parts) != 2:
        return None
    scheme, token = parts
    if scheme.lower() != "bearer":
        return None
    token = token.strip()
    return token or None


def key_prefix_hint(raw_key: str) -> str:
    if not raw_key:
        return ""
    if len(raw_key) <= 10:
        return raw_key[:4] + "…"
    return raw_key[:8] + "…"


def create_key_record(
    *,
    name: str,
    scopes: Iterable[str] | str | None = None,
    expires_at: float | None = None,
) -> tuple[str, dict[str, Any]]:
    """Return (plaintext_once, record_without_plaintext)."""
    raw = generate_api_key()
    salt, digest = hash_api_key(raw)
    now = time.time()
    key_id = "key_" + secrets.token_hex(8)
    record = {
        "id": key_id,
        "name": name,
        "prefix": key_prefix_hint(raw),
        "salt": salt,
        "key_hash": digest,
        "scopes": normalize_scopes(scopes),
        "created_at": now,
        "expires_at": expires_at,
        "revoked_at": None,
        "last_used_at": None,
    }
    return raw, record


def key_is_usable(record: dict[str, Any], *, now: float | None = None) -> bool:
    if not record:
        return False
    if record.get("revoked_at"):
        return False
    exp = record.get("expires_at")
    if exp is not None and float(exp) < (now if now is not None else time.time()):
        return False
    return True
