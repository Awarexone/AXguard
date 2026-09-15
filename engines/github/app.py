"""GitHub App authentication — JWT + short-lived installation tokens."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from engines.github.client import GitHubClient, HttpGitHubClient


@dataclass(frozen=True)
class GitHubAppCredentials:
    app_id: str
    private_key_pem: str
    webhook_secret: str

    @classmethod
    def from_env(
        cls,
        *,
        app_id_env: str = "AXGUARD_GITHUB_APP_ID",
        private_key_env: str = "AXGUARD_GITHUB_PRIVATE_KEY",
        private_key_path_env: str = "AXGUARD_GITHUB_PRIVATE_KEY_PATH",
        webhook_secret_env: str = "AXGUARD_GITHUB_WEBHOOK_SECRET",
    ) -> GitHubAppCredentials:
        app_id = os.environ.get(app_id_env, "").strip()
        secret = os.environ.get(webhook_secret_env, "").strip()
        pem = os.environ.get(private_key_env, "").strip()
        if not pem:
            path = os.environ.get(private_key_path_env, "").strip()
            if path:
                pem = Path(path).expanduser().read_text(encoding="utf-8")
        if not app_id or not pem or not secret:
            raise ValueError(
                "Missing GitHub App credentials. Set "
                f"{app_id_env}, {webhook_secret_env}, and "
                f"{private_key_env} or {private_key_path_env}."
            )
        return cls(app_id=app_id, private_key_pem=pem, webhook_secret=secret)


@dataclass
class InstallationToken:
    """Short-lived installation access token — do not persist permanently."""

    token: str
    expires_at: float  # unix epoch
    installation_id: int
    permissions: dict[str, str]

    @property
    def expired(self) -> bool:
        # Refresh 60s early
        return time.time() >= (self.expires_at - 60)

    def redact(self) -> dict[str, Any]:
        return {
            "installation_id": self.installation_id,
            "expires_at": self.expires_at,
            "permissions": self.permissions,
            "token": "[REDACTED]",
        }


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def create_app_jwt(app_id: str, private_key_pem: str, *, now: float | None = None) -> str:
    """Create a GitHub App JWT (RS256), valid ≤10 minutes.

    Prefers PyJWT if installed; otherwise uses cryptography if available.
    Raises RuntimeError with install hint when neither is present.
    """
    issued = int(now if now is not None else time.time())
    payload = {
        "iat": issued - 60,
        "exp": issued + 9 * 60,
        "iss": str(app_id),
    }
    try:
        import jwt  # type: ignore

        return jwt.encode(payload, private_key_pem, algorithm="RS256")
    except ImportError:
        pass

    try:
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import padding
    except ImportError as exc:
        raise RuntimeError(
            "GitHub App JWT signing requires PyJWT[crypto] or cryptography. "
            "Install optional extras, or inject a pre-built JWT in tests via MockGitHubClient."
        ) from exc

    header = {"alg": "RS256", "typ": "JWT"}
    segments = (
        _b64url(json.dumps(header, separators=(",", ":")).encode()),
        _b64url(json.dumps(payload, separators=(",", ":")).encode()),
    )
    signing_input = f"{segments[0]}.{segments[1]}".encode("ascii")
    key = serialization.load_pem_private_key(private_key_pem.encode("utf-8"), password=None)
    signature = key.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
    return f"{segments[0]}.{segments[1]}.{_b64url(signature)}"


class GitHubApp:
    """Authenticate as a GitHub App and mint short-lived installation tokens."""

    def __init__(
        self,
        credentials: GitHubAppCredentials,
        *,
        client: GitHubClient | None = None,
    ) -> None:
        self.credentials = credentials
        self.client: GitHubClient = client or HttpGitHubClient()
        self._token_cache: dict[int, InstallationToken] = {}

    def app_jwt(self) -> str:
        return create_app_jwt(self.credentials.app_id, self.credentials.private_key_pem)

    def get_installation_token(self, installation_id: int) -> InstallationToken:
        cached = self._token_cache.get(installation_id)
        if cached and not cached.expired:
            return cached
        jwt_token = self.app_jwt()
        data = self.client.post_json(
            f"/app/installations/{installation_id}/access_tokens",
            {},
            token=jwt_token,
        )
        if not isinstance(data, dict) or not data.get("token"):
            raise RuntimeError("Failed to mint installation access token")
        expires_raw = str(data.get("expires_at") or "")
        expires_at = _parse_github_time(expires_raw) or (time.time() + 3600)
        tok = InstallationToken(
            token=str(data["token"]),
            expires_at=expires_at,
            installation_id=installation_id,
            permissions={str(k): str(v) for k, v in (data.get("permissions") or {}).items()},
        )
        self._token_cache[installation_id] = tok
        return tok

    def clear_token_cache(self) -> None:
        """Drop cached tokens (e.g. on uninstall) — never write tokens to disk."""
        self._token_cache.clear()

    def token_fingerprint(self, installation_id: int) -> str | None:
        tok = self._token_cache.get(installation_id)
        if not tok:
            return None
        return hashlib.sha256(tok.token.encode()).hexdigest()[:12]


def _parse_github_time(value: str) -> float | None:
    if not value:
        return None
    try:
        # 2026-09-15T12:00:00Z
        from datetime import datetime, timezone

        return datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()
    except ValueError:
        return None
