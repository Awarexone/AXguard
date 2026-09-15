"""Mockable GitHub HTTP client interface (stdlib urllib)."""

from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Protocol, runtime_checkable


GITHUB_API = "https://api.github.com"


@runtime_checkable
class GitHubClient(Protocol):
    """Minimal GitHub REST surface used by the adapter — mock in tests."""

    def request(
        self,
        method: str,
        path: str,
        *,
        token: str | None = None,
        json_body: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
    ) -> dict[str, Any] | list[Any] | None:
        ...

    def get_json(self, path: str, *, token: str | None = None) -> Any:
        ...

    def post_json(
        self, path: str, body: dict[str, Any], *, token: str | None = None
    ) -> Any:
        ...

    def patch_json(
        self, path: str, body: dict[str, Any], *, token: str | None = None
    ) -> Any:
        ...


@dataclass
class MockGitHubClient:
    """In-memory client for unit tests — no network."""

    responses: dict[str, Any] = field(default_factory=dict)
    calls: list[dict[str, Any]] = field(default_factory=list)
    default: Any = None

    def _key(self, method: str, path: str) -> str:
        return f"{method.upper()} {path}"

    def request(
        self,
        method: str,
        path: str,
        *,
        token: str | None = None,
        json_body: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
    ) -> dict[str, Any] | list[Any] | None:
        self.calls.append(
            {
                "method": method.upper(),
                "path": path,
                "token": token,
                "json_body": json_body,
                "headers": headers or {},
            }
        )
        key = self._key(method, path)
        if key in self.responses:
            return self.responses[key]
        # prefix match for dynamic paths
        for k, v in self.responses.items():
            if key.startswith(k.rstrip("*")) or k.endswith("*") and key.startswith(k[:-1]):
                return v
        return self.default

    def get_json(self, path: str, *, token: str | None = None) -> Any:
        return self.request("GET", path, token=token)

    def post_json(
        self, path: str, body: dict[str, Any], *, token: str | None = None
    ) -> Any:
        return self.request("POST", path, token=token, json_body=body)

    def patch_json(
        self, path: str, body: dict[str, Any], *, token: str | None = None
    ) -> Any:
        return self.request("PATCH", path, token=token, json_body=body)

    def set(self, method: str, path: str, response: Any) -> None:
        self.responses[self._key(method, path)] = response


@dataclass
class HttpGitHubClient:
    """Stdlib urllib GitHub REST client."""

    api_base: str = GITHUB_API
    user_agent: str = "AXGuard-GitHub-Bot/0.2"
    timeout: float = 30.0

    def request(
        self,
        method: str,
        path: str,
        *,
        token: str | None = None,
        json_body: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
    ) -> dict[str, Any] | list[Any] | None:
        url = path if path.startswith("http") else f"{self.api_base.rstrip('/')}/{path.lstrip('/')}"
        hdrs = {
            "Accept": "application/vnd.github+json",
            "User-Agent": self.user_agent,
            "X-GitHub-Api-Version": "2022-11-28",
        }
        if token:
            hdrs["Authorization"] = f"Bearer {token}"
        if headers:
            hdrs.update(headers)
        data = None
        if json_body is not None:
            data = json.dumps(json_body).encode("utf-8")
            hdrs["Content-Type"] = "application/json"
        req = urllib.request.Request(url, data=data, headers=hdrs, method=method.upper())
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                body = resp.read()
                if not body:
                    return None
                return json.loads(body.decode("utf-8"))
        except urllib.error.HTTPError as exc:
            err_body = exc.read().decode("utf-8", errors="replace")
            raise RuntimeError(
                f"GitHub API {method.upper()} {path} failed: {exc.code} {err_body[:500]}"
            ) from exc

    def get_json(self, path: str, *, token: str | None = None) -> Any:
        return self.request("GET", path, token=token)

    def post_json(
        self, path: str, body: dict[str, Any], *, token: str | None = None
    ) -> Any:
        return self.request("POST", path, token=token, json_body=body)

    def patch_json(
        self, path: str, body: dict[str, Any], *, token: str | None = None
    ) -> Any:
        return self.request("PATCH", path, token=token, json_body=body)
