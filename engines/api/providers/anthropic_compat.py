"""Anthropic Messages API via urllib (BYOK only)."""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import Any

DEFAULT_ANTHROPIC_URL = "https://api.anthropic.com/v1/messages"
ANTHROPIC_VERSION = "2023-06-01"


class AnthropicCompatProvider:
    def __init__(
        self,
        *,
        api_key: str,
        model: str | None = None,
        base_url: str | None = None,
        mode: str = "user_key",
        timeout: float = 60.0,
    ) -> None:
        self.api_key = api_key
        self.default_model = model
        self.base_url = (base_url or DEFAULT_ANTHROPIC_URL).rstrip("/")
        self._mode = mode
        self.timeout = timeout
        self.provider_name = "anthropic"

    @property
    def mode(self) -> str:
        return self._mode

    @property
    def available(self) -> bool:
        return bool(self.api_key)

    def complete(
        self,
        messages: list[dict[str, str]],
        *,
        model: str | None = None,
        temperature: float = 0.0,
        max_tokens: int = 1024,
    ) -> dict[str, Any]:
        if not self.available:
            raise RuntimeError("Anthropic provider is not configured")
        use_model = model or self.default_model
        if not use_model:
            raise RuntimeError("AXGUARD_AI_MODEL is required for LLM completion")

        system = None
        converted: list[dict[str, Any]] = []
        for m in messages:
            role = m.get("role", "user")
            content = m.get("content", "")
            if role == "system":
                system = content if system is None else f"{system}\n{content}"
                continue
            if role not in {"user", "assistant"}:
                role = "user"
            converted.append({"role": role, "content": content})

        body: dict[str, Any] = {
            "model": use_model,
            "max_tokens": max_tokens,
            "temperature": temperature,
            "messages": converted or [{"role": "user", "content": ""}],
        }
        if system:
            body["system"] = system

        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "x-api-key": self.api_key,
            "anthropic-version": ANTHROPIC_VERSION,
        }
        req = urllib.request.Request(
            self.base_url,
            data=json.dumps(body).encode("utf-8"),
            headers=headers,
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                raw = resp.read().decode("utf-8")
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")[:500]
            raise RuntimeError(f"Anthropic HTTP {exc.code}: {detail}") from None
        except urllib.error.URLError as exc:
            raise RuntimeError(f"Anthropic unreachable: {exc.reason}") from None

        data = json.loads(raw)
        content_blocks = data.get("content") or []
        text_parts = [
            b.get("text", "")
            for b in content_blocks
            if isinstance(b, dict) and b.get("type") == "text"
        ]
        return {
            "provider": "anthropic",
            "model": use_model,
            "content": "\n".join(text_parts),
            "raw": {"id": data.get("id"), "usage": data.get("usage")},
        }
