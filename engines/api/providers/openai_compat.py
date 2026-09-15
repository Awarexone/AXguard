"""OpenAI-compatible chat via urllib (openai, groq, deepseek, ollama, together, mistral)."""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import Any


class OpenAICompatProvider:
    def __init__(
        self,
        *,
        base_url: str,
        api_key: str | None = None,
        model: str | None = None,
        mode: str = "user_key",
        provider_name: str = "openai_compat",
        timeout: float = 60.0,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.default_model = model
        self._mode = mode
        self.provider_name = provider_name
        self.timeout = timeout

    @property
    def mode(self) -> str:
        return self._mode

    @property
    def available(self) -> bool:
        if not self.base_url:
            return False
        if self._mode == "local":
            return True
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
            raise RuntimeError("OpenAI-compatible provider is not configured")
        use_model = model or self.default_model
        if not use_model:
            raise RuntimeError("AXGUARD_AI_MODEL is required for LLM completion")
        url = f"{self.base_url}/chat/completions"
        body = {
            "model": use_model,
            "messages": messages,
            "temperature": temperature,
            "max_tokens": max_tokens,
        }
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        req = urllib.request.Request(
            url,
            data=json.dumps(body).encode("utf-8"),
            headers=headers,
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                raw = resp.read().decode("utf-8")
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")[:500]
            raise RuntimeError(f"LLM provider HTTP {exc.code}: {detail}") from None
        except urllib.error.URLError as exc:
            raise RuntimeError(f"LLM provider unreachable: {exc.reason}") from None
        data = json.loads(raw)
        choices = data.get("choices") or []
        content = ""
        if choices:
            msg = choices[0].get("message") or {}
            content = msg.get("content") or ""
        return {
            "provider": self.provider_name,
            "model": use_model,
            "content": content,
            "raw": {"id": data.get("id"), "usage": data.get("usage")},
        }
