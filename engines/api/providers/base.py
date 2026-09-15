"""Provider protocol — no silent cloud calls."""

from __future__ import annotations

from typing import Any, Protocol, runtime_checkable


@runtime_checkable
class LLMProvider(Protocol):
    """User-controlled completion provider."""

    @property
    def mode(self) -> str:
        """none | local | user_key | configured"""
        ...

    @property
    def available(self) -> bool:
        ...

    def complete(
        self,
        messages: list[dict[str, str]],
        *,
        model: str | None = None,
        temperature: float = 0.0,
        max_tokens: int = 1024,
    ) -> dict[str, Any]:
        ...
