"""No-op provider — default when AXGUARD_AI_MODE=no-llm."""

from __future__ import annotations

from typing import Any


class NoneProvider:
    """Valid no-llm configuration. Not usable for enrichment=llm."""

    name = "none"

    @property
    def mode(self) -> str:
        return "none"

    @property
    def available(self) -> bool:
        # Config is valid (no-llm is intentional); enrichment still rejected in factory.
        return True

    @property
    def provider_name(self) -> str:
        return "none"

    @property
    def default_model(self) -> str | None:
        return None

    def complete(
        self,
        messages: list[dict[str, str]],
        *,
        model: str | None = None,
        temperature: float = 0.0,
        max_tokens: int = 1024,
    ) -> dict[str, Any]:
        raise RuntimeError(
            "No LLM configured. Set AXGUARD_AI_MODE=local|user_key and provider credentials. "
            "AXGuard has no hosted model."
        )
