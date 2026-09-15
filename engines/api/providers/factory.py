"""Build LLM provider from env/config — never AwareXone-hosted."""

from __future__ import annotations

import os
from typing import Any

from engines.api.providers.anthropic_compat import AnthropicCompatProvider
from engines.api.providers.none import NoneProvider
from engines.api.providers.openai_compat import OpenAICompatProvider

PROVIDER_BASE_URLS: dict[str, str] = {
    "openai": "https://api.openai.com/v1",
    "groq": "https://api.groq.com/openai/v1",
    "deepseek": "https://api.deepseek.com/v1",
    "together": "https://api.together.xyz/v1",
    "mistral": "https://api.mistral.ai/v1",
    "ollama": "http://127.0.0.1:11434/v1",
    "cerebras": "https://api.cerebras.ai/v1",
}


def _norm_mode(raw: str | None) -> str:
    mode = (raw or "no-llm").strip().lower().replace("_", "-")
    if mode in {"none", "no", "off", "disabled", "no-llm"}:
        return "no-llm"
    if mode in {"local", "local-model", "ollama"}:
        return "local"
    if mode in {"user-key", "user_key", "byok"}:
        return "user_key"
    if mode in {"configured", "configured-provider"}:
        return "configured"
    return mode


def get_provider(
    *,
    settings: Any | None = None,
    mode: str | None = None,
    provider: str | None = None,
    api_key: str | None = None,
    base_url: str | None = None,
    model: str | None = None,
) -> Any:
    """Return a provider instance. Default is NoneProvider (no network)."""
    if settings is not None:
        mode = mode or getattr(settings, "ai_mode", None)
        provider = provider or getattr(settings, "ai_provider", None)
        api_key = api_key if api_key is not None else getattr(settings, "ai_api_key", None)
        base_url = base_url if base_url is not None else getattr(settings, "ai_base_url", None)
        model = model if model is not None else getattr(settings, "ai_model", None)

    mode_n = _norm_mode(mode or os.environ.get("AXGUARD_AI_MODE"))
    provider_n = (
        provider or os.environ.get("AXGUARD_AI_PROVIDER") or "none"
    ).strip().lower()
    api_key = api_key if api_key is not None else os.environ.get("AXGUARD_AI_API_KEY")
    base_url = base_url if base_url is not None else os.environ.get("AXGUARD_AI_BASE_URL")
    model = model if model is not None else os.environ.get("AXGUARD_AI_MODEL")

    if mode_n == "no-llm" or provider_n in {"", "none", "no", "off"}:
        return NoneProvider()

    runtime_mode = (
        "local"
        if mode_n == "local"
        else ("configured" if mode_n == "configured" else "user_key")
    )

    if provider_n in {"anthropic", "claude"}:
        if not api_key:
            return NoneProvider()
        return AnthropicCompatProvider(
            api_key=api_key,
            model=model,
            base_url=base_url,
            mode=runtime_mode,
        )

    resolved_base = base_url or PROVIDER_BASE_URLS.get(provider_n)
    if provider_n in {"ollama", "local"} and not resolved_base:
        resolved_base = PROVIDER_BASE_URLS["ollama"]
    if not resolved_base:
        if mode_n == "local":
            resolved_base = PROVIDER_BASE_URLS["ollama"]
        else:
            return NoneProvider()

    if runtime_mode != "local" and not api_key and provider_n not in {"ollama", "local"}:
        return NoneProvider()

    return OpenAICompatProvider(
        base_url=resolved_base,
        api_key=api_key,
        model=model,
        mode=runtime_mode,
        provider_name=provider_n or "openai_compat",
    )


def provider_status(provider: Any | None = None, *, settings: Any | None = None) -> dict[str, Any]:
    """Safe status dict for /health — never includes API keys."""
    p = provider if provider is not None else get_provider(settings=settings)
    mode = getattr(p, "mode", "none")
    label = "no-llm" if mode == "none" else str(mode)
    return {
        "llm_mode": label,
        "provider": getattr(p, "provider_name", getattr(p, "name", type(p).__name__)),
        "available": bool(getattr(p, "available", False)),
        "model": getattr(p, "default_model", None),
        "cloud": False,
        "hosted_llm": False,
    }


def require_provider_for_enrichment(enrichment: str | None, provider: Any) -> None:
    """Reject enrichment=llm unless a real local/BYOK provider is configured.

    NoneProvider is a valid no-llm config (available=True) but must still 422 here.
    """
    from engines.api.errors import ApiError

    enr = (enrichment or "none").strip().lower()
    if enr != "llm":
        return

    mode = getattr(provider, "mode", "none") if provider is not None else "none"
    is_none = (
        provider is None
        or isinstance(provider, NoneProvider)
        or mode in {"none", "no-llm"}
        or getattr(provider, "name", None) == "none"
    )
    if is_none or not getattr(provider, "available", False):
        raise ApiError(
            "LLM_NOT_CONFIGURED",
            "enrichment=llm requires a configured local or BYOK provider "
            "(AXGUARD_AI_MODE + provider credentials). AXGuard has no hosted model.",
            status_code=422,
            details={
                "hint": "Use enrichment=none|auto, or set AXGUARD_AI_MODE=local|user_key",
            },
        )
