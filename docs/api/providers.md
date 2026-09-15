# AI Providers (local / BYOK)

AXGuard has **no hosted model**.

| Env | Purpose |
|---|---|
| `AXGUARD_AI_MODE` | `no-llm` (default), `local`, `user_key` |
| `AXGUARD_AI_PROVIDER` | `none`, `ollama`, `openai`, `anthropic`, `groq`, … |
| `AXGUARD_AI_API_KEY` | Your key (never logged) |
| `AXGUARD_AI_BASE_URL` | OpenAI-compatible or Anthropic base URL |
| `AXGUARD_AI_MODEL` | Model id |

`enrichment=llm` returns **422** unless a real local/BYOK provider is configured. `NoneProvider` is valid for no-llm (`available=True`) but still rejected for enrichment.
