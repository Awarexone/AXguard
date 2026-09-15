# AI providers (BYOK / local / none)

AXGuard ships **no hosted model**. Default is deterministic `no-llm`.

```bash
# Offline (default)
export AXGUARD_AI_MODE=no-llm

# Ollama
export AXGUARD_AI_MODE=local
export AXGUARD_AI_PROVIDER=ollama
export AXGUARD_AI_BASE_URL=http://127.0.0.1:11434/v1
export AXGUARD_AI_MODEL=llama3.2

# OpenAI BYOK
export AXGUARD_AI_MODE=user_key
export AXGUARD_AI_PROVIDER=openai
export AXGUARD_AI_API_KEY=sk-...
export AXGUARD_AI_MODEL=gpt-4.1-mini

# Anthropic BYOK
export AXGUARD_AI_MODE=user_key
export AXGUARD_AI_PROVIDER=anthropic
export AXGUARD_AI_API_KEY=sk-ant-...

# OpenAI-compatible (Groq, DeepSeek, Together, Mistral, Cerebras, …)
export AXGUARD_AI_MODE=user_key
export AXGUARD_AI_PROVIDER=openai_compat
export AXGUARD_AI_BASE_URL=https://api.groq.com/openai/v1
export AXGUARD_AI_API_KEY=...
```

Scan body `enrichment`: `none` (default) | `auto` | `llm` (422 if no provider configured).
