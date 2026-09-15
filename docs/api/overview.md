# AXGuard Security Intelligence API

Local-first, programmable security intelligence over the AXGuard engine.

```text
AXGuard Core
      ↓
Local Security Intelligence API
      ↓
+-----+---------+---------+
|     |         |         |
CLI  MCP*    GitHub*    CI/CD
|     |         |         |
Human AI      PRs      Pipelines
      |
      ↓
User-controlled LLM / local model / NO_LLM
```

\* MCP and GitHub App are designed against this API; they are not required for API use.

## Product principle

**AXGuard provides the security intelligence. You provide the environment, infrastructure, and model.**

AXGuard does **not** require an AwareXone account, AXGuard cloud, or hosted inference.

| Mode | Meaning |
|---|---|
| `no-llm` (default) | Deterministic engines only |
| `local` | Ollama or OpenAI-compatible local endpoint |
| `user_key` / BYOK | Your OpenAI, Anthropic, Groq, DeepSeek, … key |

## Start

```bash
pip install -e '.[api]'
axguard api start
# → http://127.0.0.1:8787
```

See [quickstart](quickstart.md), [authentication](authentication.md), [providers](providers.md), [security](security.md).
