# AI providers (GitHub bot)

AXGuard Core is **deterministic by default**. Outbound model calls that include
code are **opt-in** and use credentials from the environment only.

Related: [privacy.md](privacy.md) · [config.md](config.md).

---

## Modes

| `ai.mode` | Behavior |
|---|---|
| `no-llm` (default) | No external model. Engines only. |
| `local` | Customer-local endpoint (`AXGUARD_AI_BASE_URL`); optional key |
| `user_key` | Customer-provided cloud key via `AXGUARD_AI_API_KEY` |

`ai.provider` selects the adapter (`none`, `local`, `ollama`, `openai`,
`anthropic`, `openrouter`, …). Keys are never read from the analyzed repo.

---

## Example — stay offline

```yaml
ai:
  provider: none
  mode: no-llm
```

---

## Example — local Ollama

```yaml
ai:
  provider: ollama
  mode: local
  model: llama3.1
  base_url_env: AXGUARD_AI_BASE_URL
```

```bash
export AXGUARD_AI_BASE_URL=http://127.0.0.1:11434
```

---

## Example — user-owned cloud key

```yaml
ai:
  provider: openai
  mode: user_key
  model: gpt-4.1-mini
  api_key_env: AXGUARD_AI_API_KEY
```

```bash
export AXGUARD_AI_API_KEY=sk-…
```

Rules:

1. No silent third-party calls on private source.
2. Send the smallest snippet required; never whole-monorepo dumps by default.
3. Customer code is not used to train Awarexone models.
4. Redact secrets before any optional provider call ([security.md](security.md)).

Validate:

```bash
axguard github validate .
```
