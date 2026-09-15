# Config — `.axguard.yml` (GitHub section)

AXGuard previously had **no** project config file. The GitHub bot introduces an
optional `.axguard.yml` (also `.axguard.yaml` / `.axguard.json`) loaded by
`engines.github.config`.

Missing file → safe defaults: **no-LLM**, `retain_source: false`, fail only on
verified critical/high (policy).

CLI:

```bash
axguard github setup .       # write example
axguard github validate .
```

Example on disk: [axguard.yml.example](axguard.yml.example).

---

## Full example

```yaml
# AXGuard project config (optional)
# Docs: docs/github/config.md

github:
  # Env var *names* only — never put secrets in this file
  app_id_env: AXGUARD_GITHUB_APP_ID
  private_key_path_env: AXGUARD_GITHUB_PRIVATE_KEY_PATH
  private_key_env: AXGUARD_GITHUB_PRIVATE_KEY
  webhook_secret_env: AXGUARD_GITHUB_WEBHOOK_SECRET
  webhook_host: 127.0.0.1
  webhook_port: 8787

review:
  enabled: true
  on_pull_request: true
  on_push: false
  check_name: "AXGuard Security Review"
  include_footer: true

preship:
  enabled: true
  check_name: "AXGuard Pre-Ship"

watch:
  enabled: false
  on_push: true
  on_release: true
  check_name: "AXGuard Watch"

policy:
  fail_on: [critical, high]
  review_on: [likely]
  fail_on_analysis_error: false
  fail_on_unverified: false
  medium_fail: false

analysis:
  mode: balanced   # fast | balanced | deep
  max_changed_files: 200
  max_annotations: 50

ai:
  provider: none   # none | local | openai | anthropic | openrouter | ollama
  mode: no-llm     # no-llm | local | user_key
  model: null
  api_key_env: AXGUARD_AI_API_KEY
  base_url_env: AXGUARD_AI_BASE_URL

privacy:
  retain_source: false
  log_source: false
```

Sections may also nest under `github:` (loader merges top-level and nested).

---

## Section reference

| Section | Purpose |
|---|---|
| `github` | Env var **names** for App credentials + webhook bind host/port |
| `review` | PR REVIEW mode (default on) |
| `preship` | Stricter pre-ship check naming / enable |
| `watch` | Optional post-ship / push / release observe mode (default off) |
| `policy` | Which severities fail the check |
| `analysis` | Depth + annotation caps |
| `ai` | Provider selection — keys via env only |
| `privacy` | Source retention / logging (defaults stay off) |

---

## Secrets

Never put App private keys, webhook secrets, or AI API keys in `.axguard.yml`.
Store values in the environment (or a secret manager that injects env vars).

| Env (default name) | Role |
|---|---|
| `AXGUARD_GITHUB_APP_ID` | GitHub App ID |
| `AXGUARD_GITHUB_WEBHOOK_SECRET` | HMAC webhook secret |
| `AXGUARD_GITHUB_PRIVATE_KEY_PATH` | Path to PEM |
| `AXGUARD_GITHUB_PRIVATE_KEY` | PEM contents (alternative to path) |
| `AXGUARD_AI_API_KEY` | Optional AI provider key |
| `AXGUARD_AI_BASE_URL` | Optional local/custom base URL |

---

## Loader

```python
from engines.github.config import load_github_config

cfg = load_github_config()  # search upward from cwd
```

See `engines/github/config.py` for dataclasses and defaults.
