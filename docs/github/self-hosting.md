# Self-hosting the GitHub adapter

Preferred deployment for privacy-sensitive teams: run the AXGuard GitHub
adapter + Core in **your** network. Prefer this over a SaaS dashboard.

Related: [install.md](install.md) · [privacy.md](privacy.md) ·
[docs/research/github-security-bot.md](../research/github-security-bot.md).

---

## Shape

```text
Customer VPC / GHES
  ├── HTTPS webhook receiver (Adapter)
  ├── Queue + worker (async; ack webhooks in <10s)
  ├── AXGuard Core (engines/*)
  └── Optional local AI endpoint
```

There is **no large hosted UI** in this repo. Operational status is:

```bash
axguard github status .
axguard github validate .
```

If/when a process exposes a bind address (`github.webhook_host` /
`github.webhook_port` in `.axguard.yml`), treat it as a webhook endpoint — not
a product dashboard.

---

## Checklist

1. Register a GitHub App with [permissions.md](permissions.md).
2. Store PEM + webhook secret in your secret manager; export env vars from [config.md](config.md).
3. `axguard github setup .` and edit `.axguard.yml` bind host/port if needed.
4. Terminate TLS in front of the adapter (reverse proxy / load balancer).
5. Allowlist GitHub webhook IPs from [`GET /meta`](https://docs.github.com/en/rest/meta/meta) when practical.
6. Keep `privacy.retain_source: false` unless debugging with an explicit TTL.
7. On uninstall, stop the process and delete local credentials ([uninstall.md](uninstall.md)).

---

## GitHub Enterprise Server

Point the adapter’s API base at your GHES hostname. Keep the same permission
matrix and signature verification. Confirm API version headers against your
GHES release notes.

---

## Actions-only (no always-on webhook)

If you cannot run a receiver:

```yaml
# .github/workflows/axguard.yml (illustrative)
on: pull_request
jobs:
  axguard:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: pip install -e .
      - run: axguard audit . --fail-on high --no-banner
```

This runs Core in CI; it does not create App Check Runs unless you add further
Checks API wiring.
