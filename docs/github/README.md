# AXGuard GitHub Security Bot

Optional GitHub App adapter that runs AXGuard Core on pull requests and posts
Check Runs + one updatable PR summary comment.

```text
GitHub webhooks → GitHub Adapter (engines/github) → AXGuard Core (CLI engines)
```

This is **not** required for local `axguard audit` / `axguard scan`. Core stays
usable without GitHub.

Architecture research: [docs/research/github-security-bot.md](../research/github-security-bot.md).

**Marketplace:** preparation docs only — no listing/approval claim.
See [marketplace-prep.md](marketplace-prep.md).

---

## CLI

```bash
pip install -e .

axguard github setup .          # steps + write example .axguard.yml
axguard github validate .
axguard github test .
axguard github status .
```

| Command | Purpose |
|---|---|
| `setup` | Print App permission steps; write example `.axguard.yml` |
| `validate` | Check config + credential env presence (no live API) |
| `test` | Local dry-run (config + optional webhook HMAC self-check) |
| `status` | Show bind address, modes, credential presence (secrets redacted) |

---

## Docs map

| Doc | Topic |
|---|---|
| [install.md](install.md) | GitHub App registration & first install |
| [permissions.md](permissions.md) | Minimum scopes + rejected permissions |
| [config.md](config.md) | `.axguard.yml` github / review / AI / privacy |
| [privacy.md](privacy.md) | Retention, logging, tokens, AI egress |
| [ai-providers.md](ai-providers.md) | no-llm / local / user_key |
| [self-hosting.md](self-hosting.md) | Run the adapter yourself |
| [required-checks.md](required-checks.md) | Branch protection / required checks |
| [pr-ux.md](pr-ux.md) | Check + comment tone rules |
| [security.md](security.md) | Untrusted repo + webhook threat model |
| [troubleshooting.md](troubleshooting.md) | Common failures |
| [uninstall.md](uninstall.md) | Remove the App / revoke access |
| [marketplace-prep.md](marketplace-prep.md) | Listing prep placeholders (not approved) |

---

## Package layout

| Path | Role |
|---|---|
| `engines/github/` | Adapter (auth, webhooks, config, CLI helpers) |
| `cli/main.py` | `axguard github …` entrypoints |
| `.axguard.yml` | Optional project config (see [config.md](config.md)) |

Do **not** look for an `axguard/` Python package — runtime is `cli/` + `engines/`.
