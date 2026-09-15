# Troubleshooting — GitHub Security Bot

Quick fixes for common install and delivery issues.

Related: [install.md](install.md) · [self-hosting.md](self-hosting.md) ·
[permissions.md](permissions.md).

---

## CLI first

```bash
axguard github status .
axguard github validate .
axguard github test .
```

| Symptom | Check |
|---|---|
| `ready: no` | Export `AXGUARD_GITHUB_APP_ID`, webhook secret, and private key path/PEM |
| `private key path not found` | Fix `AXGUARD_GITHUB_PRIVATE_KEY_PATH` or use `AXGUARD_GITHUB_PRIVATE_KEY` |
| `ai mode=user_key but … unset` | Set `AXGUARD_AI_API_KEY` or switch `ai.mode` to `no-llm` |
| `privacy.log_source must be false` | Set `privacy.log_source: false` in `.axguard.yml` |

---

## Webhooks

| Symptom | Likely cause |
|---|---|
| Deliveries fail TLS | Broken cert / wrong hostname on reverse proxy |
| 401/403 on webhook | Wrong `AXGUARD_GITHUB_WEBHOOK_SECRET` or body rewritten before HMAC |
| Duplicate scans | Idempotency store missing — adapter should key on `X-GitHub-Delivery` |
| No deliveries | App not installed on that repo; event not subscribed |

Always verify `X-Hub-Signature-256` against the **raw** request body.

---

## Checks / PR comment

| Symptom | Likely cause |
|---|---|
| No check appears | Missing `checks:write`; App not installed; wrong `head_sha` |
| Check name missing from required list | Check has never completed on this repo — open a test PR first |
| Comment spam | Marker missing — body must include `<!-- AXGUARD-SECURITY-REVIEW -->` |
| Fork PR quirks | Expected Limits on Checks/fork association — see research doc |

Tone and lifecycle language: [pr-ux.md](pr-ux.md).

---

## JWT / tokens

| Symptom | Likely cause |
|---|---|
| 401 minting installation token | Wrong App ID, bad PEM, or clock skew |
| Expired mid-job | Installation tokens last ~1h — mint per job, do not persist |

Signing needs `PyJWT` or `cryptography` in the adapter environment.

---

## Still stuck

1. Re-read [docs/research/github-security-bot.md](../research/github-security-bot.md).
2. Confirm permissions match [permissions.md](permissions.md) — revoke over-broad Apps.
3. Open an issue on the AXGuard repo with **redacted** logs (no PEMs, tokens, or source).
