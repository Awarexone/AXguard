# Uninstall — AXGuard GitHub App

Remove AXGuard access cleanly. Related: [permissions.md](permissions.md) ·
[privacy.md](privacy.md).

---

## GitHub UI

1. Repository or Organization → **Settings** → **Integrations** / **GitHub Apps**.
2. Find AXGuard → **Uninstall** (or **Suspend** for a temporary pause).
3. Confirm the App no longer appears under installed Apps.
4. Confirm webhook deliveries stop (App → **Advanced** → Recent Deliveries).

---

## Self-hosted adapter

1. Stop the adapter / worker process.
2. Delete local secrets: App PEM, `AXGUARD_GITHUB_*` env files, cached installation tokens.
3. Remove any reverse-proxy routes pointing at the webhook path.
4. Optionally delete project `.axguard.yml` if unused.

```bash
# Confirm CLI no longer sees credentials
unset AXGUARD_GITHUB_APP_ID AXGUARD_GITHUB_WEBHOOK_SECRET
unset AXGUARD_GITHUB_PRIVATE_KEY AXGUARD_GITHUB_PRIVATE_KEY_PATH
axguard github status .
```

---

## After uninstall

- AXGuard cannot read contents, create checks, or comment on PRs for that installation.
- Rotate webhook secrets / App keys if they were dedicated to this deployment.
- Request deletion of any non-source operational logs per your retention policy
  ([privacy.md](privacy.md)).
