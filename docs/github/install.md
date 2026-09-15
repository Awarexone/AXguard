# Install — AXGuard GitHub App

Step-by-step for registering a **development** GitHub App and wiring it to a
self-hosted AXGuard adapter. Prefer [self-hosting.md](self-hosting.md) over any
hosted SaaS UI.

Related: [permissions.md](permissions.md) · [config.md](config.md) ·
[docs/research/github-security-bot.md](../research/github-security-bot.md).

---

## Prerequisites

- AXGuard CLI installed (`pip install -e .`)
- A GitHub org or user that can create GitHub Apps
- HTTPS endpoint reachable by GitHub (or a tunnel for local dev)
- Secrets stored in your secret manager / shell env — **never in git**

---

## 1. Create the GitHub App

1. GitHub → **Settings** → **Developer settings** → **GitHub Apps** → **New GitHub App**.
2. Set **Webhook URL** to your adapter (e.g. `https://axguard.example.com/webhooks/github`).
3. Set a high-entropy **Webhook secret**; store it as `AXGUARD_GITHUB_WEBHOOK_SECRET`.
4. Permissions — use the matrix in [permissions.md](permissions.md):

   | Permission | Access |
   |---|---|
   | Contents | Read |
   | Metadata | Read |
   | Pull requests | Read & write (summary comment only) |
   | Checks | Read & write |

5. Subscribe to events: **Pull request** (at least `opened`, `synchronize`, `reopened`).
6. Create the App → note **App ID** → generate and download a **private key** (PEM).

Reject any configuration that requests Administration, Actions, Secrets, or Contents **write**.

---

## 2. Export credentials

```bash
export AXGUARD_GITHUB_APP_ID=123456
export AXGUARD_GITHUB_WEBHOOK_SECRET='…'
export AXGUARD_GITHUB_PRIVATE_KEY_PATH="$HOME/secrets/axguard-app.pem"
# alternative: export AXGUARD_GITHUB_PRIVATE_KEY="$(cat "$HOME/secrets/axguard-app.pem")"
```

Optional AI (off by default): see [ai-providers.md](ai-providers.md).

---

## 3. Project config

```bash
axguard github setup .
# edits .axguard.yml — see config.md
axguard github validate .
```

---

## 4. Install on repositories

1. App settings → **Install App** → choose **Only select repositories**.
2. Confirm the permission screen matches [permissions.md](permissions.md).
3. Open a test PR and confirm a Check Run named like `AXGuard Security Review` appears.

To require the check on merge, see [required-checks.md](required-checks.md).

---

## 5. Verify locally

```bash
axguard github status .
axguard github test .
```

`validate` / `test` / `status` do **not** need to call GitHub’s API for basic
credential and config checks. Live webhook delivery is verified by opening a PR
against an installed repo once the adapter is running.

---

## Actions alternative

Teams that cannot run a webhook receiver can run Core in CI:

```bash
axguard audit . --fail-on high
```

That path does not replace the App’s Checks UX; it is complementary. See
research §9 (Actions vs App) in [github-security-bot.md](../research/github-security-bot.md).
