# AXGuard GitHub App — Privacy

This document describes what AXGuard accesses when installed as a GitHub App, how long data is kept, what is never logged, and how AI and self-hosted deployments affect where code goes.

Related: [permissions.md](permissions.md) · [security.md](security.md) · [docs/research/github-security-bot.md](../research/github-security-bot.md) (when present).

---

## Data flow (summary)

```text
GitHub webhook (signed)
        │
        ▼
AXGuard GitHub Adapter  ──► short-lived installation token
        │
        ├── fetch PR / commit metadata + file contents (contents:read)
        ├── run AXGuard Core analysis in-process / worker
        ├── post Check Run + optional PR summary comment
        └── discard working copy (retain_source: false by default)
```

Nothing in this path requires permanent storage of repository source on Awarexone infrastructure.

---

## What code and metadata are accessed

| Data | When | Purpose |
|---|---|---|
| Repository metadata (name, id, default branch, visibility) | Installation + each job | Route jobs; enforce install scope |
| Pull request metadata (number, head/base SHAs, author login, changed file paths) | REVIEW / relevant events | Scope the diff and Checks target |
| File contents / blobs for analyzed paths | During analysis | Static security review (AXGuard Core) |
| Commit SHAs and Check Run identifiers | During reporting | Publish results to GitHub Checks |
| Installation and delivery IDs | Webhook handling | Auth, idempotency, replay protection |

AXGuard does **not** need: Issues bodies (by default), Actions logs, Dependabot alerts write access, org member lists, or repository secrets.

---

## Retention

| Asset | Default | Notes |
|---|---|---|
| **Source / working tree** | **`retain_source: false`** | Ephemeral checkout or API-fetched blobs are deleted when the job finishes (success or failure). |
| Finding summaries (title, severity, path, line, rule id) | Short operational retention only if needed for support/debug | Prefer regenerating from GitHub Check Run / comment history over storing copies. |
| Raw source snippets in long-term stores | **Off by default** | Do not warehouse customer repositories. |
| Webhook payloads | Minimal; strip bodies after verify + enqueue where possible | Keep delivery id / timestamp for replay defense, not full source. |
| Installation access tokens | Memory / secret-store TTL only | Never permanent disk retention. See [Token security](#token-security). |

Operators may set `retain_source: true` only for **explicit, local/self-hosted debugging**, with a documented TTL and customer awareness. Hosted Awarexone defaults remain `retain_source: false`.

---

## Logging rules

AXGuard and its GitHub adapter **must not** log:

- Repository **source code** or file bodies
- **Secrets**, credentials, API keys, or private keys found in analysis (findings may note *presence/location*, not secret values)
- **GitHub App private keys**, webhook secrets, or **installation access tokens**
- Authorization headers or raw `X-Hub-Signature-256` material beyond a boolean “verified”

Allowed in logs (examples): installation id, repository full name, PR number, commit SHA, delivery id, job id, rule ids, severities, Check Run conclusion, error *classes* (timeout, rate limit), redacted exception messages.

---

## AI provider rules

AXGuard Core can run fully **without** sending code to any external model.

| Configuration | Code sent to external AI? |
|---|---|
| No AI provider configured (deterministic / local engines only) | **No** |
| User/org configures their own provider (API key + endpoint they control) | **Only then**, and only the paths/snippets required for that optional step |
| Awarexone-hosted default models without customer opt-in | **Do not** send private repository source |

Rules:

1. **Opt-in** — outbound AI calls that include code require explicit customer configuration.
2. **Minimize** — send the smallest relevant snippet or path set; never whole-monorepo dumps by default.
3. **No training** — customer code must not be used to train Awarexone models.
4. **Redaction** — apply [secret redaction](security.md#secret-redaction) before any optional provider call.
5. Provider keys are customer secrets; AXGuard must not log them.

---

## Self-hosted option

Self-hosting the GitHub adapter + AXGuard Core:

- Keeps **repository source off Awarexone infrastructure**
- Uses the customer’s own App credentials, webhook endpoint, and compute
- Still follows the same permission matrix and `retain_source: false` default
- Optional AI providers stay under the customer’s network and contracts

Hosted vs self-hosted is a deployment choice; privacy guarantees for self-hosted are stronger because Awarexone never receives the webhook body or blobs.

---

## Token security

| Credential | Lifetime | Storage |
|---|---|---|
| GitHub App **JWT** (RS256, App id + private key) | ~10 minutes max (GitHub limit) | Private key in secret manager; never in repo or logs |
| **Installation access token** | Short-lived (GitHub-issued, typically ~1 hour) | Request per job or refresh window; **never permanent**; discard after use |
| Webhook **secret** | Long-lived shared secret | Secret manager only; used for HMAC verify |

Principles:

- Prefer minting a fresh installation token per analysis job over long-lived caching.
- If a token is cached briefly to amortize API calls, enforce TTL well under GitHub’s expiry and encrypt at rest.
- Rotate App private keys and webhook secrets on a schedule and after personnel or incident events.
- Uninstall revokes the installation; outstanding tokens fail subsequent API calls.

See also: [Authenticating as a GitHub App installation](https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/authenticating-as-a-github-app-installation).

---

## Customer controls

- Install on selected repositories only ([permissions.md](permissions.md#installer-guidance-least-privilege)).
- Disable PR summary comments (Checks-only) to reduce written metadata in the PR timeline.
- Uninstall to cut off all further access ([permissions.md](permissions.md#uninstall-and-revoke)).
- Self-host to keep code and webhooks entirely in your environment.

---

## Change control

Changes to retention defaults, AI egress, or logging must update this document and pass security review. Default stance: **no source retention, no secret logging, no AI egress without configuration**.
