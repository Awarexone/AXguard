# Research: AXGuard GitHub Security Bot (GitHub App)

**Status:** Internal architecture + API research (not a product claim or Marketplace listing)  
**Date:** 2026-09  
**Primary sources:** [docs.github.com](https://docs.github.com) (Apps, Webhooks, Checks, Marketplace)  
**Stance:** Static / symbolic review only. No active production attacks. Minimize permissions, retention, and trust surface.

---

## 1. Purpose

Define how AXGuard presents as a **GitHub App** that reviews pull requests and pre-ship signals, without embedding GitHub SDK details into AXGuard Core.

Goals:

| Goal | Implication |
|---|---|
| Pre-merge security signal | Check runs + annotations + one updatable PR summary comment |
| Least privilege | Only the permissions required to read code, read/write PRs, write checks |
| Ephemeral auth | JWT → short-lived installation tokens; never store tokens permanently |
| Privacy-minimizing | Minimize source retention; no secret logging; AI only via user-configured providers |
| Deployable two ways | Hosted App (webhooks) **or** self-hosted / Actions-triggered adapter |

This document does **not** claim GitHub Marketplace approval, listing readiness, or product launch status.

---

## 2. Architecture

```text
┌─────────────────────────────────────────────────────────────┐
│                     GitHub platform                         │
│  Webhooks · REST API · Checks UI · PR conversation          │
└───────────────────────────┬─────────────────────────────────┘
                            │ HTTPS (webhooks + API)
                            ▼
┌─────────────────────────────────────────────────────────────┐
│              AXGuard GitHub Adapter                         │
│  • Signature verify (X-Hub-Signature-256)                   │
│  • Replay guard (X-GitHub-Delivery)                         │
│  • JWT + installation token mint (≤1h)                      │
│  • Event → job queue                                        │
│  • Checkout / sparse fetch of PR head                       │
│  • Map findings → check runs, annotations, PR comment       │
│  • Mode switch: REVIEW | PRE-SHIP | WATCH                   │
└───────────────────────────┬─────────────────────────────────┘
                            │ internal API / CLI / library call
                            ▼
┌─────────────────────────────────────────────────────────────┐
│                    AXGuard Core                             │
│  scan · audit · surface · flow · verify · adversary ·       │
│  evidence · attack graph · report (deterministic first)     │
└─────────────────────────────────────────────────────────────┘
```

### 2.1 Layer responsibilities

| Layer | Owns | Must not own |
|---|---|---|
| **GitHub App registration** | App ID / client ID, private key, webhook secret, permission set, event subscriptions | Business logic, rule packs, Judge/Adversary |
| **GitHub Adapter** | Auth, webhooks, idempotency, GitHub API I/O, finding → Checks/comments mapping, mode policy | Deep analysis algorithms |
| **AXGuard Core** | Scanning, verification, evidence, reports | GitHub HTTP, JWT minting, webhook crypto |

### 2.2 Why the adapter boundary matters

- Core stays runnable as CLI (`axguard audit .`) without GitHub.
- Adapter can be swapped (GitHub App vs Actions job vs self-hosted webhook receiver).
- Security review of GitHub credentials is isolated to the adapter process.

---

## 3. Required permissions (minimize)

GitHub Apps start with **no** permissions; select the minimum required.

Official guidance:

- [Choosing permissions for a GitHub App](https://docs.github.com/en/apps/creating-github-apps/registering-a-github-app/choosing-permissions-for-a-github-app)
- [Permissions required for GitHub Apps](https://docs.github.com/en/rest/authentication/permissions-required-for-github-apps)

### 3.1 Recommended repository permissions

| Permission | Access | Why AXGuard needs it | Why not higher / extra |
|---|---|---|---|
| **Metadata** | `read` | Mandatory baseline for App installation context (repo identity, basic metadata). GitHub Apps effectively always carry metadata read for installation/API discovery. | Do not request `write`. |
| **Contents** | `read` | Fetch PR head / compare commits / read file blobs for analysis (HTTP Git or Contents API). Required for non-public and private repos the App is installed on. | Do **not** request `write` (no commits, no force-pushes, no branch deletion). |
| **Pull requests** | `read` + `write` | **Read:** PR metadata, files changed, base/head SHAs, diff context. **Write:** create/update the single summary comment (and related PR comment surfaces documented under pull-request access). | Prefer PR comments over “Issues” unless a future feature truly needs Issues; avoid `admin`. |
| **Checks** | `write` | Create/update **check runs** and **annotations** via the Checks API. **Write for Checks is GitHub-App-only** (OAuth apps / users cannot create check runs). | `read` alone cannot post CI-style results. |

Sources:

- [Building CI checks with a GitHub App](https://docs.github.com/en/apps/creating-github-apps/writing-code-for-a-github-app/building-ci-checks-with-a-github-app)
- [REST API endpoints for check runs](https://docs.github.com/en/rest/checks/runs)

### 3.2 Explicitly out of scope (do not request by default)

| Permission | Reason to omit |
|---|---|
| Contents `write` | No auto-commit / auto-fix unless a separate, opt-in product mode is designed later |
| Administration | High trust; not needed for PR review |
| Secrets / Actions secrets | Never read customer CI secrets |
| Workflows | Not required to *run* analysis; Actions is an alternate *delivery* channel |
| Security events / Dependabot / Code scanning write | Avoid overlapping GitHub-native security products unless integrating deliberately |
| Members / Organization admin | Identity expansion without need |

### 3.3 Permission change UX

Any permission increase requires installers to **accept** the new permissions on existing installations. Keep the first listing minimal so upgrades are rare and explainable.

---

## 4. Webhook model

Configure webhooks on the App registration; subscribe only to events the chosen permissions allow.

Official guidance:

- [Using webhooks with GitHub Apps](https://docs.github.com/en/apps/creating-github-apps/registering-a-github-app/using-webhooks-with-github-apps)
- [Webhook events and payloads](https://docs.github.com/en/webhooks/webhook-events-and-payloads)
- [Best practices for using webhooks](https://docs.github.com/en/webhooks/using-webhooks/best-practices-for-using-webhooks)

### 4.1 Required / primary events

| Event | Actions to handle | Adapter behavior |
|---|---|---|
| `pull_request` | **`opened`**, **`synchronize`**, **`reopened`** | Enqueue REVIEW (or PRE-SHIP if label/config says so). Use `pull_request.head.sha` as check run `head_sha`. Debounce rapid `synchronize` bursts. |

`pull_request` action types include (among others): `opened`, `synchronize`, `reopened`, `closed`, `edited`, `ready_for_review`, … — see [pull_request webhook](https://docs.github.com/en/webhooks/webhook-events-and-payloads#pull_request).

### 4.2 Optional events

| Event | Use | Notes |
|---|---|---|
| `pull_request` → `closed` | Cancel queued jobs; mark WATCH state idle | Do not scan merged code unless PRE-SHIP / release mode explicitly requests post-merge |
| `check_run` | Handle `rerequested` / `requested_action` for “Re-run” | Aligns with Checks UX in the CI-checks tutorial |
| `installation` | Create/delete tenant records; revoke local config | Fired on install/uninstall |
| `installation_repositories` | Add/remove repos from tenant scope | Partial installs |
| `push` | Optional WATCH / default-branch policy scans | High volume — prefer PR-only unless justified |
| `release` | Optional PRE-SHIP gate on published releases | Tag/release artifact review, not exploit |

### 4.3 Delivery mechanics (operational)

- Respond **2xx within 10 seconds**; process asynchronously via a queue ([best practices](https://docs.github.com/en/webhooks/using-webhooks/best-practices-for-using-webhooks)).
- Payload size cap **25 MB**; oversized events may not be delivered ([webhook events overview](https://docs.github.com/en/webhooks/webhook-events-and-payloads)).
- Prefer **HTTPS** with SSL verification left enabled.
- Optionally allowlist GitHub webhook source IPs from [`GET /meta`](https://docs.github.com/en/rest/meta/meta) (`hooks` ranges).

### 4.4 Headers to always read

| Header | Purpose |
|---|---|
| `X-GitHub-Event` | Event name |
| `X-GitHub-Delivery` | Unique delivery id (idempotency / replay) |
| `X-GitHub-Hook-Installation-Target-ID` / related | Installation routing (when present) |
| `X-Hub-Signature-256` | HMAC integrity |

---

## 5. Authentication

### 5.1 Two-token model

```text
App private key (PEM)
        │
        ▼
   JWT (RS256, exp ≤ 10 min)     ← authenticate *as the App*
        │
        │  POST /app/installations/{id}/access_tokens
        ▼
Installation access token (≈ 1 hour)  ← authenticate *as the installation*
        │
        ▼
   REST calls (Contents, PRs, Checks, …)
```

Official docs:

- [Generating a JWT for a GitHub App](https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/generating-a-json-web-token-jwt-for-a-github-app)
- [Generating an installation access token](https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/generating-an-installation-access-token-for-a-github-app)
- [Authenticating as a GitHub App installation](https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/authenticating-as-a-github-app-installation)

### 5.2 JWT claims (current behavior)

| Claim | Rule |
|---|---|
| `iat` | Issued-at; GitHub recommends skew buffer (e.g. 60s in the past) for clock drift |
| `exp` | **No more than 10 minutes** after issue |
| `iss` | App **client ID** (recommended) or application ID |
| `alg` | **RS256** only |
| Header | `Authorization: Bearer <JWT>` (Bearer required for JWTs) |

### 5.3 Installation tokens

- Expire after **approximately one hour**.
- May optionally be scoped down further with `repositories` / `repository_ids` and a reduced `permissions` object on mint (cannot exceed App grant).
- **Never store permanently.** Keep in memory / short TTL cache only; mint per job or refresh near expiry.
- Prefer Octokit / official SDKs for refresh if used; still treat tokens as secrets.

### 5.4 Token format note (2026)

GitHub has documented a staged rollout (from **2026-04-27**) of a **stateless** installation token format (`ghs_APPID_JWT`-style). Apps that assume a fixed **40-character** token length may break. Validate against current docs and the temporary opt-in header described in GitHub’s App token documentation / blog when testing.

### 5.5 Secrets inventory (adapter)

| Secret | Storage | Rotation |
|---|---|---|
| App private key PEM | KMS / sealed secret; never in git | Rotate via GitHub App settings; dual-key window if possible |
| Webhook secret | Same | Rotate; dual-verify briefly if needed |
| Installation tokens | Memory only | Auto-expire ≤1h |
| Customer AI provider keys | Customer-controlled; never logged | Customer rotation |

---

## 6. Webhook signature verification + replay protection

### 6.1 Signature (`X-Hub-Signature-256`)

Official: [Validating webhook deliveries](https://docs.github.com/en/webhooks/using-webhooks/validating-webhook-deliveries)

1. Configure a high-entropy webhook secret on the App.
2. On each delivery, compute `HMAC-SHA256(secret, raw_body)`.
3. Expect header form: `sha256=<hex>`.
4. Compare with **constant-time** equality (`hmac.compare_digest` / `crypto.timingSafeEqual`). Never use `==`.
5. Verify against the **raw** body bytes (UTF-8); do not re-serialize JSON before verify.
6. Prefer `X-Hub-Signature-256` over legacy `X-Hub-Signature` (SHA-1).

GitHub publishes a known test vector (`secret` / `payload` / expected hex) in the validating-webhook-deliveries doc — use it in unit tests.

### 6.2 Replay protection

Official best practice: use **`X-GitHub-Delivery`** to ensure each delivery is unique per event ([best practices](https://docs.github.com/en/webhooks/using-webhooks/best-practices-for-using-webhooks)).

Recommended adapter policy:

1. After signature OK, look up `X-GitHub-Delivery` in a short-TTL idempotency store (e.g. Redis, 24–72h).
2. If seen → ack 2xx, skip work (safe for retries).
3. If new → record delivery id, enqueue job.
4. Note: **manual redelivery reuses the same delivery id** — treat as idempotent, not as a new scan trigger unless content/SHA policy says otherwise.
5. Optionally reject deliveries whose payload `repository.pushed_at` / event timestamp is older than a configured skew (defense in depth; signature still primary).

### 6.3 Processing order

```text
TLS terminate → read raw body → verify X-Hub-Signature-256
  → check X-GitHub-Delivery idempotency
  → parse JSON → filter event/action
  → enqueue → return 2xx quickly
```

---

## 7. Check runs, annotations, and PR summary comments

### 7.1 Check runs

- Create with `POST /repos/{owner}/{repo}/check-runs` using installation token.
- Required conceptual fields: `name`, `head_sha`, `status` (`queued` → `in_progress` → `completed`), and on completion `conclusion` (`success`, `failure`, `neutral`, `cancelled`, `timed_out`, `action_required`, `skipped`, … per current API enum).
- Only **GitHub Apps** can create check runs ([Checks API](https://docs.github.com/en/rest/checks/runs)).

Lifecycle recommendation:

1. On webhook: create check run `status=in_progress` (or `queued` then update).
2. Run AXGuard Core.
3. Update with `conclusion`, markdown `output.summary` / `output.text`, and annotations.

### 7.2 Annotations

- Each annotation needs at least: `path`, `start_line`, `end_line`, `annotation_level` (`notice` \| `warning` \| `failure`), `message`.
- **Max 50 annotations per API request**; append more via repeated `PATCH` updates ([check runs docs](https://docs.github.com/en/rest/checks/runs)).
- Cap displayed findings (e.g. top N by severity/confidence) to avoid spam; link to full report artifact if needed.
- Map AXGuard severities conservatively (e.g. critical/high → `failure`, medium → `warning`, low/info → `notice`), gated by confidence so UNKNOWN does not fail the check unless policy says so.

### 7.3 PR summary comment marker

Maintain **exactly one** bot summary comment per PR, identified by an HTML comment marker:

```html
<!-- AXGUARD-SECURITY-REVIEW -->
```

Pattern:

1. List issue/PR comments for the PR number.
2. Find comment whose body contains the marker.
3. If found → `PATCH` update; else → `POST` create.
4. Keep the marker on the first line of the body so updates stay stable across markdown edits.

Comment body outline:

- Mode (REVIEW / PRE-SHIP / WATCH)
- Verdict counts (by severity + confidence)
- Top findings with file:line
- Link to check run details
- Explicit “no active exploitation / no production attacks” disclaimer for WATCH/PRE-SHIP

### 7.4 Fork PRs

Checks API behavior: pushes on **fork** branches may yield empty `pull_requests` associations for check runs created in the base repo ([Checks API notes](https://docs.github.com/en/rest/checks/runs)). Design for:

- Running against `pull_request.head.sha` from the webhook payload directly.
- Clear UX when annotations cannot bind to fork paths the same way.
- Never requesting broader permissions “to make forks work.”

---

## 8. Three modes: REVIEW, PRE-SHIP, WATCH

All modes are **read-only analysis** relative to the customer environment. **No active production attacks**, no live exploit attempts, no credential stuffing, no SSRF probes against customer infra.

| Mode | Trigger (typical) | Depth | GitHub outputs | Gate behavior |
|---|---|---|---|---|
| **REVIEW** | `pull_request` opened / synchronize / reopened | PR-diff-focused + targeted Core passes | Check run + annotations + summary comment | Fail check on high-confidence critical/high per policy |
| **PRE-SHIP** | Label `/axguard-preship`, release event, or protected-branch config | Full audit-style pipeline (threat-model → audit → triage signals) | Check run (stricter conclusions) + summary | Suitable for release blockers; still static/symbolic only |
| **WATCH** | Optional push to default branch, schedule, or install health | Lightweight / incremental; trend + drift | Neutral/success check or comment-only; low noise | Observability; does not page on every commit |

Shared hard rules:

- Deterministic engines first; LLM only as optional explainer/summarizer behind user-configured providers.
- Prefer UNKNOWN / needs-review over inventing evidence (AXGuard Core stance).
- Never exfiltrate full repos to third parties without explicit customer AI provider config.

---

## 9. GitHub Actions integration vs GitHub App

| Dimension | GitHub App (webhook service) | GitHub Actions workflow |
|---|---|---|
| **Trigger** | Server receives webhooks | Workflow YAML on `pull_request` / `workflow_dispatch` |
| **Auth** | App JWT + installation token | `GITHUB_TOKEN` or App token via `actions/create-github-app-token` |
| **Checks API write** | Native App strength | Actions can post check runs / annotations with limitations (Actions also has annotation quotas per step) |
| **UX** | Install once; works across repos without copying workflows | Requires workflow file per repo (or org reusable workflow) |
| **Data plane** | Code may leave GitHub runners into adapter host | Code stays on GitHub-hosted / self-hosted runners if Core runs in-job |
| **Ops** | You run always-on HTTPS + queue | GitHub runs jobs; you maintain action + optional backend |
| **Best fit** | Productized “AXGuard Security” bot | Open-source / enterprise air-gap / “bring your own runner” |

**Recommended product shape:** App as the primary UX; ship a thin **Actions wrapper** that calls the same Adapter→Core path (or runs Core in-process) for customers who refuse outbound webhooks.

Complementary, not exclusive: App posts Checks; Actions can still run `axguard audit` and upload SARIF/HTML artifacts.

---

## 10. Self-hosted option

For enterprises that cannot send code or webhooks to AXGuard SaaS:

```text
Customer VPC / GHES
  ├── Webhook receiver (Adapter)  ← same signature + JWT logic
  ├── Queue + worker
  ├── AXGuard Core (container / binary)
  └── Optional local AI endpoint (customer-configured)
```

Requirements:

- Public or privately routed HTTPS endpoint reachable by GitHub.com / GHES.
- Same permission set; private key and webhook secret stay in customer secret store.
- Document GHES API hostname differences (`api.` vs enterprise URL) when supporting GHES.
- Mirror rate-limit and delivery idempotency behavior.

Self-hosted does **not** reduce the need for signature verification or least privilege.

---

## 11. Free vs paid infrastructure

| Cost center | Who pays | Notes |
|---|---|---|
| **GitHub API usage for a GitHub App** | Generally included with GitHub; Apps use installation-token rate limits (base on the order of **5,000 req/hour** per installation for GitHub.com, with documented scaling for large orgs — verify live via [`GET /rate_limit`](https://docs.github.com/en/rest/rate-limit/rate-limit)) | API access itself is not a separate “App API fee”; abide by [API Terms](https://docs.github.com/en/site-policy/github-terms/github-terms-of-service) and rate limits |
| **AI inference** | Customer or AXGuard (product choice) | Separate from GitHub. Only call user-configured providers; bill accordingly |
| **Hosting (Adapter + queue + storage)** | Operator of the App (AXGuard SaaS or customer self-host) | TLS, compute, logs, idempotency store |
| **GitHub Actions minutes** | Customer (if using Actions path) | Independent of App hosting |
| **Marketplace listing** | Free vs paid *plans* are a commercial choice; paid Marketplace apps have extra publisher requirements | See §13 — **no approval claimed** |

Rule of thumb for messaging: **“GitHub API is free with a GitHub App; AI and hosting are separate.”**

---

## 12. Security risks and mitigations

| Risk | Mitigation |
|---|---|
| Forged webhooks | HMAC `X-Hub-Signature-256` + constant-time compare; reject missing signature |
| Replay | Persist `X-GitHub-Delivery`; short TTL; idempotent handlers |
| Stolen App private key | KMS, rotation, anomaly alerts on mint volume; minimal machine access |
| Over-scoped tokens | Mint installation tokens with reduced `permissions` / repo subset when possible |
| Prompt injection via PR text / README | Core policy: repo text cannot rewrite safety policy; LLM never invents evidence |
| Secret leakage in logs | Redact tokens, PEMs, `Authorization`, webhook secrets, `.env` values; never log raw installation tokens |
| Untrusted fork code execution | Prefer static analysis; if any build/exec sandbox exists later, isolate hard — default is **no code execution** |
| SSRF via malicious repo content | No outbound fetch of user-controlled URLs during review; AI providers allowlisted |
| Secondary rate limits / abuse | Backoff; debounce `synchronize`; batch annotation patches |
| Confused deputy across installs | Bind every job to `installation_id` + repo id from verified payload |
| Supply chain of Adapter deps | Pin/lock; SBOM; no `curl \| bash` in install docs for production |

Also follow: [Best practices for creating a GitHub App](https://docs.github.com/en/apps/creating-github-apps/about-creating-github-apps/best-practices-for-creating-a-github-app).

---

## 13. Marketplace prep (do not claim approval)

Prepare for a future listing; **do not assert** that AXGuard is approved, listed, or verified.

Official references:

- [Requirements for listing an app](https://docs.github.com/en/apps/github-marketplace/creating-apps-for-github-marketplace/requirements-for-listing-an-app)
- [GitHub Marketplace Developer Agreement](https://docs.github.com/en/site-policy/github-terms/github-marketplace-developer-agreement)
- [About GitHub Marketplace](https://docs.github.com/en/apps/github-marketplace/github-marketplace-overview/about-github-marketplace) (path may redirect; use Marketplace docs hub if moved)

Checklist (prep only):

| Item | Notes |
|---|---|
| Privacy policy URL | Required for listings |
| Support contact / URL | Required |
| Accurate permissions description | Match runtime App settings |
| Webhook handling for Marketplace purchase events | Required if using Marketplace billing plans |
| Paid plan extras | Publisher verification; minimum installation counts (docs cite **100** GitHub App installs for paid); purchase event handling |
| ToS acceptance | Marketplace Developer Agreement |
| Security narrative | Least privilege, no permanent token storage, data retention limits |

GitHub retains discretion over what appears on Marketplace. Submission ≠ approval.

---

## 14. Data flow / privacy

```text
GitHub webhook (metadata + SHAs)
    → Adapter verifies signature
    → Installation token (ephemeral)
    → Fetch only needed blobs / PR diff
    → AXGuard Core (local to Adapter worker)
    → Optional: snippets to user-configured AI provider
    → Results → Checks + PR comment
    → Delete working tree / GC job artifacts per TTL
```

Policies:

| Topic | Policy |
|---|---|
| Source retention | Keep working copies only for job TTL (e.g. minutes–hours); prefer ephemeral disks |
| Secrets | Never log; scrub findings that are themselves secrets before commenting if policy requires redaction in public PRs |
| AI | Code/snippets leave the trust boundary **only** to providers the user configured; no silent third-party model calls |
| Cross-tenant | Strict installation/repo isolation; no shared caches of source across customers |
| Subprocessors | Disclose hosting + any default AI in privacy policy before Marketplace |
| Customer deletion | On `installation` deleted, wipe tenant config and residual artifacts |

Public PR comments are visible to anyone who can see the PR — avoid pasting full secret values into comments/annotations; point to check summary with redaction.

---

## 15. Suggested implementation sequence

1. Register GitHub App (dev) with minimal permissions + `pull_request` events.  
2. Implement signature verify + delivery idempotency + JWT/installation mint.  
3. Map one finding → one annotation + summary comment with `<!-- AXGUARD-SECURITY-REVIEW -->`.  
4. Wire REVIEW mode to Core `audit`/`scan` on PR head.  
5. Add PRE-SHIP config (label/release) and WATCH (optional).  
6. Add Actions composite for self-serve runners.  
7. Hardening: rate limits, redaction, retention TTLs.  
8. Marketplace **prep** docs/privacy — submit only when product-ready (still no approval claim).

---

## 16. Official docs index (primary)

| Topic | URL |
|---|---|
| Choosing App permissions | https://docs.github.com/en/apps/creating-github-apps/registering-a-github-app/choosing-permissions-for-a-github-app |
| Permissions ↔ REST endpoints | https://docs.github.com/en/rest/authentication/permissions-required-for-github-apps |
| Webhooks with GitHub Apps | https://docs.github.com/en/apps/creating-github-apps/registering-a-github-app/using-webhooks-with-github-apps |
| Webhook events & payloads | https://docs.github.com/en/webhooks/webhook-events-and-payloads |
| Validating webhook deliveries | https://docs.github.com/en/webhooks/using-webhooks/validating-webhook-deliveries |
| Webhook best practices | https://docs.github.com/en/webhooks/using-webhooks/best-practices-for-using-webhooks |
| JWT for GitHub Apps | https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/generating-a-json-web-token-jwt-for-a-github-app |
| Installation access tokens | https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/generating-an-installation-access-token-for-a-github-app |
| Authenticating as installation | https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/authenticating-as-a-github-app-installation |
| Building CI checks | https://docs.github.com/en/apps/creating-github-apps/writing-code-for-a-github-app/building-ci-checks-with-a-github-app |
| Check runs REST API | https://docs.github.com/en/rest/checks/runs |
| Rate limits | https://docs.github.com/en/rest/rate-limit/rate-limit |
| Meta / hook IPs | https://docs.github.com/en/rest/meta/meta |
| App best practices | https://docs.github.com/en/apps/creating-github-apps/about-creating-github-apps/best-practices-for-creating-a-github-app |
| Marketplace listing requirements | https://docs.github.com/en/apps/github-marketplace/creating-apps-for-github-marketplace/requirements-for-listing-an-app |
| Marketplace Developer Agreement | https://docs.github.com/en/site-policy/github-terms/github-marketplace-developer-agreement |

---

## 17. Open questions (for later product decisions)

1. Default check conclusion when confidence is UNKNOWN — `neutral` vs `success`?  
2. Whether PRE-SHIP may upload HTML reports as release/check artifacts (storage + retention).  
3. GHES support timeline and API version pinning (`X-GitHub-Api-Version`).  
4. Whether a separate “autofix” App permission set (Contents write) is ever justified as opt-in.  
5. Commercial packaging: SaaS App vs self-hosted license vs Actions-only.

---

*End of research note. Implementation belongs in a future `adapters/github/` (or equivalent) — not specified here as landed code.*
