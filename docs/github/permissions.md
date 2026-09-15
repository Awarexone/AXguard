# AXGuard GitHub App — Permissions

AXGuard requests the **minimum GitHub App permissions** needed to read repository context, run security analysis, publish Check Run results, and post a single PR summary comment. Every granted permission has a documented reason. Broad or unused permissions are rejected.

Related architecture and webhook design: [docs/research/github-security-bot.md](../research/github-security-bot.md) (when present). Privacy and retention: [privacy.md](privacy.md). Threat model for untrusted content: [security.md](security.md).

Official reference: [GitHub Apps permissions](https://docs.github.com/en/apps/creating-github-apps/registering-a-github-app/choosing-permissions-for-a-github-app).

---

## Permission matrix (granted)

| Permission | Access | Required | Reason |
|---|---|---|---|
| **Repository contents** | `read` | Yes | Read file trees and blobs for the PR head (and optionally base) so AXGuard can scan changed and related source. Never write to the default branch or force-push. |
| **Metadata** | `read` | Yes (mandatory) | GitHub requires metadata for every App. Used for repository identity, default branch, visibility, and installation context only. |
| **Checks** | `write` | Yes | Create and update Check Runs / annotations that surface findings in the PR Checks UI without mutating code. |
| **Pull requests** | `read` | Yes | Read PR metadata, changed files, commits, and diff context for REVIEW / PRE-SHIP analysis. |
| **Pull requests** | `write` | Conditional | **Only** to create or update the AXGuard summary comment (marker `<!-- AXGUARD-SECURITY-REVIEW -->`). Not used to approve, request changes, merge, or edit PR titles/bodies. |

### Access levels in words

- **contents:read** — clone/fetch via API or Git for analysis input; no contents write.
- **metadata:read** — always on for GitHub Apps; no extra scope beyond identity.
- **checks:write** — report conclusions (`success` / `neutral` / `failure` per policy) and line annotations.
- **pull_requests:read** — understand what changed and where to comment.
- **pull_requests:write** — summary comment upsert only; disable in config if comments are unwanted (Checks-only mode).

---

## Explicitly rejected permissions

AXGuard **must not** request or accept App configurations that grant the following (unless a future, separately documented, opt-in product feature is approved and reviewed):

| Permission | Why rejected |
|---|---|
| **contents:write** / **contents:admin** | No commits, branches, tags, or file writes from the bot. Patches are suggestions in comments/checks only. |
| **administration** | No repo settings, collaborators, or branch protection changes. |
| **actions** (read or write) | No workflow run control, secret reading, or Actions artifact access. |
| **secrets** / **dependabot secrets** / **environments** | Never touch repository or org secrets. |
| **workflows** | No editing of workflow files via App write. |
| **security_events** / **vulnerability alerts** (write) | Findings stay in Checks / PR comments; no Code Scanning API upload unless a future opt-in is specified. |
| **members** / **organization administration** | Org-wide identity and admin are out of scope. |
| **issues:write** (and usually **issues:read**) | AXGuard does not open or triage Issues by default. PR comments use the pull_requests permission, not issues. |
| **statuses:write** | Prefer Checks API over legacy commit statuses. Do not request both unless a documented compatibility mode requires statuses. |
| **deployments** / **packages** / **pages** | Unrelated to static security review. |
| **single file** write | No privileged path writes. |
| **email** / **profile** user data beyond installation actor identity for audit of who installed the App | Minimize PII. |

If a Marketplace listing or manifest ever drifts toward broader scopes, treat that as a **security regression**: revoke, rebuild the App manifest with the matrix above, and re-install.

---

## Mode-specific needs

| Mode | Extra permission notes |
|---|---|
| **REVIEW** (PR opened / synchronize / reopened) | contents:read + pull_requests:read + checks:write; pull_requests:write only for summary comment. |
| **PRE-SHIP** (release / tag / manual) | Same repository scopes; may read release metadata via existing contents/metadata if exposed on the event — still no contents:write. |
| **WATCH** (post-ship / push to default branch) | Same read scopes; Checks may target the commit SHA. Still no admin, Actions, or secrets access. |

Optional webhook subscriptions (`installation`, `installation_repositories`, `push`, `release`, `check_run`) do **not** require extra repository permissions beyond the matrix; they only deliver events.

---

## Installation tokens (scope enforcement)

- Access to GitHub APIs uses **short-lived installation access tokens** minted from the App JWT for a single installation.
- Tokens inherit **only** the permissions above for repositories selected at install time.
- Never store installation tokens permanently. See [privacy.md](privacy.md#token-security).

---

## Installer guidance (least privilege)

When installing AXGuard:

1. Prefer **Only select repositories** over All repositories.
2. Review the permission screen: you should see Contents (read), Metadata (read), Checks (read & write), Pull requests (read, and write if comments enabled).
3. Reject any listing that asks for Administration, Actions, Secrets, or Contents write.
4. Restrict branch protection / required checks so AXGuard Check Runs gate merges only when your team opts in — AXGuard itself does not change protection rules.

---

## Uninstall and revoke

To fully remove AXGuard access:

1. **GitHub UI** — Repository or Organization → **Settings** → **Integrations** / **GitHub Apps** → AXGuard → **Uninstall** (or suspend).
2. Confirm the App no longer appears under installed Apps and that webhook deliveries stop.
3. **Self-hosted** — stop the AXGuard GitHub adapter process; delete local `GITHUB_APP_PRIVATE_KEY`, webhook secret, and any cached installation token material from disk/secret store.
4. **Hosted (Awarexone)** — uninstalling the App ends installation-token minting for that installation; request deletion of any non-source operational logs per [privacy.md](privacy.md) retention policy.
5. Rotate any **repository webhook secrets** or **App credentials** you generated solely for AXGuard if you also self-hosted a fork of the adapter.

After uninstall, AXGuard cannot read contents, create checks, or comment on pull requests for that installation.

---

## Change control

Any new GitHub permission requires:

1. A documented reason in this file.
2. Update to the App manifest / Marketplace listing.
3. Security review noting why a narrower alternative (Checks-only, comment-only) is insufficient.

Default stance: **deny new scopes**.
