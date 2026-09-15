# AXGuard GitHub Marketplace — listing preparation

Internal checklist and **placeholder** metadata for a future GitHub Marketplace listing of the AXGuard GitHub Bot / App.

**Status:** preparation only. This document does **not** claim Marketplace approval, listing, or publication. Do **not** publish from this file alone.

---

## Purpose

Capture listing fields early so product, legal, and design can fill real values before any Marketplace submission. All URLs and pricing below are placeholders until replaced with approved production assets.

---

## Listing metadata (placeholders)

| Field | Placeholder / notes |
|---|---|
| **Name** | `AXGuard` (confirm exact Marketplace display name) |
| **Short description** | `[TODO] One-line Marketplace blurb — security review for PRs; keep factual, no hype.` |
| **Full description** | `[TODO] Multi-paragraph listing body: what the app does on PRs, permissions required, privacy posture, support path. Align tone with docs/github/pr-ux.md.` |
| **Categories / tags** | `[TODO] e.g. Security, Code quality — confirm against current Marketplace taxonomy` |
| **Icon** | `[TODO] Path or asset URL — square Marketplace icon (recommended 1024×1024 PNG); brand-safe, no unapproved badges` |
| **Screenshots** | `[TODO] PR check + summary comment screenshots; redact customer secrets` |
| **Privacy policy URL** | `https://example.invalid/axguard/privacy` ← replace with real policy URL before any submission |
| **Support URL** | `https://example.invalid/axguard/support` ← replace with real support/docs/issues URL |
| **Homepage / docs URL** | `[TODO] e.g. https://awarexone.com/ or repo docs` |
| **Company / publisher** | `Awarexone` (confirm legal publisher name for Marketplace) |
| **Contact email** | `[TODO] Support or publisher email for Marketplace profile` |
| **Pricing model** | `[TODO] Placeholder only — e.g. Free / Free + paid plan / Paid. Do not publish pricing until approved.` |
| **Pricing details** | `[TODO] Plan names, seat/repo limits, trial terms — all TBD` |
| **Installation URL** | `[TODO] GitHub App install / Marketplace install link after listing exists` |
| **Webhook / App slug** | `[TODO] GitHub App slug once registered` |

---

## Description draft slots

Use these slots when drafting copy; leave empty until content is approved.

```text
SHORT_DESCRIPTION=
FULL_DESCRIPTION=
```

Suggested constraints for drafts:

- Describe security review behavior accurately (checks, annotations, single PR comment)
- Do not claim Marketplace approval, “featured”, or partner status
- Do not contradict PR UX rules (no star begging, no scare marketing in product screenshots)

---

## Asset checklist (pre-submission)

- [ ] Icon asset approved (`ICON_PATH=` / URL TBD)
- [ ] Privacy policy live at production URL
- [ ] Support page or issue template live at production URL
- [ ] Screenshots reviewed for secret leakage
- [ ] Pricing model decided and legal-approved (`PRICING_MODEL=`)
- [ ] Permissions list matches actual GitHub App scopes
- [ ] Listing copy reviewed against `docs/github/pr-ux.md` tone

---

## Explicit non-claims

- This repo path does **not** mean the app is on the GitHub Marketplace.
- Placeholders must not be pasted into a live listing without replacement.
- No publish, submit, or “go live” action is authorized by this document.

---

## Related

- Docs index: [README.md](./README.md)
- PR comment and check tone: [pr-ux.md](./pr-ux.md)
- Permissions: [permissions.md](./permissions.md)
- Privacy: [privacy.md](./privacy.md)
