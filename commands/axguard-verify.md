---
description: Hunter → Judge verification diagnostic (not a vuln report). Usage: /axguard-verify [path]
---

# /axguard-verify

**Specialist:** Hunter → Judge Verification

## Usage

```
/axguard-verify
/axguard-verify ./app
```

## Focus

Deterministic Phase 3 verification over the application model + dataflow:

- Hunters emit **candidates only** (never auto-VERIFIED)
- Judge assigns: `VERIFIED` | `LIKELY` | `UNVERIFIED` | `FALSE_POSITIVE`
- Prefer **UNVERIFIED** over inventing VERIFIED
- No LLM API calls in the default pipeline

This is a **diagnostic verification**, not a vulnerability advisory or full audit report.

## Steps

1. Run:

```bash
axguard verify .
# optional after surface/dataflow during audit (soft-attached, never fails audit):
axguard audit . --out-dir .findings/axguard
```

2. Read:

- `.findings/axguard/verification.json`
- `.findings/axguard/verification.md`

3. Use Judge statuses to focus triage — parameterized / allowlisted paths should not stay VERIFIED.
