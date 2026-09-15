---
description: Full A→Z pre-ship security audit. Writes Markdown + HTML + JSON reports. Usage: /axguard-audit [path]
---

# /axguard-audit

**Specialist:** Pre-ship Lead

Run when the user is about to publish, ship, or open a PR and wants a complete security pass — not a single vuln class.

## Usage

```
/axguard-audit
/axguard-audit .
/axguard-audit ./apps/api
```

## Steps

1. Ensure CLI: `axguard version` (else `pip install -e .` from this repo).
2. Run:

```bash
axguard audit <path> --out-dir .findings/axguard
```

3. Open reports:
   - `.findings/axguard/axguard-report.html`
   - `.findings/axguard/axguard-report.md`
4. Triage **critical/high** with source→sink reasoning.
5. Summarize severity counts + concrete fixes.

## Chain

- Narrow a class → `/axguard-secrets`, `/axguard-auth`, …
- Polish deliverable → `/axguard-report`
- Apply fixes → `/axguard-fix`
- Threat model first → `/axguard-threat-model`
