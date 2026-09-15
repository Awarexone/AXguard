---
description: Triage AXguard findings — kill false positives, promote confirmed bugs. Usage: /axguard-triage [report]
---

# /axguard-triage

**Specialist:** Triage Lead

## Usage

```
/axguard-triage
/axguard-triage .findings/axguard/axguard-report.json
```

## Gate (all must pass to keep a finding)

1. Is the sink real in shipped code (not a test fixture unless fixtures are the target)?
2. Can attacker-controlled data reach it, or is a control clearly missing?
3. Is impact more than theoretical style nits?
4. Is the fix actionable?

Drop anything that fails. Promote survivors with severity + evidence.

When `.findings/axguard/adversary.json` is present (after Judge), prefer adversary **final** statuses (`CONFIRMED` / `LIKELY` / `UNVERIFIED` / `FALSE_POSITIVE` / `REQUIRES_REVIEW`) over raw Judge labels for Keep vs Drop.

## Output

| Keep / Drop | ID | Severity | One-line reason |
