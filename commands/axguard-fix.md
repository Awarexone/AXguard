---
description: Remediate confirmed AXguard findings with concrete patches. Usage: /axguard-fix
---

# /axguard-fix

**Specialist:** Remediation Engineer

## Usage

```
/axguard-fix
```

Requires an existing report or a just-finished `/axguard-audit` / `/axguard-triage`.

## Rules

- Fix confirmed issues only.
- One logical fix per change; keep diffs tight.
- Prefer safe APIs over clever filters.
- Re-run `axguard audit .` after fixes and show before/after counts.

## Order

1. critical → high → medium
2. Secrets: remove + rotate instructions first
3. RCE / injection sinks
4. AuthZ
5. Everything else
