---
description: Dataflow / taint path analysis (diagnostic). Usage: /axguard-flow [path]
---

# /axguard-flow

**Specialist:** Data Flow + Taint Analysis

## Usage

```
/axguard-flow
/axguard-flow ./app
```

## Focus

Static source→sink taint paths over the Phase 1 application model:

- Sources (request params/body/headers/cookies, env, webhooks, AI outputs)
- Sinks (sql, net, cmd, fs, html, eval, deser, redirect, ai_tool, …)
- Controls along paths (parameterization, allowlist, sanitization, authz)
- Taint states: TAINTED | PARTIALLY_SANITIZED | VALIDATED | SANITIZED | TRUSTED | UNKNOWN

This is **diagnostic inventory**, not a vulnerability report. Prefer UNKNOWN over inventing safety.

## Steps

1. Run:

```bash
axguard flow .
# or after surface during audit:
axguard audit . --out-dir .findings/axguard
```

2. Read:

- `.findings/axguard/dataflow.json`
- `.findings/axguard/dataflow.md`

3. Use path evidence to focus SSRF / SQLi / injection skills — do not treat paths as confirmed vulns without review.
