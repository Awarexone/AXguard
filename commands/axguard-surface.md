---
description: Map application understanding + attack surface graph (routes, sinks, stack, AI). Usage: /axguard-surface [path]
---

# /axguard-surface

**Specialist:** Application Understanding

## Usage

```
/axguard-surface
/axguard-surface ./app
```

## Focus

Before hunting vulns, build a structured model of:

- Technology stack / frameworks
- HTTP entry points and handlers
- Auth evidence (confirmed / likely / unknown — never invent)
- Sinks, assets (secrets REDACTED), external + AI services
- Trust boundaries and a queryable attack-surface graph

## Steps

1. Run:

```bash
axguard surface .
# or as part of a full audit:
axguard audit . --out-dir .findings/axguard
```

2. Read:

- `.findings/axguard/application-model.json`
- `.findings/axguard/application-model.md`

3. Prefer model facts with evidence over guessing. Load domain skills only after the surface is clear.
