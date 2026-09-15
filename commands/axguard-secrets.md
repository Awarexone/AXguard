---
description: Hunt hard-coded secrets, keys, tokens, PEM material. Usage: /axguard-secrets [path]
---

# /axguard-secrets

**Specialist:** Secrets Hunter

## Usage

```
/axguard-secrets
/axguard-secrets ./
```

## Steps

1. Run focused scan (filter secrets rules from full audit or grep leads):

```bash
axguard scan <path> --format json -o .findings/axguard/secrets.json
```

2. Keep findings whose id starts with `secrets.`
3. For each hit: confirm it is live material (not a fixture/example), then require rotation + removal.
4. Check `.env`, CI logs, committed configs, client bundles.

## Output

List each secret class, location, and rotation steps. Never echo full secret values in chat — redact middle chars.
