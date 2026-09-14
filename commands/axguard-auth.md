---
description: AuthZ / IDOR / JWT / CSRF footgun hunt. Usage: /axguard-auth [path]
---

# /axguard-auth

**Specialist:** Access Control Lead

## Usage

```
/axguard-auth
/axguard-auth ./api
```

## Focus

- Object fetch by id without ownership/tenant scope (IDOR)
- Sibling routes missing middleware
- JWT `alg=none` / weak verification
- CSRF protection disabled on cookie sessions

## Steps

1. `axguard scan <path>` → keep `auth.*` findings.
2. Map routes/handlers manually for ownership checks the scanner cannot see.
3. Report only issues with a clear missing control.

## Chain

Escalate confirmed IDOR paths into `/axguard-report` impact language.
