---
name: authentication-analysis
description: Analyze authentication mechanisms — use when reviewing login, MFA, password storage, account recovery, API keys, or credential handling failures (CWE-287 / A07:2021 / API2:2023).
version: "1.0.0"
author: AwareXone
license: MIT
domain: identity
subcategory: authentication
tags: [authentication, login, mfa, credentials, cwe-287]
frameworks:
  cwe: [CWE-287, CWE-798]
  owasp_top10: [A07:2021]
  owasp_api_top10: [API2:2023]
  owasp_llm_top10: []
  owasp_wstg: []
  owasp_asvs: []
  mitre_attack: []
  mitre_atlas: []
  nist_csf: []
  nist_ai_rmf: []
related_skills: [session-security, jwt-security, oauth-security, authorization-analysis, secrets-detection, security-triage, security-remediation]
related_commands: [/axguard-auth, /axguard-secrets, /axguard-audit]
related_rules: [auth., secrets., crypto.]
references:
  - https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/
  - https://owasp.org/API-Security/editions/2023/en/api2-broken-authentication/
  - https://cwe.mitre.org/data/definitions/287.html
  - https://cwe.mitre.org/data/definitions/798.html
last_reviewed: "2026-09-15"
---

# Authentication Analysis

## Purpose

Encode pre-ship reasoning for **authentication** failures: proving identity incorrectly, weakly, or with recoverable/brute-forceable credentials.

## When to Use / When Not to Use

**Use when:**

- Login, signup, MFA, password reset, magic links, API keys, service accounts, or “auth disabled in prod” flags.
- After AXguard hits `auth.*`, `secrets.*`, or weak password hashing (`crypto.*`).
- Distinguishing “who are you?” issues from “what may you do?” (`authorization-analysis`).

**Do not use when:**

- The bug is purely object ownership after a valid login (use `authorization-analysis`).
- Token cryptography details dominate (prefer `jwt-security` / `oauth-security` after establishing auth flow).

## Security Concepts

Authentication binds a principal to a session/token. Failures include missing auth, guessable credentials, weak recovery, broken MFA, and hard-coded secrets. Rate limits and lockouts are part of auth, not optional UX.

## Threat Model

Attacker goals:

1. Credential stuffing / password spraying into account takeover.
2. Bypass MFA or reset flows.
3. Use hard-coded or leaked service credentials.
4. Authenticate as another user via flawed token issuance.

## Analysis Workflow

1. Inventory auth entry points (password, SSO, API keys, device codes).
2. Confirm password storage uses modern KDFs (Argon2/bcrypt/scrypt) — not MD5/SHA1 for passwords.
3. Review rate limits, lockout, and bot resistance on login/reset.
4. Trace account recovery: token entropy, expiry, one-time use, notification.
5. Check MFA enforceability for sensitive roles; detect backup-code weaknesses.
6. Hunt hard-coded credentials and auth-bypass flags (`if DEBUG: login as admin`).
7. Hand session cookies to `session-security`; JWT/OAuth stacks to those skills.

## Evidence Requirements

- Auth handler / config location
- Specific weakness (storage, bypass, recovery, rate limit)
- Affected identity class (user/admin/service)
- Impact: account takeover plausibility

## False Positive Controls

- Test-only backdoors clearly excluded from production builds
- Intentionally public endpoints
- Placeholder secrets in docs not deployed (still flag if ship risk)

## Remediation

1. Strong password KDF + breached-password checks where appropriate.
2. Rate-limit and monitor auth endpoints; secure recovery tokens.
3. MFA for privileged accounts; phishing-resistant factors when warranted.
4. Remove hard-coded credentials; use secret managers (`secrets-detection`).
5. Fail closed on auth errors; consistent responses to reduce user enumeration where feasible.

## Verification

```text
Map auth flows → Fix storage/bypass/limits → Re-run axguard → Confirm no prod bypass flags
```

## Related Skills

- `session-security`, `jwt-security`, `oauth-security`
- `authorization-analysis`, `secrets-detection`
- `security-triage`, `security-remediation`

## Framework Mapping

- CWE-287, CWE-798
- OWASP A07:2021 Identification and Authentication Failures
- OWASP API2:2023 Broken Authentication

## References

- https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/
- https://owasp.org/API-Security/editions/2023/en/api2-broken-authentication/
- https://cwe.mitre.org/data/definitions/287.html
- https://cwe.mitre.org/data/definitions/798.html

## Research Provenance

Primary sources:

- OWASP A07:2021; OWASP API2:2023; CWE-287; CWE-798 (accessed 2026-09-15)

Secondary / internal:

- AXGuard `rules/auth.json`, `rules/secrets.json`, `rules/crypto.json`, `/axguard-auth`
- AwareXone Agentic-Bug-Hunter authentication methodology (concepts only; not copied)

Datasets:

- UVID HF dataset — category linkage concepts only (MIT license metadata review 2026-09-15)
