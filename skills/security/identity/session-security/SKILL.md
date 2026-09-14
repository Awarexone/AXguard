---
name: session-security
description: Analyze session management security — use when reviewing cookie flags, session fixation, timeout, logout, concurrent sessions, or server-side session stores (A07:2021 / CWE-287 / CWE-352 adjacency).
version: "1.0.0"
author: AwareXone
license: MIT
domain: identity
subcategory: session-management
tags: [session, cookies, fixation, csrf]
frameworks:
  cwe: [CWE-287, CWE-352]
  owasp_top10: [A07:2021]
  owasp_api_top10: [API2:2023]
  owasp_llm_top10: []
  owasp_wstg: []
  owasp_asvs: []
  mitre_attack: []
  mitre_atlas: []
  nist_csf: []
  nist_ai_rmf: []
related_skills: [authentication-analysis, jwt-security, oauth-security, websocket-security, xss-analysis, security-triage, security-remediation]
related_commands: [/axguard-auth, /axguard-xss, /axguard-audit]
related_rules: [auth., xss.]
references:
  - https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/
  - https://owasp.org/API-Security/editions/2023/en/api2-broken-authentication/
  - https://cwe.mitre.org/data/definitions/287.html
  - https://cwe.mitre.org/data/definitions/352.html
last_reviewed: "2026-09-15"
---

# Session Security

## Purpose

Guide review of **session management**: how authenticated state is established, stored, protected in transit/browser, rotated, and invalidated.

## When to Use / When Not to Use

**Use when:**

- Cookie sessions, server session stores, “remember me,” logout flows, or CSRF on cookie-authenticated state-changing requests.
- After finding XSS near session cookies (theft impact) or `auth.disable-csrf` style hits.

**Do not use when:**

- Pure bearer JWT APIs with no cookies (use `jwt-security`; still consider token storage on clients).
- AuthZ object checks unrelated to session lifecycle (`authorization-analysis`).

## Security Concepts

A session ID is a bearer capability. It needs entropy, TLS, cookie flags (`Secure`, `HttpOnly`, `SameSite`), rotation at login, and server-side invalidation at logout. CSRF matters when cookies authenticate browsers automatically.

## Threat Model

Attacker goals:

1. Steal or fixate session IDs → account takeover.
2. CSRF state-changing actions as the victim.
3. Prolong access via non-expiring sessions / missing logout.
4. Session confusion across privilege changes (login as user A then B without rotate).

## Analysis Workflow

1. Identify session mechanism (cookie SID, server store, signed cookie).
2. Check cookie attributes and scope (`Domain`/`Path` least privilege).
3. Confirm regeneration of session ID on login and privilege elevation.
4. Review idle/absolute timeouts and remember-me token design.
5. Verify logout destroys server session and clears cookies.
6. For cookie auth: CSRF tokens / SameSite / double-submit patterns on mutating routes.
7. Assess XSS impact if `HttpOnly` missing; bind with `xss-analysis`.

## Evidence Requirements

- Session config / middleware location
- Missing flag, rotation, timeout, or CSRF control
- Impact on account takeover or forged actions

## False Positive Controls

- Bearer-header APIs without cookie auth (CSRF N/A for classic cookie CSRF)
- SameSite=Strict with no cross-site needs and verified behavior
- Short-lived sessions with robust rotation already present

## Remediation

1. Set `Secure`, `HttpOnly`, and appropriate `SameSite`; use `__Host-` prefix when possible.
2. Rotate session IDs on login; invalidate on logout/password change.
3. Enforce timeouts; bind sessions to user agent risk signals as needed.
4. Protect mutating cookie-auth routes against CSRF.
5. Store minimal data server-side; never put privileges only in forgeable client state.

## Verification

```text
Review cookie/session lifecycle → Fix flags/rotation/CSRF → Re-run axguard → Confirm logout invalidates server state
```

## Related Skills

- `authentication-analysis`, `jwt-security`, `oauth-security`
- `websocket-security`, `xss-analysis`
- `security-triage`, `security-remediation`

## Framework Mapping

- CWE-287, CWE-352
- OWASP A07:2021
- OWASP API2:2023 Broken Authentication

## References

- https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/
- https://owasp.org/API-Security/editions/2023/en/api2-broken-authentication/
- https://cwe.mitre.org/data/definitions/287.html
- https://cwe.mitre.org/data/definitions/352.html

## Research Provenance

Primary sources:

- OWASP A07:2021; OWASP API2:2023; CWE-287; CWE-352 (accessed 2026-09-15)

Secondary / internal:

- AXGuard `rules/auth.json` (CSRF disable patterns), `/axguard-auth`
- AwareXone Agentic-Bug-Hunter session methodology (concepts only; not copied)

Datasets:

- UVID HF dataset — category linkage concepts only (MIT license metadata review 2026-09-15)
