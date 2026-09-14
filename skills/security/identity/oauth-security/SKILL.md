---
name: oauth-security
description: Analyze OAuth/OIDC integration security — use when reviewing redirect URIs, state/nonce, token handling, PKCE, or confused-deputy risks in authorization code flows (CWE-601 / A07:2021 / API2:2023).
version: "1.0.0"
author: AwareXone
license: MIT
domain: identity
subcategory: oauth
tags: [oauth, oidc, redirect, pkce, cwe-601]
frameworks:
  cwe: [CWE-601, CWE-287, CWE-352]
  owasp_top10: [A07:2021]
  owasp_api_top10: [API2:2023]
  owasp_llm_top10: []
  owasp_wstg: []
  owasp_asvs: []
  mitre_attack: []
  mitre_atlas: []
  nist_csf: []
  nist_ai_rmf: []
related_skills: [authentication-analysis, jwt-security, session-security, authorization-analysis, api-security, security-triage, security-remediation]
related_commands: [/axguard-auth, /axguard-audit, /axguard-cloud]
related_rules: [auth.]
references:
  - https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/
  - https://owasp.org/API-Security/editions/2023/en/api2-broken-authentication/
  - https://cwe.mitre.org/data/definitions/601.html
  - https://cwe.mitre.org/data/definitions/287.html
last_reviewed: "2026-09-15"
---

# OAuth Security

## Purpose

Teach defensive review of **OAuth 2.0 / OpenID Connect** client and resource-server integrations: redirect URI validation, CSRF (`state`), replay (`nonce`), PKCE, and token handling.

## When to Use / When Not to Use

**Use when:**

- Apps act as OAuth clients (social login, enterprise IdP) or resource servers validating access tokens.
- Custom callback handlers, deep links, or mobile schemes receive `code`/`token`.
- Reviewing “Login with …” or multi-tenant SSO.

**Do not use when:**

- Homegrown username/password only (`authentication-analysis`).
- JWT crypto bugs without OAuth protocol context (`jwt-security`).

## Security Concepts

OAuth security hinges on **binding the redirect to a pre-registered URI**, binding the browser session with `state`, and (for public clients) **PKCE**. Implicit/token-in-URL flows are legacy. Open redirects in post-login destinations are often chained with OAuth.

## Threat Model

Attacker goals:

1. Steal authorization codes via open/unsafe redirect URIs.
2. CSRF login linking (account takeover via victim completing OAuth without `state`).
3. Token leakage via referrers, logs, or insecure storage.
4. Confused deputy / overly broad scopes.

## Analysis Workflow

1. Identify roles: client, auth server, resource server; which code you own.
2. Verify redirect URI matching is exact/allowlisted — no wildcards that enable takeover.
3. Confirm `state` generated with entropy, stored server-side or signed, validated on callback.
4. For OIDC: validate `nonce` and ID token claims (`iss`, `aud`, `exp`) — hand signature details to `jwt-security`.
5. Prefer auth code + PKCE; reject implicit flow for new apps.
6. Check token storage (HttpOnly cookies vs localStorage), refresh rotation, and scope minimization.
7. Review post-auth redirects for open redirect (CWE-601) chaining.
8. Ensure client secrets are not in mobile/SPA binaries (`secrets-detection`).

## Evidence Requirements

- Callback / client config location
- Missing `state`/PKCE/redirect allowlist or token mishandling
- Impact: code theft / account linking CSRF / token leak

## False Positive Controls

- Server apps using confidential clients with exact redirect URIs and validated `state`
- Device/code flows intentionally different — review against their RFC threats separately
- Third-party IdP misconfiguration outside owned code (document; do not “hack” IdP)

## Remediation

1. Exact redirect URI allowlists; HTTPS (except controlled loopback dev).
2. Mandatory `state`; PKCE for public clients; auth code flow.
3. Validate ID/access tokens fully; minimize scopes.
4. Store tokens securely; rotate refresh tokens; revoke on logout.
5. Fix open redirects on post-login destinations.

## Verification

```text
Map OAuth callbacks → Enforce redirect/state/PKCE → Re-run axguard → Confirm tokens not in URLs/logs
```

## Related Skills

- `authentication-analysis`, `jwt-security`, `session-security`
- `authorization-analysis`, `api-security`
- `security-triage`, `security-remediation`

## Framework Mapping

- CWE-601, CWE-287, CWE-352
- OWASP A07:2021
- OWASP API2:2023 Broken Authentication

## References

- https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/
- https://owasp.org/API-Security/editions/2023/en/api2-broken-authentication/
- https://cwe.mitre.org/data/definitions/601.html
- https://cwe.mitre.org/data/definitions/287.html

## Research Provenance

Primary sources:

- OWASP A07:2021; OWASP API2:2023; CWE-601; CWE-287; CWE-352 (accessed 2026-09-15)

Secondary / internal:

- AXGuard `rules/auth.json`, `/axguard-auth`
- AwareXone Agentic-Bug-Hunter OAuth methodology (concepts only; not copied)

Datasets:

- UVID HF dataset — category linkage concepts only (MIT license metadata review 2026-09-15)
