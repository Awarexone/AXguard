---
name: jwt-security
description: Analyze JWT implementation flaws — use when reviewing alg confusion, none algorithm, missing verify, weak secrets, or claim validation gaps (A07:2021 / API2:2023 / auth.jwt rules).
version: "1.0.0"
author: AwareXone
license: MIT
domain: identity
subcategory: tokens
tags: [jwt, jose, tokens, authentication]
frameworks:
  cwe: [CWE-287]
  owasp_top10: [A07:2021]
  owasp_api_top10: [API2:2023]
  owasp_llm_top10: []
  owasp_wstg: []
  owasp_asvs: []
  mitre_attack: []
  mitre_atlas: []
  nist_csf: []
  nist_ai_rmf: []
related_skills: [authentication-analysis, authorization-analysis, oauth-security, session-security, api-security, security-triage, security-remediation]
related_commands: [/axguard-auth, /axguard-audit, /axguard-crypto]
related_rules: [auth., crypto.]
references:
  - https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/
  - https://owasp.org/API-Security/editions/2023/en/api2-broken-authentication/
  - https://cwe.mitre.org/data/definitions/287.html
last_reviewed: "2026-09-15"
---

# JWT Security

## Purpose

Encode defensive analysis of **JSON Web Tokens**: signature verification, algorithm handling, claim validation, and secret/key management mistakes that enable impersonation.

## When to Use / When Not to Use

**Use when:**

- APIs accept JWTs (access/refresh/ID tokens), custom `jose` usage, or `jwt.decode` without verify.
- After AXguard hits `auth.jwt-none-algorithm`, `auth.jwt-decode-without-verify`, or weak HMAC secrets.

**Do not use when:**

- Opaque server-side session IDs only (`session-security`).
- Full OAuth/OIDC protocol issues beyond JWT crypto (pair with `oauth-security`).

## Security Concepts

JWTs are client-held assertions. **Verify signature with an allowlisted algorithm** before trusting claims. `alg=none`, RS↔HS confusion, and `decode` without `verify` are classic failures. Claims (`exp`, `nbf`, `aud`, `iss`, `sub`) must be enforced explicitly.

## Threat Model

Attacker goals:

1. Forge tokens (none alg, weak secret, key confusion).
2. Reuse tokens outside intended audience/issuer.
3. Privilege escalation via mutable claims trusted from token without server check.
4. Persist access via non-rotating refresh tokens.

## Analysis Workflow

1. Find JWT create/verify call sites and libraries.
2. Confirm verification is mandatory on every trust decision; ban `decode`-only auth.
3. Allowlist algorithms (e.g., `RS256`/`ES256`); reject `none`; never select alg from header alone unchecked.
4. Assess secret strength for HMAC; prefer asymmetric keys with proper rotation (JWKS).
5. Validate `exp`/`nbf`/`aud`/`iss`/`sub`; treat `role` claims as hints only unless issuer is trusted and authZ still applied.
6. Review refresh token storage, rotation, and revocation.
7. Ensure clock skew windows are reasonable; log verify failures.

## Evidence Requirements

- Verify/decode call site
- Missing verification, alg weakness, or claim gap
- Impact: impersonation / privilege escalation

## False Positive Controls

- Display-only decode of already-verified tokens
- Internal tools using JWT with strong secrets and full verify (still review claim authZ)
- Test keys clearly not used in production configs

## Remediation

1. Always verify with allowlisted algorithms and keyed material from a secrets manager/JWKS.
2. Enforce standard claims; keep tokens short-lived.
3. Rotate and revoke refresh tokens; bind to client where appropriate.
4. Do not put sensitive PII in JWT bodies unless necessary; assume readable.
5. Centralize token validation middleware.

## Verification

```text
Find JWT sinks → Enforce verify+alg allowlist+claims → Re-run axguard → Confirm none/decode-only paths gone
```

## Related Skills

- `authentication-analysis`, `oauth-security`, `authorization-analysis`
- `session-security`, `api-security`
- `security-triage`, `security-remediation`

## Framework Mapping

- CWE-287
- OWASP A07:2021
- OWASP API2:2023 Broken Authentication

## References

- https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/
- https://owasp.org/API-Security/editions/2023/en/api2-broken-authentication/
- https://cwe.mitre.org/data/definitions/287.html

## Research Provenance

Primary sources:

- OWASP A07:2021; OWASP API2:2023; CWE-287 (accessed 2026-09-15)

Secondary / internal:

- AXGuard `rules/auth.json`, `rules/advanced.json` JWT patterns, `/axguard-auth`
- AwareXone Agentic-Bug-Hunter JWT methodology (concepts only; not copied)

Datasets:

- UVID HF dataset — category linkage concepts only (MIT license metadata review 2026-09-15)
