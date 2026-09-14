---
name: authorization-analysis
description: Analyze authorization and access control — use for IDOR/BOLA, missing ownership checks, privilege escalation, and function-level authZ gaps (CWE-639 / CWE-862 / CWE-863 / A01:2021 / API1:2023 / API5:2023).
version: "1.0.0"
author: AwareXone
license: MIT
domain: identity
subcategory: authorization
tags: [authorization, idor, bola, bfla, cwe-639]
frameworks:
  cwe: [CWE-639, CWE-862, CWE-863]
  owasp_top10: [A01:2021]
  owasp_api_top10: [API1:2023, API5:2023]
  owasp_llm_top10: []
  owasp_wstg: []
  owasp_asvs: []
  mitre_attack: []
  mitre_atlas: []
  nist_csf: []
  nist_ai_rmf: []
related_skills: [api-security, graphql-security, authentication-analysis, jwt-security, security-triage, security-remediation]
related_commands: [/axguard-auth, /axguard-audit, /axguard-graphql]
related_rules: [auth.]
references:
  - https://owasp.org/Top10/A01_2021-Broken_Access_Control/
  - https://owasp.org/API-Security/editions/2023/en/api1-broken-object-level-authorization/
  - https://owasp.org/API-Security/editions/2023/en/api5-broken-function-level-authorization/
  - https://cwe.mitre.org/data/definitions/639.html
  - https://cwe.mitre.org/data/definitions/862.html
  - https://cwe.mitre.org/data/definitions/863.html
last_reviewed: "2026-09-15"
---

# Authorization Analysis

## Purpose

Teach systematic detection of **broken access control**: authenticated (or anonymous) callers acting outside their permitted objects, tenants, or functions.

## When to Use / When Not to Use

**Use when:**

- Handlers load objects by client-supplied IDs, or expose admin/actions based on role claims.
- After AXguard `auth.*` hits or `/axguard-auth` triage.
- Multi-tenant apps with `org_id` / `user_id` in paths or bodies.

**Do not use when:**

- The issue is proving identity (login/MFA) — use `authentication-analysis`.
- Pure injection into a sink with no access-control question.

## Security Concepts

Authorization answers **“is this principal allowed to do this to that object?”** UI hiding is not a control. Object-level (BOLA/IDOR) and function-level (BFLA) failures are distinct and both common in APIs.

## Threat Model

Attacker goals:

1. Read/update/delete another user’s objects by ID.
2. Invoke admin APIs as a standard user.
3. Cross-tenant data access in SaaS.
4. Escalate via mass-assigned role fields (pair with `api-security` / CWE-915).

## Analysis Workflow

1. List sensitive operations (read/write/delete/export/admin).
2. For each: identify how the object is selected (path/body/graphql id).
3. Confirm server-side check binds object to `current_user` / tenant — not merely “is logged in.”
4. Check role guards on admin functions; ensure middleware cannot be skipped by alternate routes.
5. Review horizontal (same role, other user) and vertical (privilege escalation) cases.
6. Inspect batch endpoints and exports for missing per-object checks.
7. Prefer proving missing checks in code; authorized dual-account tests only on owned systems.

## Evidence Requirements

- Handler location and object lookup
- Missing ownership/role predicate
- Affected object type and action
- Confidence: CONFIRMED only with code path + (when possible) dual-principal validation in authorized env

## False Positive Controls

- Public resources by design
- Capability URLs that are high-entropy **and** revoked/expired properly (still review leakage)
- Checks performed in a shared repository layer actually invoked by the handler

## Remediation

1. Centralize authZ policy (ownership + role + tenant).
2. Deny by default; test with two users and two tenants.
3. Never trust client-supplied `user_id`/`isAdmin` for decisions.
4. Apply the same checks to GraphQL resolvers, WS topics, and job consumers.
5. Log and alert authZ denials on sensitive resources.

## Verification

```text
Map object/function ops → Add ownership/role checks → Re-run axguard → Dual-user regression tests
```

## Related Skills

- `api-security`, `graphql-security`
- `authentication-analysis`, `jwt-security`
- `security-triage`, `security-remediation`

## Framework Mapping

- CWE-639, CWE-862, CWE-863
- OWASP A01:2021 Broken Access Control
- OWASP API1:2023, API5:2023

## References

- https://owasp.org/Top10/A01_2021-Broken_Access_Control/
- https://owasp.org/API-Security/editions/2023/en/api1-broken-object-level-authorization/
- https://owasp.org/API-Security/editions/2023/en/api5-broken-function-level-authorization/
- https://cwe.mitre.org/data/definitions/639.html
- https://cwe.mitre.org/data/definitions/862.html
- https://cwe.mitre.org/data/definitions/863.html

## Research Provenance

Primary sources:

- OWASP A01:2021; OWASP API1/API5:2023; CWE-639/862/863 (accessed 2026-09-15)

Secondary / internal:

- AXGuard `rules/auth.json`, `/axguard-auth`
- AwareXone Agentic-Bug-Hunter IDOR/authZ methodology (concepts only; not copied)

Datasets:

- UVID HF dataset — category linkage concepts only (MIT license metadata review 2026-09-15)
