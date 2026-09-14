---
name: graphql-security
description: Analyze GraphQL API security — use when reviewing schemas, resolvers, introspection, batching, authorization per field, or CSRF on cookie-authenticated GraphQL endpoints (API1/API5/API8:2023).
version: "1.0.0"
author: AwareXone
license: MIT
domain: application-security
subcategory: api-security
tags: [graphql, introspection, resolvers, api-security]
frameworks:
  cwe: [CWE-862, CWE-863, CWE-639]
  owasp_top10: [A01:2021]
  owasp_api_top10: [API1:2023, API5:2023, API8:2023]
  owasp_llm_top10: []
  owasp_wstg: []
  owasp_asvs: []
  mitre_attack: []
  mitre_atlas: []
  nist_csf: []
  nist_ai_rmf: []
related_skills: [api-security, authorization-analysis, authentication-analysis, xss-analysis, security-triage, security-remediation]
related_commands: [/axguard-graphql, /axguard-auth, /axguard-audit]
related_rules: [graphql., auth.]
references:
  - https://owasp.org/API-Security/editions/2023/en/api1-broken-object-level-authorization/
  - https://owasp.org/API-Security/editions/2023/en/api5-broken-function-level-authorization/
  - https://owasp.org/API-Security/editions/2023/en/api8-security-misconfiguration/
  - https://owasp.org/Top10/A01_2021-Broken_Access_Control/
last_reviewed: "2026-09-15"
---

# GraphQL Security

## Purpose

Teach pre-ship analysis of **GraphQL** deployments: schema exposure, resolver-level authorization, expensive queries, mutations CSRF, and injection into resolvers.

## When to Use / When Not to Use

**Use when:**

- Apollo/Yoga/Graphene/Hasura/AppSync schemas and resolvers are in scope.
- After AXguard hits `graphql.*`.
- Single `/graphql` endpoint aggregates many privileged operations.

**Do not use when:**

- No GraphQL layer (use `api-security` for REST/RPC).
- Pure schema design docs without runtime resolvers.

## Security Concepts

GraphQL concentrates attack surface into one URL. **AuthZ must run in resolvers/data loaders per object**, not only at the HTTP gateway. Introspection, batching, and nested queries change enumeration and DoS risk.

## Threat Model

Attacker goals:

1. IDOR via `node(id:)` / object queries without ownership checks (API1).
2. Call admin mutations as a low-privilege user (API5).
3. Abuse introspection and field suggestions for inventory.
4. CSRF mutations on cookie-based sessions; DoS via deeply nested/batched queries.

## Analysis Workflow

1. Inventory GraphQL endpoints, schemas, and auth mode (JWT header vs cookies).
2. Check introspection/playground exposure in production.
3. For each sensitive field/mutation: verify resolver authN + object-level authZ.
4. Review `node`/global ID patterns for BOLA.
5. Check CSRF defenses if cookies are used (SameSite, custom headers, Apollo CSRF prevention).
6. Assess query cost limiting, depth/amount limits, timeouts, persisted queries.
7. Trace resolver inputs into SQL/command/SSRF sinks (hand off to those skills).

## Evidence Requirements

- Schema/resolver location for the sensitive operation
- Missing authZ or misconfiguration evidence
- Auth mode (cookie vs bearer) for CSRF conclusions
- Impact on objects/functions reachable

## False Positive Controls

- Introspection disabled in prod with alternate safe docs
- Persisted queries only + strict allowlist
- Gateway + resolver checks both present and tested
- Public schema fields that are intentionally unauthenticated

## Remediation

1. Disable introspection and risky IDE tooling in production.
2. Enforce authZ in every resolver/loader returning sensitive objects.
3. Limit depth/complexity; prefer persisted queries; rate-limit.
4. For cookie auth: require CSRF-safe mutation posture.
5. Least-privilege schema — split admin graphs when feasible.

## Verification

```text
Map schema → Verify per-resolver authZ + limits → Re-run axguard → Confirm introspection/CSRF settings for environment
```

## Related Skills

- `api-security`, `authorization-analysis`, `authentication-analysis`
- `xss-analysis` — if GraphQL feeds HTML clients
- `security-triage`, `security-remediation`

## Framework Mapping

- CWE-862, CWE-863, CWE-639
- OWASP A01:2021 Broken Access Control
- OWASP API1:2023, API5:2023, API8:2023

## References

- https://owasp.org/API-Security/editions/2023/en/api1-broken-object-level-authorization/
- https://owasp.org/API-Security/editions/2023/en/api5-broken-function-level-authorization/
- https://owasp.org/API-Security/editions/2023/en/api8-security-misconfiguration/
- https://owasp.org/Top10/A01_2021-Broken_Access_Control/

## Research Provenance

Primary sources:

- OWASP API Security Top 10:2023 (API1, API5, API8); OWASP A01:2021; CWE-862/863/639 (accessed 2026-09-15)

Secondary / internal:

- AXGuard `rules/graphql.json`, `/axguard-graphql`
- AwareXone Agentic-Bug-Hunter GraphQL methodology (concepts only; not copied)

Datasets:

- UVID HF dataset — category linkage concepts only (MIT license metadata review 2026-09-15)
