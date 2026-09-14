---
name: api-security
description: Analyze REST/RPC/API security design — use for BOLA/BFLA, mass assignment, auth on endpoints, rate limits, inventory gaps, and unsafe outbound API consumption (OWASP API Top 10 2023).
version: "1.0.0"
author: AwareXone
license: MIT
domain: application-security
subcategory: api-security
tags: [api, bola, bfla, mass-assignment, rest]
frameworks:
  cwe: [CWE-639, CWE-862, CWE-863, CWE-915]
  owasp_top10: [A01:2021, A04:2021]
  owasp_api_top10: [API1:2023, API2:2023, API3:2023, API4:2023, API5:2023, API6:2023, API7:2023, API8:2023, API9:2023, API10:2023]
  owasp_llm_top10: []
  owasp_wstg: []
  owasp_asvs: []
  mitre_attack: []
  mitre_atlas: []
  nist_csf: []
  nist_ai_rmf: []
related_skills: [authorization-analysis, authentication-analysis, graphql-security, ssrf-analysis, security-triage, security-remediation]
related_commands: [/axguard-auth, /axguard-audit, /axguard-ssrf, /axguard-scan]
related_rules: [auth., ssrf., injection.]
references:
  - https://owasp.org/API-Security/editions/2023/en/0x11-t10/
  - https://owasp.org/Top10/A01_2021-Broken_Access_Control/
  - https://cwe.mitre.org/data/definitions/639.html
  - https://cwe.mitre.org/data/definitions/915.html
last_reviewed: "2026-09-15"
---

# API Security

## Purpose

Provide a practitioner checklist for **HTTP API** pre-ship review aligned to OWASP API Security Top 10:2023 — object/function authZ, property controls, consumption limits, inventory, and SSRF/outbound trust.

## When to Use / When Not to Use

**Use when:**

- REST/JSON-RPC/gRPC-gateway APIs expose object IDs, admin functions, or bulk operations.
- Reviewing mass assignment / DTO binding, pagination limits, or webhook callbacks.
- Building the authZ portion of `/axguard-audit` for API-heavy apps.

**Do not use when:**

- Issue is purely browser DOM XSS with no API shape concerns (`xss-analysis`).
- Narrow single-class sink already identified (go straight to `sql-injection`, `ssrf-analysis`, etc.).

## Security Concepts

APIs fail when **identity ≠ authorization**. Object IDs in paths/bodies require ownership checks (BOLA). Property-level expose/bind risks hide in serializers. Resource limits and business-flow abuse are first-class API risks, not afterthoughts.

## Threat Model

Attacker goals:

1. Access/modify other users’ objects (API1).
2. Call admin/privileged functions (API5).
3. Overwrite `role`/`price` via mass assignment (API3).
4. Exhaust resources or abuse purchase/invite flows (API4/API6).
5. Pivot via SSRF or trust unsafe third-party API responses (API7/API10).

## Analysis Workflow

1. Inventory endpoints (OpenAPI/routes) vs deployed reality (API9).
2. For each object-ID parameter: confirm authN + ownership/tenant checks (API1).
3. For privileged operations: confirm role/function checks independent of UI hiding (API5).
4. Review serializers/DTO bind allowlists — reject unexpected properties (API3 / CWE-915).
5. Check auth mechanisms for token quality, credential stuffing resistance (API2) — hand deep JWT/OAuth to those skills.
6. Confirm rate limits, payload size, pagination caps (API4); sensitive flow step-up/abuse controls (API6).
7. Review outbound URL fetches (API7 → `ssrf-analysis`) and parsing of third-party responses (API10).
8. Flag verbose errors, permissive CORS, default keys (API8).

## Evidence Requirements

- Route/handler location
- Missing control mapped to a specific API Top 10 category
- Object/property/function affected
- Confidence based on code proof, not scanner alone

## False Positive Controls

- Endpoints that are public by design with no sensitive data
- IDs that are capability tokens (unpredictable, unguessable) **and** still authZ-checked
- Admin-only networks with strong edge auth (document residual risk; do not auto-close)

## Remediation

1. Centralize authZ helpers; test BOLA/BFLA with two-user fixtures.
2. Explicit response/request DTOs; no blind `**kwargs` / mass assign.
3. Rate-limit and quota by user/IP/token; harden expensive endpoints.
4. Maintain accurate API inventory; disable shadow/old versions.
5. Harden CORS, errors, and secrets; validate outbound destinations and third-party payloads.

## Verification

```text
Inventory APIs → AuthZ + DTO + limits review → Re-run axguard → Add two-user ownership tests
```

## Related Skills

- `authorization-analysis`, `authentication-analysis`, `jwt-security`, `oauth-security`
- `graphql-security`, `ssrf-analysis`
- `security-triage`, `security-remediation`

## Framework Mapping

- CWE-639, CWE-862, CWE-863, CWE-915
- OWASP A01:2021, A04:2021
- OWASP API1:2023 through API10:2023

## References

- https://owasp.org/API-Security/editions/2023/en/0x11-t10/
- https://owasp.org/Top10/A01_2021-Broken_Access_Control/
- https://cwe.mitre.org/data/definitions/639.html
- https://cwe.mitre.org/data/definitions/915.html

## Research Provenance

Primary sources:

- OWASP API Security Top 10:2023; OWASP A01/A04:2021; CWE-639/915/862/863 (accessed 2026-09-15)

Secondary / internal:

- AXGuard `rules/auth.json`, `/axguard-auth`, `/axguard-audit`
- AwareXone Agentic-Bug-Hunter API methodology (concepts only; not copied)

Datasets:

- UVID HF dataset — category linkage concepts only (MIT license metadata review 2026-09-15)
