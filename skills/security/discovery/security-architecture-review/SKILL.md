---
name: security-architecture-review
description: Review security architecture and trust boundaries — use for design-level control gaps across authZ, secrets, egress, multi-tenant isolation, and insecure-by-design features (A04:2021) before or with /axguard-audit.
version: "1.0.0"
author: AwareXone
license: MIT
domain: discovery
subcategory: architecture
tags: [architecture, trust-boundaries, insecure-design, defense-in-depth]
frameworks:
  cwe: []
  owasp_top10: [A04:2021, A01:2021]
  owasp_api_top10: [API8:2023, API9:2023]
  owasp_llm_top10: []
  owasp_wstg: []
  owasp_asvs: []
  mitre_attack: []
  mitre_atlas: []
  nist_csf: []
  nist_ai_rmf: []
related_skills: [threat-modeling, attack-surface-mapping, api-security, authentication-analysis, authorization-analysis, security-triage]
related_commands: [/axguard-threat-model, /axguard-cso, /axguard-audit, /axguard-cloud]
related_rules: []
references:
  - https://owasp.org/Top10/A04_2021-Insecure_Design/
  - https://owasp.org/Top10/A01_2021-Broken_Access_Control/
  - https://owasp.org/API-Security/editions/2023/en/api8-security-misconfiguration/
  - https://owasp.org/API-Security/editions/2023/en/api9-improper-inventory-management/
last_reviewed: "2026-09-15"
---

# Security Architecture Review

## Purpose

Perform a **design-level security architecture review**: whether trust boundaries, control placement, and isolation strategies are fit for the app’s risk — catching insecure design before (or while) hunting implementation bugs.

## When to Use / When Not to Use

**Use when:**

- New product, major rewrite, multi-tenant SaaS, payments, agents with tools, or significant cloud redesign.
- CSO/`/axguard-cso` lead pass needs architecture context.
- Threat model shows systemic issues (no authZ layer, shared DB without tenants, secrets in clients).

**Do not use when:**

- Single-line sink fix with clear local remediation.
- Pure secret scanning without design questions (`secrets-detection`).

## Security Concepts

Insecure design (A04) is missing or misplaced **controls**, not just missing patches. Good architecture places authN/authZ, validation, secrets, and egress policy at boundaries — with defense in depth, not a single UI check.

## Threat Model

Architecture review asks:

1. What happens if one component is compromised?
2. Can tenants/users cross isolation barriers by design?
3. Are privileged operations reachable with weak step-up?
4. Do agents/tools inherit over-broad credentials?

## Analysis Workflow

1. Draw trust boundaries: client, edge, app, data, jobs, IdP, cloud APIs, agent tools.
2. For each boundary: authN method, authZ enforcement point, encryption in transit/at rest expectations.
3. Check **tenant isolation** model (row-level, schema, DB-per-tenant) and failure modes.
4. Review secrets: where created, stored, injected; client exposure; rotation.
5. Review egress: SSRF-prone features, metadata exposure, third-party token relay.
6. Review admin/break-glass paths and debug surfaces in production designs.
7. For AI agents: tool allowlists, human approval, credential scoping.
8. Output architecture risks as design findings + which implementation skills to run next.

## Evidence Requirements

Architecture findings need:

- Diagram or clear boundary description
- Missing/misplaced control (not just “could be better”)
- Realistic abuse case
- Recommended control — confidence usually MEDIUM until implementation proof

Do not claim RCE from architecture alone.

## False Positive Controls

- Compensating controls proven in code/deploy (WAF alone is not sufficient authZ)
- Risks accepted explicitly with documented owners/expiry
- Aspirational hardening outside current scope — track as backlog, not critical vuln

## Remediation

1. Move authZ to a consistent server-side policy layer.
2. Enforce tenant isolation in data access APIs.
3. Introduce secret management, short-lived creds, least privilege IAM.
4. Constrain egress and metadata hops; segment admin planes.
5. Reduce agent/tool blast radius; separate duties.

## Verification

```text
Architecture notes → Control backlog → Implementation skills + axguard audit → Re-review boundaries after major changes
```

## Related Skills

- `threat-modeling`, `attack-surface-mapping`
- `api-security`, `authentication-analysis`, `authorization-analysis`
- `ssrf-analysis`, cloud/secrets skills as applicable

## Framework Mapping

- OWASP A04:2021 Insecure Design; A01:2021 Broken Access Control
- OWASP API8:2023 Security Misconfiguration; API9:2023 Improper Inventory Management

## References

- https://owasp.org/Top10/A04_2021-Insecure_Design/
- https://owasp.org/Top10/A01_2021-Broken_Access_Control/
- https://owasp.org/API-Security/editions/2023/en/api8-security-misconfiguration/
- https://owasp.org/API-Security/editions/2023/en/api9-improper-inventory-management/

## Research Provenance

Primary sources:

- OWASP Top 10:2021 A04/A01; OWASP API8/API9:2023 (accessed 2026-09-15)

Secondary / internal:

- AXGuard `/axguard-threat-model`, `/axguard-cso`, `/axguard-audit`
- AwareXone Agentic-Bug-Hunter architecture review methodology (concepts only; not copied)

Datasets:

- UVID HF dataset — category linkage concepts only (MIT license metadata review 2026-09-15)
