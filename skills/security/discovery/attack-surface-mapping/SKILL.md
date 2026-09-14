---
name: attack-surface-mapping
description: Map application attack surface before deep scanning — use to inventory entry points, trust boundaries, data stores, and high-risk features that prioritize AXGuard skills and /axguard-audit.
version: "1.0.0"
author: AwareXone
license: MIT
domain: discovery
subcategory: attack-surface
tags: [attack-surface, inventory, discovery, recon]
frameworks:
  cwe: []
  owasp_top10: [A04:2021]
  owasp_api_top10: [API9:2023]
  owasp_llm_top10: []
  owasp_wstg: []
  owasp_asvs: []
  mitre_attack: []
  mitre_atlas: []
  nist_csf: []
  nist_ai_rmf: []
related_skills: [threat-modeling, security-architecture-review, api-security, security-triage]
related_commands: [/axguard-threat-model, /axguard-surface, /axguard-audit, /axguard-scan, /axguard-cso]
related_rules: []
references:
  - https://owasp.org/Top10/A04_2021-Insecure_Design/
  - https://owasp.org/API-Security/editions/2023/en/api9-improper-inventory-management/
last_reviewed: "2026-09-15"
---

# Attack Surface Mapping

## Purpose

Produce a concise **attack surface inventory** of the software under review so subsequent AXGuard skills target real entry points instead of guessing.

## When to Use / When Not to Use

**Use when:**

- First touch on a repo, large PR, or pre-ship gate.
- Before `/axguard-audit` when scope is unclear.
- Alongside `threat-modeling` for unknown systems.

**Do not use when:**

- A single known sink class is already in scope (go to that domain skill).
- Pure dependency CVE scanning without app entry mapping (supply-chain skill when available).

## Security Concepts

Attack surface = **reachable interfaces that accept trust** (HTTP, WS, queues, uploads, admin CLIs, agent tools). Shadow endpoints and forgotten versions (API9) are surface, not footnotes.

## Threat Model

Mapping itself is not a vuln. It identifies where attackers interact: anonymous vs authenticated surfaces, high-value sinks, and unmanaged inventory.

## Analysis Workflow

1. **Prefer CLI when available**: run `axguard surface <path>` (or rely on the audit `surface` phase via `axguard audit`) to get `application-model.json` / `.md` before manual inventory.
2. **Identify exposure**: web routes, GraphQL, WS, gRPC, webhooks, mobile BFF, admin panels, debug/actuators.
3. **List trust inputs**: params, headers, files, messages, env-injected dynamic config, model/tool outputs.
4. **Map identities**: anonymous, user, admin, service, CI.
5. **Note data stores & egress**: DB, object storage, email, outbound HTTP (SSRF candidates), cloud metadata.
6. **Flag high-risk features**: auth, payments, uploads, HTML render, template editors, deserializers, shell-outs, agents.
7. **Diff inventory vs docs/OpenAPI** — mark undocumented/shadow routes.
8. **Prioritize** top surfaces → assign AXGuard commands/skills (`/axguard-auth`, `ssrf-analysis`, etc.).
9. Hand off to `threat-modeling` (abuse cases) and `axguard audit` (detection).

## Evidence Requirements

Surface maps are **inventory artifacts**. Do not file CVEs from mapping alone. Record:

- Entry point list with auth expectation
- High-risk feature tags
- Recommended next skills

## False Positive Controls

- Dead code / unreachable feature flags documented as non-surface
- Internal-only listeners bound to localhost with confirmed deployment evidence
- Third-party SaaS UIs outside the owned codebase (note as dependency risk only)

## Remediation

Inventory gaps become engineering work: remove shadow APIs, document OpenAPI, disable debug surfaces, reduce anonymous reachability.

## Verification

```text
axguard surface <path> (or audit surface phase) → Confirm against routes/deploy config → Feed /axguard-audit → Update map when features change
```

## Related Skills

- `threat-modeling`, `security-architecture-review`
- `api-security`, `axguard-cso` / audit orchestration

## Framework Mapping

- OWASP A04:2021 Insecure Design
- OWASP API9:2023 Improper Inventory Management

## References

- https://owasp.org/Top10/A04_2021-Insecure_Design/
- https://owasp.org/API-Security/editions/2023/en/api9-improper-inventory-management/

## Research Provenance

Primary sources:

- OWASP Top 10:2021 A04; OWASP API9:2023 (accessed 2026-09-15)

Secondary / internal:

- AXGuard `/axguard-threat-model`, `/axguard-audit`, CSO skill
- AwareXone Agentic-Bug-Hunter recon/surface methodology (concepts only; not copied)

Datasets:

- UVID HF dataset — category linkage concepts only (MIT license metadata review 2026-09-15)
