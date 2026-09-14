---
name: threat-modeling
description: Lightweight threat modeling for an application before deep scanning — map assets, trust boundaries, and abuse cases; feeds /axguard-audit.
version: "1.0.0"
author: AwareXone
license: MIT
domain: discovery
subcategory: threat-modeling
tags: [threat-model, stride, design-review]
frameworks:
  cwe: []
  owasp_top10: [A04:2021]
  owasp_api_top10: []
  owasp_llm_top10: []
  owasp_wstg: []
  owasp_asvs: []
  mitre_attack: []
  mitre_atlas: []
  nist_csf: []
  nist_ai_rmf: []
related_skills: [attack-surface-mapping, security-architecture-review, security-triage]
related_commands: [/axguard-threat-model, /axguard-audit, /axguard-cso]
related_rules: []
references:
  - https://owasp.org/Top10/A04_2021-Insecure_Design/
last_reviewed: "2026-09-15"
---

# Threat Modeling

## Purpose

Produce a short, actionable threat model that guides which AXGuard skills and scans to run next.

## When to Use

- New codebase / first audit
- Major feature (auth, payments, agents, file import)
- Before `/axguard-audit` on unfamiliar systems

## When Not to Use

- Single-line bugfix with known sink (go straight to the class skill)

## Analysis Workflow

1. **Assets**: data, secrets, admin, money movement, model tools.
2. **Actors**: anonymous, user, admin, attacker, malicious model/tool output.
3. **Trust boundaries**: browser↔API, API↔DB, API↔cloud, agent↔tools, CI↔prod.
4. **STRIDE-lite** per boundary (spoof, tamper, repudiate, info disclosure, DoS, elevation) — keep to realistic top abuses.
5. Rank top 5 abuse cases.
6. Map each to an AXGuard command/skill (`/axguard-auth`, `ssrf-analysis`, etc.).
7. Hand off to `axguard audit` + focused skills.

## Evidence Requirements

Threat models are **design artifacts**, not vulns. Do not report a CVE from modeling alone.

## Remediation

Insecure design findings become backlog controls (authZ checks, allowlists, least privilege) tracked into remediation skills.

## Related Skills

`attack-surface-mapping`, `security-architecture-review`, `axguard-cso`

## Framework Mapping

- OWASP A04:2021 Insecure Design

## References

- https://owasp.org/Top10/A04_2021-Insecure_Design/

## Research Provenance

Primary: OWASP Top 10:2021 A04 (2026-09-15).  
Internal: AXGuard `/axguard-threat-model` command + CSO skill.
