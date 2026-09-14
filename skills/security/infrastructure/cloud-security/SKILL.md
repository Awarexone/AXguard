---
name: cloud-security
description: Review cloud and CORS misconfiguration in app code and IaC-adjacent configs — metadata URLs, public buckets, wildcard origins (CWE-918 / CWE-942 / A05:2021 / A10:2021).
version: "1.0.0"
author: AwareXone
license: MIT
domain: infrastructure
subcategory: cloud
tags: [cloud, cors, metadata, iam, cwe-918, cwe-942]
frameworks:
  cwe: [CWE-918, CWE-942, CWE-284]
  owasp_top10: [A01:2021, A05:2021, A10:2021]
  owasp_api_top10: [API8:2023]
  owasp_llm_top10: []
  owasp_wstg: []
  owasp_asvs: []
  mitre_attack: []
  mitre_atlas: []
  nist_csf: []
  nist_ai_rmf: []
related_skills: [ssrf-analysis, secrets-detection, configuration-security, supply-chain-security, security-triage]
related_commands: [/axguard-cloud, /axguard-ssrf, /axguard-audit]
related_rules: [cloud.]
references:
  - https://owasp.org/Top10/A05_2021-Security_Misconfiguration/
  - https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/
  - https://cwe.mitre.org/data/definitions/918.html
  - https://cwe.mitre.org/data/definitions/942.html
last_reviewed: "2026-09-15"
---

# Cloud Security

## Purpose

Guide pre-ship review of **cloud exposure and CORS/trust-boundary mistakes** in application code and nearby config — especially SSRF-to-metadata paths, overly open origins, and public object storage hints.

## When to Use

- Apps deployed on AWS/GCP/Azure or using object storage / serverless.
- After `axguard` hits `cloud.*` (or `ssrf.*` near metadata).
- PR review of CORS middleware, bucket ACL/policy snippets, or metadata URL references.

## When Not to Use

- Pure client-side SPA with no server egress and no cloud SDK/config in repo.
- Unauthorized probing of someone else’s cloud account or metadata service.

## Security Concepts

Cloud risk in app repos often appears as **egress to privileged link-local endpoints**, **permissive cross-origin policies**, and **world-readable storage**. Instance metadata (e.g. `169.254.169.254`) can yield temporary credentials if reachable via SSRF. Wildcard CORS (`*`) with credentials, or reflected origins without allowlists, widens browser-side data theft.

## Threat Model

Attacker goals:

1. Steal cloud credentials via metadata (often chained from SSRF).
2. Read/write objects in misconfigured buckets or queues.
3. Abuse permissive CORS to exfiltrate authenticated browser sessions.
4. Expand blast radius via overly broad IAM roles assumed by the app.

## Analysis Workflow

1. Run `axguard scan` / `audit`; collect `cloud.*` and related `ssrf.*` / `secrets.*`.
2. Search for metadata endpoints (`169.254.169.254`, `metadata.google.internal`) and confirm whether URLs are user-influenced.
3. Review CORS: `Access-Control-Allow-Origin`, `credentials`, origin reflection vs allowlist.
4. Hunt public ACL / policy markers (`public-read`, `AllUsers`, wildcard principals) in code or infra-as-code snippets present in the repo.
5. Check cloud SDKs: hard-coded keys (hand off to `secrets-detection`), overly broad default credentials assumptions.
6. Prefer IMDSv2 / provider SDK role assumption over any app-initiated metadata HTTP fetch.
7. Do **not** exercise stolen credentials or scan third-party cloud tenants.

## Evidence Requirements

- File:line for metadata URL, CORS policy, or public ACL hint
- Whether the URL/origin is attacker-influenced
- Deployment context if known (IMDSv1 vs v2, public CDN vs private API)
- Confidence: `CONFIRMED` only with clear shipped config + reachability story

## False Positive Controls

- Docs/examples with placeholder bucket names and no ship path
- CORS `*` on truly public, unauthenticated static assets without credentials
- Metadata string in comments or vendor SDK constants never called with user input
- Test fixtures that never deploy

## Remediation

- Block metadata and link-local destinations in SSRF defenses; use instance roles + IMDSv2.
- Allowlist CORS origins; never pair `*` with `Access-Control-Allow-Credentials: true`.
- Make buckets private by default; use signed URLs / IAM for access.
- Least-privilege roles for the workload; no long-lived keys in source.
- Harden related misconfig via `configuration-security`.

## Verification

Re-run `axguard audit` / `/axguard-cloud`. Confirm metadata fetches and wildcard credentialed CORS are gone. Manually review remaining cloud policy snippets for public principals.

## Related Skills

`ssrf-analysis`, `secrets-detection`, `configuration-security`, `security-triage`, `security-remediation`

## Framework Mapping

- CWE-918 (SSRF / metadata adjacency)
- CWE-942 (permissive cross-domain policy)
- CWE-284 (improper access control — broad cloud exposure)
- OWASP A01:2021 Broken Access Control
- OWASP A05:2021 Security Misconfiguration
- OWASP A10:2021 SSRF
- OWASP API8:2023 Security Misconfiguration

## References

- https://owasp.org/Top10/A05_2021-Security_Misconfiguration/
- https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/
- https://owasp.org/Top10/A01_2021-Broken_Access_Control/
- https://cwe.mitre.org/data/definitions/918.html
- https://cwe.mitre.org/data/definitions/942.html
- https://cwe.mitre.org/data/definitions/284.html

## Research Provenance

Primary: OWASP Top 10:2021 A01/A05/A10; CWE-918/942/284; OWASP API Security Top 10:2023 API8 (2026-09-15).  
Internal: AXGuard `rules/cloud.json`, `/axguard-cloud`.  
Secondary: methodology concepts from OWASP CheatSheetSeries / WSTG (no verbatim dump).
