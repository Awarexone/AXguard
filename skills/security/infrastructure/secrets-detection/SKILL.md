---
name: secrets-detection
description: Find and triage hard-coded secrets, tokens, and credentials in source and build artifacts before ship (CWE-798 / A07:2021 adjacent).
version: "1.0.0"
author: AwareXone
license: MIT
domain: infrastructure
subcategory: secrets
tags: [secrets, credentials, cwe-798]
frameworks:
  cwe: [CWE-798]
  owasp_top10: [A07:2021]
  owasp_api_top10: []
  owasp_llm_top10: []
  owasp_wstg: []
  owasp_asvs: []
  mitre_attack: []
  mitre_atlas: []
  nist_csf: []
  nist_ai_rmf: []
related_skills: [supply-chain-security, cloud-security, security-triage, security-remediation]
related_commands: [/axguard-secrets, /axguard-audit]
related_rules: [secrets.]
references:
  - https://cwe.mitre.org/data/definitions/798.html
  - https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/
last_reviewed: "2026-09-15"
---

# Secrets Detection

## Purpose

Detect credentials committed to repositories or artifacts and drive safe rotation + removal workflows.

## When to Use

- Pre-ship / PR review
- After `axguard` `secrets.*` hits
- Incident suspicion of leaked keys

## When Not to Use

- Scanning systems without authorization
- Printing full live secrets into chat/logs (always redact)

## Analysis Workflow

1. Run `axguard scan` / `audit`; collect `secrets.*`.
2. Classify: cloud keys, GitHub/Slack tokens, PEM private keys, generic API keys.
3. Decide if value is a real secret vs fixture/example (`EXAMPLE`, `changeme`, obviously fake).
4. If real: treat as incident — rotate first, then remove from git history if needed.
5. Check build artifacts and client bundles, not only server source.

## Evidence Requirements

- File:line
- Secret class (not full value)
- Whether it appears active (best-effort; do not exercise stolen creds against third parties)

## False Positive Controls

- Documented placeholders in fixtures
- Public test keys clearly marked
- `.env.example` with empty values

## Remediation

- Remove secret; rotate at provider
- Load via env / secret manager
- Add pre-commit secret scanning
- Ensure CI does not echo secrets

## Verification

Confirm file gone, rotation done, `axguard` no longer flags the live material, history cleaned if it was committed.

## Framework Mapping

- CWE-798
- OWASP A07:2021 (auth failures — credential exposure contributes)

## References

- https://cwe.mitre.org/data/definitions/798.html
- https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/

## Research Provenance

Primary: CWE-798; OWASP Top 10:2021 A07 (2026-09-15).  
Internal: AXGuard `rules/secrets.json`.
