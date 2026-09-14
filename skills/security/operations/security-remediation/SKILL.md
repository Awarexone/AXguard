---
name: security-remediation
description: Apply minimal defensive patches for confirmed findings and verify with re-audit — post-triage only.
version: "1.0.0"
author: AwareXone
license: MIT
domain: operations
subcategory: remediation
tags: [remediation, patch, verification, re-audit]
frameworks:
  cwe: []
  owasp_top10: []
  owasp_api_top10: []
  owasp_llm_top10: []
  owasp_wstg: []
  owasp_asvs: []
  mitre_attack: []
  mitre_atlas: []
  nist_csf: []
  nist_ai_rmf: []
related_skills: [security-triage, axguard-remediate, axguard-triage, axguard-audit]
related_commands: [/axguard-fix, /axguard-triage, /axguard-audit, /axguard-report]
related_rules: []
references:
  - https://owasp.org/www-project-cheat-sheets/
last_reviewed: "2026-09-15"
---

# Security Remediation

## Purpose

Drive **confirmed-finding fixes**: minimal diffs, critical first, then prove the issue is gone via re-scan and targeted review. Complements orchestration skill `axguard-remediate` / `/axguard-fix`.

## When to Use

- After `/axguard-triage` (or equivalent) produced a Keep list
- When the user asks to patch AXguard-confirmed bugs
- Hotfix for secrets, RCE sinks, auth bypass

## When Not to Use

- Fixing untriaged scanner noise (triage first)
- Adding exploit PoCs “to demonstrate” the bug
- Broad refactors unrelated to the confirmed sink

## Security Concepts

Remediation closes the **missing control** on a validated source→sink path: parameterize, authorize, allowlist, remove secret, disable debug, constrain agent tools. Prefer the smallest change that removes exploitability without inventing new surfaces.

## Threat Model

Bad remediation risks:

1. Cosmetic fixes that leave the sink reachable.
2. New bugs from rushed patches (e.g. broken auth checks).
3. Secret “removed” from file but not rotated / still in git history.

## Analysis Workflow

1. Input: Keep list from `security-triage` / `axguard-triage` with locations and confidence.
2. Order: critical → high → medium; secrets and RCE first.
3. For each item, open the domain skill (e.g. `sql-injection`, `secrets-detection`, `ai-agent-security`) and apply its Remediation guidance.
4. Patch minimally: bind parameters, add authZ, allowlist hosts, load secrets from a manager, remove `shell=True`, pin deps, etc.
5. For secrets: **rotate at provider first**, then remove from tree/history as needed; never paste live secrets into chat.
6. Add or adjust tests that treat malicious strings as **data**, not as instructions to exploit third parties.
7. Re-run `axguard audit` / relevant `/axguard-*` command; record delta (fixed / remaining / new).
8. Hand residual issues back to triage or `/axguard-report`.

## Evidence Requirements

- Finding ID + pre-fix evidence pointer
- Patch locations (files)
- Post-fix scan result
- For secrets: rotation confirmation (without secret values)

## False Positive Controls

Do not “fix” by:

- Deleting the rule or blanketing `# nosec` without justifying safety
- Moving vulnerable code to an unscanned path
- Marking resolved while the sink remains

## Remediation

Pattern catalog (defensive):

| Class | Prefer |
|---|---|
| SQLi | Bound parameters; allowlist identifiers |
| SSRF | Allowlist hosts; block link-local/metadata |
| Secrets | Rotate + env/secret manager |
| XSS | Context-aware encoding / safe APIs |
| Agent/MCP | Typed tools; no exec of model text |
| Supply | Pin + verify; drop curl\|sh |
| Debug | Force safe prod defaults |

## Verification

1. `axguard audit` clean for that rule id (or explained residual).
2. Manual confirmation the data flow no longer reaches an unsafe sink.
3. Regression tests green.
4. Update report with fixed vs open counts.

## Related Skills

Orchestration: `axguard-remediate`, `axguard-triage`, `axguard-audit`, `axguard-report`.  
Domain skills supply per-class fix patterns.

## Framework Mapping

Operational skill — inherit CWE/OWASP IDs from the finding’s domain skill when reporting.

## References

- AXGuard `skills/axguard-remediate/SKILL.md`
- https://owasp.org/www-project-cheat-sheets/ (methodology; no large verbatim copies)
- Domain skill Remediation sections in `skills/security/`

## Research Provenance

Primary: AXGuard remediate/fix orchestration and domain skill remediations (2026-09-15).  
Secondary: OWASP CheatSheetSeries methodology themes (CC-BY-SA-4.0; no sheet dumps).  
No exploit procedures included.
