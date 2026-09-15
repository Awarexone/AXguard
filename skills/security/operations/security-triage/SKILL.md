---
name: security-triage
description: Domain reasoning for triaging AXguard findings — keep/drop gates, confidence, and severity promotion before remediation.
version: "1.0.0"
author: AwareXone
license: MIT
domain: operations
subcategory: triage
tags: [triage, false-positives, confidence, severity]
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
related_skills: [security-remediation, axguard-triage, axguard-audit, axguard-cso]
related_commands: [/axguard-triage, /axguard-audit, /axguard-report]
related_rules: []
references:
  - https://owasp.org/Top10/
last_reviewed: "2026-09-15"
---

# Security Triage

## Purpose

Encode **keep / drop / needs-manual** decision-making over scanner output so only evidence-backed issues proceed to fix or report. Complements orchestration skill `axguard-triage` / `/axguard-triage`.

## When to Use

- After `axguard audit` / `scan` when finding volume is high
- Before `/axguard-fix` or customer-facing reports
- When severity looks inflated or understated relative to code evidence

## When Not to Use

- As a substitute for reading the sink (do not mass-drop without per-finding review)
- To suppress confirmed critical issues for convenience

## Security Concepts

Confidence model: `CONFIRMED` | `HIGH` | `MEDIUM` | `LOW` | `INFORMATIONAL`. Never jump hypothesis → `CONFIRMED` without source→sink→missing-control evidence. Triage optimizes **signal**, not emptiness.

## Threat Model

Failure modes of bad triage:

1. False confidence → ship with RCE/auth/secret bugs.
2. Alert fatigue → real issues ignored.
3. Severity theater → critical without reachability.

## Analysis Workflow

1. Prefer existing `.findings/axguard/axguard-report.json`; else run `axguard audit .`.
2. Sort critical → low; process in order.
3. Apply the gate (all must pass to **Keep**):
   - Real sink in shipped code (not test-only unless tests ship/deploy).
   - Reachability: attacker-influenced data can reach it, or a required control is clearly absent.
   - Impact beyond style / theoretical purity.
   - Actionable fix path for an engineer.
4. Fail any → **Drop** with one-line reason. Uncertain reachability → `needs-manual`, do not promote to critical.
5. Severity actions: **Promote** (clear RCE/auth bypass/prod secret), **Hold**, **Demote** (admin-only / partial mitigator), **Drop**.
6. Use class-specific FP notes from `axguard-triage` (SQL bind vars, allowlisted SSRF, DEBUG in examples, etc.).
7. Hand **Keep** list to `security-remediation` / `axguard-remediate` (`/axguard-fix`) or `/axguard-report`.

## Evidence Requirements

| Field | Content |
|---|---|
| Decision | Keep / Drop / needs-manual |
| ID | Rule or finding id |
| Severity | Final severity |
| Location | file:line |
| Reason | One line |
| Confidence | Per model above |

## False Positive Controls

Treat as drop candidates when:

- Fixture / `.env.example` / docs-only
- Fully parameterized or allowlisted path proven on the same data flow
- Dead code eliminated from all ship artifacts
- Duplicate of an already-kept root cause

## Remediation

Triage does not patch. Output a confirmed queue; invoke `security-remediation` next. If triage reveals systemic noise, open rule-tuning notes — do not silently delete signal.

## Verification

Spot-check a sample of Drops for mistaken dismissal. Ensure every Keep has a path to fix ownership. Re-count blockers (Keep ≥ high on auth/RCE/secret).

## Related Skills

Orchestration: `axguard-triage`, `axguard-remediate`, `axguard-cso`, `axguard-report`.  
Domain: per-class skills (`sql-injection`, `ssrf-analysis`, `secrets-detection`, …) for evidence standards.

## Framework Mapping

Operational skill — no primary CWE/OWASP entry. Findings retain the framework IDs of their vuln class.

## References

- AXGuard `skills/axguard-triage/SKILL.md`
- https://owasp.org/Top10/ (severity context only)

## Research Provenance

Primary: AXGuard triage orchestration skill and audit pipeline (2026-09-15).  
Secondary: AwareXone Agentic-Bug-Hunter methodology concepts for keep/drop discipline (MIT; no report dumps).  
Framework IDs deferred to domain skills.
