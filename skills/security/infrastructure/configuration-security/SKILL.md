---
name: configuration-security
description: Find security misconfiguration before ship — debug flags, verbose errors, exposed actuators/admin, weak defaults (CWE-489 / CWE-209 / A05:2021).
version: "1.0.0"
author: AwareXone
license: MIT
domain: infrastructure
subcategory: configuration
tags: [misconfiguration, debug, defaults, cwe-489, cwe-209]
frameworks:
  cwe: [CWE-489, CWE-209]
  owasp_top10: [A05:2021, A09:2021]
  owasp_api_top10: [API8:2023]
  owasp_llm_top10: []
  owasp_wstg: []
  owasp_asvs: []
  mitre_attack: []
  mitre_atlas: []
  nist_csf: []
  nist_ai_rmf: []
related_skills: [cloud-security, secrets-detection, supply-chain-security, security-triage, security-remediation]
related_commands: [/axguard-debug, /axguard-cloud, /axguard-audit]
related_rules: [debug., cloud., crypto.]
references:
  - https://owasp.org/Top10/A05_2021-Security_Misconfiguration/
  - https://cwe.mitre.org/data/definitions/489.html
  - https://cwe.mitre.org/data/definitions/209.html
last_reviewed: "2026-09-15"
---

# Configuration Security

## Purpose

Detect **insecure defaults and runtime misconfiguration** that ship with the product: debug modes, stack traces to clients, open management endpoints, and related hard-coded crypto/CORS footguns adjacent to config.

## When to Use

- Pre-ship / production config review
- After `axguard` hits `debug.*`, suspicious `cloud.*`, or `crypto.*` defaults
- Framework apps (Django/Flask/Express/Spring) where DEBUG or actuators may leak

## When Not to Use

- Local-only developer settings clearly gated and never referenced by prod deploy paths
- Penetration of live systems without authorization

## Security Concepts

A05:2021 covers incomplete hardening: unnecessary features on, default accounts, verbose errors, missing security headers, and misconfigured permissions. Active debug code (CWE-489) and sensitive error messages (CWE-209) turn configuration mistakes into reconnaissance or RCE (e.g. interactive debuggers).

## Threat Model

Attacker goals:

1. Harvest stack traces, env hints, or heap dumps from verbose errors / actuators.
2. Abuse debug/reloader features for code execution.
3. Bypass weak TLS/crypto defaults or trust-all certificate settings.
4. Combine with CORS/cloud misconfig for broader access.

## Analysis Workflow

1. Run `axguard scan` / `audit`; collect `debug.*`, review related `cloud.*` / `crypto.*`.
2. Confirm each hit is on a **shipped** path (Dockerfile, prod compose, CI deploy config, main settings module) — not only `.env.example`.
3. Check framework debug: `DEBUG=True`, `app.run(debug=True)`, Express error handlers sending `err.stack`.
4. Check management surfaces: Spring Actuator `exposure.include=*`, unauthenticated admin/metrics.
5. Review security-relevant defaults: permissive CORS (→ `cloud-security`), `verify=False`, hardcoded IVs/keys (→ `secrets-detection` / crypto rules).
6. Prefer environment-forced safe defaults (`DEBUG=False` in prod) over hope that operators remember.

## Evidence Requirements

- File:line of unsafe setting
- Whether prod/staging deploy uses that file
- Leak class (stack, env, debugger, open admin)
- Confidence gated on deploy reachability

## False Positive Controls

- `.env.example` / sample compose with `DEBUG=true` and documented local-only use
- Error handlers that log stacks server-side and return generic client bodies
- Actuator limited to `health`/`info` behind auth and network policy
- Test settings modules excluded from production images

## Remediation

- Force safe prod config via env / secrets manager; fail closed if unset.
- Disable interactive debuggers and template auto-reload in production.
- Return generic errors to clients; keep detail in server logs (with redaction).
- Minimize exposed management endpoints; authenticate and network-restrict the rest.
- Align CORS and cloud ACL hardening with `cloud-security`.

## Verification

Re-run `axguard audit` focusing on `debug.*`. Confirm production config paths cannot enable debug. Spot-check that client error responses omit stacks and secrets.

## Related Skills

`cloud-security`, `secrets-detection`, `security-triage`, `security-remediation`, `axguard-triage` (orchestration)

## Framework Mapping

- CWE-489 Active Debug Code
- CWE-209 Generation of Error Message Containing Sensitive Information
- OWASP A05:2021 Security Misconfiguration
- OWASP A09:2021 Security Logging and Monitoring Failures (adjacent when errors/logging are mishandled)
- OWASP API8:2023 Security Misconfiguration

## References

- https://owasp.org/Top10/A05_2021-Security_Misconfiguration/
- https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/
- https://cwe.mitre.org/data/definitions/489.html
- https://cwe.mitre.org/data/definitions/209.html
- https://owasp.org/API-Security/editions/2023/en/0xa8-security-misconfiguration/

## Research Provenance

Primary: OWASP Top 10:2021 A05/A09; CWE-489/209; OWASP API8:2023 (2026-09-15).  
Internal: AXGuard `rules/debug.json`, `rules/cloud.json`, `rules/crypto.json`.
