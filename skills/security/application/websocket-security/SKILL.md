---
name: websocket-security
description: Analyze WebSocket security posture — use when reviewing WS/WSS upgrade auth, origin checks, message authorization, or cross-site WebSocket hijacking risks (CWE-346 / CWE-352 / A01:2021).
version: "1.0.0"
author: AwareXone
license: MIT
domain: application-security
subcategory: web-security
tags: [websocket, origin, csrf, cwe-346]
frameworks:
  cwe: [CWE-346, CWE-352]
  owasp_top10: [A01:2021, A07:2021]
  owasp_api_top10: [API2:2023, API5:2023]
  owasp_llm_top10: []
  owasp_wstg: []
  owasp_asvs: []
  mitre_attack: []
  mitre_atlas: []
  nist_csf: []
  nist_ai_rmf: []
related_skills: [api-security, authentication-analysis, authorization-analysis, session-security, security-triage, security-remediation]
related_commands: [/axguard-auth, /axguard-audit, /axguard-scan]
related_rules: [auth.]
references:
  - https://owasp.org/Top10/A01_2021-Broken_Access_Control/
  - https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/
  - https://cwe.mitre.org/data/definitions/346.html
  - https://cwe.mitre.org/data/definitions/352.html
last_reviewed: "2026-09-15"
---

# WebSocket Security

## Purpose

Guide defensive review of **WebSocket** endpoints: authentication at upgrade time, origin validation, per-message authorization, and abuse of long-lived channels.

## When to Use / When Not to Use

**Use when:**

- Apps use `ws`/`wss`, Socket.IO, Action Cable, Spring STOMP, or browser `WebSocket` to privileged backends.
- Cookie sessions authenticate the upgrade (cross-site WebSocket hijacking risk).
- Real-time features push sensitive events or accept commands over WS.

**Do not use when:**

- Pure unidirectional server-sent events/HTTP without WS.
- Public read-only broadcast with no sensitive data and no command channel (still note DoS).

## Security Concepts

The HTTP upgrade is the auth gate. Browsers send cookies on cross-site WS; **Origin** must be validated server-side. Authorization is not “once at connect” for every later message if topics/commands vary.

## Threat Model

Attacker goals:

1. Cross-site hijack of victim WS sessions to read/act.
2. Subscribe to other users’ channels (BOLA over topics).
3. Inject malicious messages causing XSS in listeners or server-side command execution.
4. Resource exhaustion via connection floods / huge messages.

## Analysis Workflow

1. Locate upgrade handlers and auth checks (token query vs header vs cookie).
2. Verify Origin/Host allowlists — reject missing/unexpected Origin for cookie-auth sockets.
3. Prefer explicit tokens over cookie-only WS when cross-site risk is high.
4. Map message types/topics; require authZ per subscribe/publish/action.
5. Validate and size-limit message payloads; avoid `eval` of message bodies.
6. Enforce TLS (`wss`) in production; avoid sensitive data on `ws://`.
7. Rate-limit connections and messages; idle timeouts.

## Evidence Requirements

- Upgrade handler location and auth mechanism
- Missing Origin check or missing per-message authZ
- Sensitive event/command capability
- Impact (hijack / IDOR / injection / DoS)

## False Positive Controls

- Token in protocol that is not auto-sent cross-site + Origin still checked
- No cookie auth and no sensitive commands
- Same-site-only deployments with hardened Origin allowlist and tests

## Remediation

1. Authenticate upgrade; re-authorize sensitive messages.
2. Allowlist Origins; fail closed.
3. Use `wss`, short-lived tokens, and avoid putting long-lived secrets in query strings (logs).
4. Apply standard input validation to message payloads.
5. Connection/message quotas and max payload sizes.

## Verification

```text
Review upgrade+message auth → Fix Origin/authZ → Re-test authorized clients only → Confirm cross-site connect fails closed
```

## Related Skills

- `session-security`, `authentication-analysis`, `authorization-analysis`
- `api-security`, `security-triage`, `security-remediation`

## Framework Mapping

- CWE-346 Origin Validation Error; CWE-352 CSRF
- OWASP A01:2021, A07:2021
- OWASP API2:2023, API5:2023

## References

- https://owasp.org/Top10/A01_2021-Broken_Access_Control/
- https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/
- https://cwe.mitre.org/data/definitions/346.html
- https://cwe.mitre.org/data/definitions/352.html

## Research Provenance

Primary sources:

- OWASP A01/A07:2021; CWE-346; CWE-352; OWASP API2/API5:2023 (accessed 2026-09-15)

Secondary / internal:

- AXGuard `rules/auth.json` adjacency; `/axguard-auth`
- AwareXone Agentic-Bug-Hunter WebSocket methodology (concepts only; not copied)

Datasets:

- UVID HF dataset — category linkage concepts only (MIT license metadata review 2026-09-15)
