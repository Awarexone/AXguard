---
name: ssrf-analysis
description: Analyze and validate server-side request forgery in application code — use when reviewing outbound HTTP/fetch sinks, user-controlled URLs, webhook callbacks, previewers, or cloud metadata exposure (CWE-918 / A10:2021).
version: "1.0.0"
author: AwareXone
license: MIT
domain: application-security
subcategory: web-security
tags: [ssrf, egress, cloud-metadata, cwe-918]
frameworks:
  cwe: [CWE-918]
  owasp_top10: [A10:2021]
  owasp_api_top10: []
  owasp_llm_top10: []
  owasp_wstg: []
  owasp_asvs: []
  mitre_attack: []
  mitre_atlas: []
  nist_csf: []
  nist_ai_rmf: []
related_skills: [api-security, cloud-security, secrets-detection, security-triage, security-remediation]
related_commands: [/axguard-ssrf, /axguard-cloud, /axguard-audit, /axguard-flow]
related_rules: [ssrf., cloud.aws-metadata]
references:
  - https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/
  - https://cwe.mitre.org/data/definitions/918.html
last_reviewed: "2026-09-15"
---

# SSRF Analysis

## Purpose

Teach the agent to reason about **Server-Side Request Forgery (SSRF)**: when attacker-influenced input reaches a server-side network client and the server fetches a destination the attacker can affect.

## When to Use

- Code review of `requests`, `fetch`, `httpx`, `urllib`, `axios`, webhook/callback URLs, link previewers, PDF/HTML renderers, importers.
- After `axguard scan|audit` hits `ssrf.*` or `cloud.*metadata*`.
- Cloud apps that might reach instance metadata (`169.254.169.254`).

## When Not to Use

- Pure client-side browser `fetch` to same-origin APIs (not SSRF).
- Outbound calls with fully hard-coded, non-user-influenced destinations and no redirect following of user input.

## Security Concepts

SSRF is an **egress trust failure**: the server becomes a proxy into networks the attacker cannot reach directly (localhost, RFC1918, link-local, cloud metadata, internal admin).

## Threat Model

Attacker goals:

1. Read cloud credentials via metadata services.
2. Port-scan or hit internal admin panels.
3. Bypass network controls using the app as pivot.
4. Chain into RCE via internal-only endpoints.

## Preconditions

- Target is software the user owns or is authorized to test.
- Prefer static analysis + safe local validation; do not attack third-party infrastructure.

## Inputs

- Source tree / PR diff
- Optional: `axguard audit` JSON report
- Known deployment context (cloud provider, VPC, IMDSv1 vs v2)

## Discovery

1. Prefer `axguard flow` evidence when available (`dataflow.json` / unsanitized net paths); otherwise run `axguard scan .` or `axguard audit .` and collect `ssrf.*` / metadata findings.
2. Grep for network clients: `requests.`, `httpx.`, `urllib`, `fetch(`, `axios.`, `curl`, `HttpClient`, `RestTemplate`.
3. Find URL construction: query params, body fields, webhooks, `next=`, `url=`, `callback=`, `redirect=`.

## Analysis Workflow

Trace **source → transform → sink**:

1. Where does the URL/host enter (param, JSON, header, DB)?
2. Is it concatenated, parsed, normalized?
3. Is there an allowlist of schemes/hosts? Or only a denylist?
4. Is validation on hostname **before** or **after** DNS resolution?
5. Are redirects followed? To what depth?
6. Can the destination be `localhost`, `127.0.0.1`, `0.0.0.0`, IPv6 loopback, RFC1918, link-local, metadata IP?
7. Is response body/status returned to the attacker (full SSRF) or only timing/errors (blind)?
8. In cloud: can it reach metadata? Is IMDSv2 required (more resistant)?

## Data Flow

```text
attacker input → URL builder → HTTP client → internal/metadata network → response handling
```

## Validation

Authorized defensive checks only:

- Confirm code path is reachable in normal request handling.
- Confirm user influence on host/scheme/path.
- Confirm missing or weak allowlist.
- Document whether response is observable.

Do not brute-force third-party hosts.

## Evidence Requirements

Hypothesis becomes **HIGH/CONFIRMED** only with:

- File:line of sink
- Source of attacker influence
- Missing control (no allowlist / redirect follow / DNS rebinding gap)
- Impact hypothesis tied to environment (e.g., metadata readable)

## False Positive Controls

Drop or downgrade when:

- URL is enum/constant from server config only
- Strict allowlist of https + exact hosts, no redirects
- Client-side only request
- Test fixtures intentionally vulnerable (unless scanning fixtures)

## Severity Assessment

| Condition | Typical severity |
|---|---|
| Metadata credential theft plausible | Critical/High |
| Internal admin reachable + response returned | High |
| Blind internal probe only | Medium |
| Hardened allowlist, theoretical only | Low/Info |

Do not invent CVSS vectors.

## Remediation

1. **Allowlist** schemes (`https`) and hosts; reject IP literals unless required.
2. Resolve DNS and **re-validate** resolved addresses (block private/link-local/metadata ranges).
3. Disable or strictly limit redirects.
4. Use cloud metadata **IMDSv2** / hop limits; block `169.254.169.254` at egress.
5. Never return raw third-party response bodies to clients unless required and sanitized.

## Verification

```text
Detect → Fix allowlist/egress → Re-run axguard → Manually re-trace source→sink → Confirm blocked destinations
```

Add regression tests: attempts to pass metadata IP / localhost must fail closed.

## Reporting

Use AXguard report fields: location, evidence snippet, why it matters, fix, confidence.

## Related Skills

- `cloud-security` — metadata & egress policy
- `api-security` — webhook/callback designs
- `secrets-detection` — stolen cloud keys impact
- `security-triage` — confidence gating
- `security-remediation` — patch patterns

## Framework Mapping

- CWE-918
- OWASP Top 10 2021 A10:2021 SSRF

## References

- https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/
- https://cwe.mitre.org/data/definitions/918.html

## Research Provenance

Primary sources:

- OWASP Top 10:2021 A10 (accessed 2026-09-15)
- CWE-918 (accessed 2026-09-15)

Secondary / internal:

- AXGuard `rules/ssrf.json`, `rules/cloud.json`
- AwareXone Agentic-Bug-Hunter web SSRF methodology (concepts only; not copied)

Datasets:

- UVID HF dataset — category linkage concepts only (MIT license metadata review 2026-09-15)
