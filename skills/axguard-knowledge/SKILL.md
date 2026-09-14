---
name: axguard-knowledge
description: Pre-ship vulnerability class encyclopedia for AXguard — root causes, static detection hints, CWE/OWASP maps, and fix guidance for IDOR, auth, XSS, SSRF, SQLi, SSTI, deserialization, path traversal, secrets, cloud, CORS, JWT, upload, GraphQL, supply chain, LLM/agent, debug exposure, and crypto misuse. Load when auditing, triaging, or remediating and a class needs depth. Defensive static review only.
---

# AXguard Knowledge

Reference skill for **pre-ship static review**. Distills web and agent vuln classes into root cause → detection → fix. Not a live exploitation handbook.

## When to load

- `/axguard-audit`, `axguard-preship`, or `axguard-cso` needs class depth
- Triage/remediate needs FP notes or fix patterns
- Mapping findings to CWE / OWASP labels for reports

## How to use

1. Read `references/vuln-classes.md` for the matching class (or skim the index below).
2. Apply to the current repo with file:line evidence.
3. Cite `references/sources.md` if the user asks where frameworks/datasets inspired the taxonomy.

## Class index

| Class | Primary CWE | OWASP (indicative) |
|-------|-------------|--------------------|
| Broken access / IDOR | CWE-639 | A01 |
| Authn / session / CSRF | CWE-287, CWE-352 | A07 |
| JWT misuse | CWE-347 | A07 / A02 |
| SQL injection | CWE-89 | A03 |
| Command / code injection | CWE-78, CWE-94 | A03 |
| SSTI | CWE-1336 | A03 |
| Insecure deserialization | CWE-502 | A08 / A03 |
| Path traversal / LFI | CWE-22, CWE-98 | A01 / A03 |
| SSRF | CWE-918 | A10 |
| XSS | CWE-79 | A03 |
| File upload | CWE-434 | A04 |
| GraphQL issues | CWE-200, CWE-352 | A01 / A05 |
| Secrets in code | CWE-798 | A07 / A02 |
| Cloud / CORS misconfig | CWE-942, CWE-284 | A05 |
| Crypto misuse | CWE-321, CWE-328, CWE-338, CWE-295 | A02 |
| Supply chain / CI | CWE-494, CWE-506 | A08 |
| Debug / verbose errors | CWE-489, CWE-209 | A05 |
| LLM / agent tool risks | CWE-77, CWE-94 | OWASP LLM |

## Rules of engagement

- Prefer `axguard audit` / `axguard scan` for deterministic leads; this skill explains and verifies.
- Static hints only — no step-by-step attacks against third-party systems.
- When unsure: `needs-manual`, do not over-claim.

## Files

- `references/vuln-classes.md` — class distillations
- `references/sources.md` — inspiration and datasets (summaries, not verbatim copies)
