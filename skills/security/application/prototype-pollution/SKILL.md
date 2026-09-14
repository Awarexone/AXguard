---
name: prototype-pollution
description: Analyze JavaScript prototype pollution risks — use when reviewing deep merges, recursive object assigns, query-to-object parsers, or untrusted JSON key merges (CWE-1321 / A03:2021).
version: "1.0.0"
author: AwareXone
license: MIT
domain: application-security
subcategory: web-security
tags: [prototype-pollution, javascript, merge, cwe-1321]
frameworks:
  cwe: [CWE-1321]
  owasp_top10: [A03:2021]
  owasp_api_top10: []
  owasp_llm_top10: []
  owasp_wstg: []
  owasp_asvs: []
  mitre_attack: []
  mitre_atlas: []
  nist_csf: []
  nist_ai_rmf: []
related_skills: [xss-analysis, api-security, authorization-analysis, security-triage, security-remediation]
related_commands: [/axguard-inject, /axguard-xss, /axguard-audit]
related_rules: [injection., xss.]
references:
  - https://owasp.org/Top10/A03_2021-Injection/
  - https://cwe.mitre.org/data/definitions/1321.html
last_reviewed: "2026-09-15"
---

# Prototype Pollution Analysis

## Purpose

Teach defensive reasoning about **prototype pollution**: attacker-controlled property keys (`__proto__`, `constructor`, `prototype`) modify `Object.prototype` (or other prototypes) via unsafe merge/clone/path assignment, affecting unrelated code paths (gadgets).

## When to Use / When Not to Use

**Use when:**

- Node/browser code deep-merges user JSON, parses nested query objects, uses vulnerable `lodash.merge`-class APIs, recursive `for..in` assigns, or settings import endpoints.
- Client-side URL/hash parsers feed object merges (DOM XSS gadget hunts).
- AuthZ checks rely on property presence/truthiness that could be inherited.

**Do not use when:**

- No JavaScript/TypeScript object merge of untrusted structures (Python/Java dict updates are different classes).
- Data is stored only in `Map` / `Object.create(null)` with no prototype-affecting assignment.

## Security Concepts

Pollution is usually a **two-stage** issue: (1) pollution sink succeeds; (2) a gadget reads the polluted property (XSS sink, `isAdmin`, template options, `env`). Severity depends on gadgets, not on pollution alone.

## Threat Model

Attacker goals:

1. Flip security flags (`isAdmin`, `authenticated`).
2. Unlock DOM XSS via client gadgets.
3. DoS (override built-ins) or server RCE via known Node gadgets.

## Analysis Workflow

1. Find recursive merge/clone/assign utilities and query parsers that build nested objects.
2. Confirm untrusted keys flow into those sinks without key filtering.
3. Check for blocking of `__proto__`, `constructor`, `prototype` at **every** nesting level.
4. Prefer safe structures: `Object.create(null)`, `Map`, schema validation (reject unknown keys).
5. Search for gadgets: property checks without `hasOwn`, HTML sinks reading options, template/compile flags.
6. Separate client vs server impact; do not claim RCE without a concrete gadget path.
7. Review dependency versions known for merge CVEs.

## Evidence Requirements

- Merge/assign sink file:line
- Untrusted key path
- Missing dangerous-key rejection
- At least a plausible gadget or explicit “pollution without known gadget” downgrade

## False Positive Controls

- Schema validators that strip unknown keys
- Explicit rejection of dangerous keys before assign
- Use of `Map` / null-prototype objects only
- Merges of trusted server config only

## Remediation

1. Reject `__proto__`, `constructor`, `prototype` keys recursively.
2. Validate with strict schemas; avoid recursive merge of untrusted objects.
3. Use `Map` or `Object.create(null)` for dictionaries.
4. Prefer `Object.hasOwn` / `hasOwnProperty.call` for security checks.
5. Patch vulnerable merge dependencies; consider `Object.freeze(Object.prototype)` only after compatibility testing.

## Verification

```text
Find merge sinks → Add key deny + schema → Re-run review → Confirm no untrusted recursive assign
```

## Related Skills

- `xss-analysis` — common client gadget class
- `authorization-analysis` — polluted auth flags
- `api-security`, `security-triage`, `security-remediation`

## Framework Mapping

- CWE-1321
- OWASP Top 10 2021 A03:2021 Injection

## References

- https://owasp.org/Top10/A03_2021-Injection/
- https://cwe.mitre.org/data/definitions/1321.html

## Research Provenance

Primary sources:

- CWE-1321 (accessed 2026-09-15; verified title: Improperly Controlled Modification of Object Prototype Attributes)
- OWASP Top 10:2021 A03 (accessed 2026-09-15)

Secondary / internal:

- AXGuard injection/XSS rule adjacency; practitioner merge-sink review patterns
- AwareXone Agentic-Bug-Hunter prototype-pollution methodology (concepts only; not copied)

Datasets:

- UVID HF dataset — category linkage concepts only (MIT license metadata review 2026-09-15)
