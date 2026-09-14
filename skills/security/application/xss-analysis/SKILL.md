---
name: xss-analysis
description: Analyze and validate cross-site scripting in web/UI code — use when reviewing HTML sinks, DOM APIs, template escaping, dangerouslySetInnerHTML, or reflected/stored XSS paths (CWE-79 / A03:2021).
version: "1.0.0"
author: AwareXone
license: MIT
domain: application-security
subcategory: web-security
tags: [xss, dom, escaping, cwe-79]
frameworks:
  cwe: [CWE-79]
  owasp_top10: [A03:2021]
  owasp_api_top10: []
  owasp_llm_top10: []
  owasp_wstg: []
  owasp_asvs: []
  mitre_attack: []
  mitre_atlas: []
  nist_csf: []
  nist_ai_rmf: []
related_skills: [prototype-pollution, graphql-security, api-security, security-triage, security-remediation]
related_commands: [/axguard-xss, /axguard-audit, /axguard-scan]
related_rules: [xss.]
references:
  - https://owasp.org/Top10/A03_2021-Injection/
  - https://cwe.mitre.org/data/definitions/79.html
last_reviewed: "2026-09-15"
---

# XSS Analysis

## Purpose

Teach the agent to reason about **Cross-Site Scripting (XSS)**: untrusted data reaches an HTML/JS execution or DOM interpretation sink without context-correct encoding, enabling script execution in a victim browser.

## When to Use / When Not to Use

**Use when:**

- Reviewing templates, React/Vue/Svelte markup, `innerHTML`, `document.write`, `dangerouslySetInnerHTML`, URL/`javascript:` sinks, or markdown/HTML renderers.
- After `axguard` hits `xss.*` findings.
- Auth/session cookies lack `HttpOnly` and HTML reflection is nearby (session theft impact).

**Do not use when:**

- Pure server-to-server JSON APIs with no HTML consumers (prefer `api-security` for injection into other sinks).
- Content is forced through a known safe text node API with no attribute/URL context issues and no raw HTML path.

## Security Concepts

XSS is a **browser trust-boundary failure**. Context matters: HTML body, attribute, JS string, URL, CSS, and JSON-in-script each need different encoding. Framework auto-escaping helps only when you stay on the safe API path.

## Threat Model

Attacker goals:

1. Steal session tokens / local storage secrets.
2. Act as the victim (CSRF-like actions from the victim origin).
3. Deface, phish, or pivot into admin UI.
4. Chain with CSP gaps, prototype pollution gadgets, or open redirects.

## Analysis Workflow

Trace **source → transform → sink** with context:

1. Find sinks: `innerHTML`, `outerHTML`, `document.write`, `insertAdjacentHTML`, `dangerouslySetInnerHTML`, `v-html`, `|safe`, `Markup(`, unescaped `{{`, `eval`/`Function` on user strings, `location`/`href`/`src` assignments.
2. Find sources: query/body/path, stored user content, webhook payloads, markdown, email HTML, AI/tool output rendered in UI.
3. Identify **output context** (HTML text, attribute, JS, URL). Wrong encoder = still XSS.
4. Check framework escape defaults vs deliberate bypass (`|safe`, `raw`, `bypassSecurityTrustHtml`).
5. Check CSP: is it enforced? Does it allow `unsafe-inline` / wildcards that neutralize mitigation?
6. Classify: reflected vs stored vs DOM-based; note if HttpOnly / SameSite reduce cookie theft.
7. For DOM XSS: confirm attacker-controlled string reaches sink **in the browser** without server re-encoding.

## Evidence Requirements

Hypothesis becomes **HIGH/CONFIRMED** only with:

- File:line of sink and source of attacker influence
- Proof of missing/incorrect encoding for that context
- Realistic execution path (not dead template)
- Impact note (session, account takeover, admin UI)

## False Positive Controls

Drop or downgrade when:

- Value is constrained to a safe allowlist (enum, UUID, integer) before render
- Safe text APIs only (`textContent`, escaped templates) with no raw HTML path
- Markdown renderer is hardened and HTML disabled
- Finding is in intentional XSS test fixtures (unless auditing fixtures)

## Remediation

1. Prefer framework text-binding; never concatenate untrusted data into HTML.
2. Context-correct encoding libraries for any residual HTML.
3. Sanitize HTML with a maintained allowlist sanitizer if rich text is required.
4. Set CSP (nonces/hashes; avoid `unsafe-inline` where possible), `HttpOnly` + `Secure` + `SameSite` cookies.
5. Avoid `javascript:` / data URL assignment from user input.

## Verification

```text
Detect → Encode/sanitize sink → Re-run axguard → Confirm no raw sink path → Add regression tests for reflected/stored strings
```

## Related Skills

- `prototype-pollution` — client gadgets that unlock DOM XSS
- `graphql-security` / `api-security` — stored fields later rendered in UI
- `security-triage`, `security-remediation`

## Framework Mapping

- CWE-79
- OWASP Top 10 2021 A03:2021 Injection

## References

- https://owasp.org/Top10/A03_2021-Injection/
- https://cwe.mitre.org/data/definitions/79.html

## Research Provenance

Primary sources:

- OWASP Top 10:2021 A03 (accessed 2026-09-15)
- CWE-79 (accessed 2026-09-15)

Secondary / internal:

- AXGuard `rules/xss.json`, `/axguard-xss`
- AwareXone Agentic-Bug-Hunter XSS methodology (concepts only; not copied)

Datasets:

- UVID HF dataset — category linkage concepts only (MIT license metadata review 2026-09-15)
