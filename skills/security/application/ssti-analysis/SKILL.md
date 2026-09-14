---
name: ssti-analysis
description: Analyze server-side template injection risks — use when user input reaches template engines (Jinja, Twig, Freemarker, Pug, Liquid) or dynamic template compile/render APIs (CWE-1336 / A03:2021).
version: "1.0.0"
author: AwareXone
license: MIT
domain: application-security
subcategory: injection
tags: [ssti, templates, jinja, cwe-1336]
frameworks:
  cwe: [CWE-1336]
  owasp_top10: [A03:2021]
  owasp_api_top10: []
  owasp_llm_top10: []
  owasp_wstg: []
  owasp_asvs: []
  mitre_attack: []
  mitre_atlas: []
  nist_csf: []
  nist_ai_rmf: []
related_skills: [command-injection, xss-analysis, deserialization-security, security-triage, security-remediation]
related_commands: [/axguard-ssti, /axguard-inject, /axguard-audit]
related_rules: [ssti.]
references:
  - https://owasp.org/Top10/A03_2021-Injection/
  - https://cwe.mitre.org/data/definitions/1336.html
last_reviewed: "2026-09-15"
---

# SSTI Analysis

## Purpose

Encode practitioner reasoning for **Server-Side Template Injection (SSTI)**: attacker-influenced strings are evaluated as template code by the server template engine, often escalating to RCE or data disclosure.

## When to Use / When Not to Use

**Use when:**

- Code calls `render_template_string`, `Template(user)`, `compile(`, Pug/`_.template`, Twig string templates, Freemarker `StringTemplateLoader`, Liquid parse of user content.
- After AXguard hits `ssti.*`.
- Features like “custom email templates”, “report builders”, or “theme editors” accept template syntax from users.

**Do not use when:**

- Templates are static files and user data is passed only as **variables** into a fixed template (normal MVC rendering).
- Client-side-only template libs with no server evaluation (consider XSS instead).

## Security Concepts

SSTI is not “XSS on the server.” The engine **parses and executes** template language constructs (`{{ }}`, `{% %}`, expressions). Passing user input as data into a precompiled template is usually safe; building or compiling a template from user input is not.

## Threat Model

Attacker goals:

1. Remote code execution via template sandbox escapes.
2. Read secrets/env/config through template object graphs.
3. Bypass auth by evaluating expressions in privileged render paths.

## Analysis Workflow

1. Inventory template engines and versions (Jinja2, Mako, Twig, Freemarker, Velocity, Pug, EJS, Liquid).
2. Find **dynamic compile/render** APIs vs static template + context dict.
3. Trace whether any request/DB/AI field becomes the template **source string**.
4. Check sandbox / restricted environments — note they are often escapable; do not treat “sandbox=True” as automatic safe.
5. Distinguish design: admin-only template editors vs any-user input.
6. Assess impact by engine capabilities (file read, subprocess, class loading).
7. Prefer static confirmation of taint → compile/render over speculative payload design.

## Evidence Requirements

- File:line of template compile/render sink
- Attacker-controlled template source (not merely variables)
- Missing isolation (no sandbox / weak sandbox / privileged process)
- Impact class (RCE / file read / info disclosure) as hypothesis until validated

## False Positive Controls

- Fixed template path + user values only in context
- Template names selected from server allowlist (not raw body)
- Offline build-time templates with no runtime string compile
- Intentional SSTI unit fixtures

## Remediation

1. Never compile templates from untrusted strings; pass data as variables only.
2. If user-defined templates are required: strict sandbox, allowlisted tags/filters, separate least-privilege worker, no access to OS/app objects.
3. Prefer non-Turing template languages or logic-less templates for tenant customization.
4. Keep engines patched; disable dangerous extensions/plugins.

## Verification

```text
Detect dynamic template APIs → Remove user-as-template → Re-run axguard → Confirm only variable substitution remains
```

## Related Skills

- `command-injection` — common SSTI escalation class
- `xss-analysis` — if output is HTML without server evaluation
- `security-triage`, `security-remediation`

## Framework Mapping

- CWE-1336
- OWASP Top 10 2021 A03:2021 Injection

## References

- https://owasp.org/Top10/A03_2021-Injection/
- https://cwe.mitre.org/data/definitions/1336.html

## Research Provenance

Primary sources:

- OWASP Top 10:2021 A03 (accessed 2026-09-15)
- CWE-1336 (accessed 2026-09-15)

Secondary / internal:

- AXGuard `rules/ssti.json`, `/axguard-ssti`
- AwareXone Agentic-Bug-Hunter SSTI methodology (concepts only; not copied)

Datasets:

- UVID HF dataset — category linkage concepts only (MIT license metadata review 2026-09-15)
