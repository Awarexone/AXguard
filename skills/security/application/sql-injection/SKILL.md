---
name: sql-injection
description: Analyze SQL and ORM injection risks in application code — use for string-built queries, raw SQL helpers, and database sinks (CWE-89 / A03:2021).
version: "1.0.0"
author: AwareXone
license: MIT
domain: application-security
subcategory: injection
tags: [sqli, injection, orm, cwe-89]
frameworks:
  cwe: [CWE-89]
  owasp_top10: [A03:2021]
  owasp_api_top10: []
  owasp_llm_top10: []
  owasp_wstg: []
  owasp_asvs: []
  mitre_attack: []
  mitre_atlas: []
  nist_csf: []
  nist_ai_rmf: []
related_skills: [api-security, command-injection, security-triage, security-remediation]
related_commands: [/axguard-sql, /axguard-inject, /axguard-audit, /axguard-flow]
related_rules: [sql., nosql.]
references:
  - https://owasp.org/Top10/A03_2021-Injection/
  - https://cwe.mitre.org/data/definitions/89.html
last_reviewed: "2026-09-15"
---

# SQL Injection Analysis

## Purpose

Encode practitioner reasoning for detecting and validating **SQL injection** and unsafe raw-query patterns during pre-ship review.

## When to Use

- Reviewing database access code (SQL strings, ORM `.raw`, query builders).
- After AXguard hits `sql.*` or suspicious `injection.*` near DB APIs.
- API endpoints that filter/sort/search with user parameters.

## When Not to Use

- Queries that are fully static with zero user influence.
- NoSQL-specific operator injection (use a dedicated NoSQL skill when available; AXguard `nosql.*` rules are adjacent).

## Security Concepts

SQLi occurs when untrusted input changes SQL **syntax/structure**, not merely values. Parameter binding sends values separately so structure stays fixed.

## Threat Model

Attacker influence over WHERE/ORDER/identifiers can yield data disclosure, authentication bypass, or in some stacks RCE via DB features — assess per engine.

## Analysis Workflow

1. Prefer `axguard flow` evidence when available (`sources_to_sql` / unsanitized paths in `dataflow.json`).
2. Find sinks: `execute`, `executemany`, `query`, `.raw`, `text(`, cursor calls.
3. Find sources: request params, headers, path, webhook bodies, AI tool args.
4. Determine if input is concatenated, f-string formatted, or `%`-formatted into SQL.
5. Check whether identifiers (table/column) are user-controlled — bind parameters cannot fix identifier injection; need allowlists.
6. Confirm ORM usage is actually parameterized (some `.raw`/`extra` APIs are not).

## Evidence Requirements

- Sink location
- Source of taint
- Proof of string composition into SQL
- Impact class (read / write / auth bypass) as hypothesis until validated

## False Positive Controls

- Bound parameters (`?`, `%s` with args tuple, ORM filters)
- Allowlisted sort columns mapped server-side
- Static admin scripts with no external input

## Remediation

- Parameterized queries / prepared statements only for values.
- Allowlist for ORDER BY / column names.
- Least-privilege DB accounts.
- Prefer ORM query APIs without raw string splicing.

## Verification

Re-run `axguard audit`, then manually confirm the risky composition path is gone and tests cover malicious input strings as data (not syntax).

## Related Skills

`api-security`, `security-triage`, `security-remediation`, `command-injection`

## Framework Mapping

- CWE-89
- OWASP A03:2021 Injection

## References

- https://owasp.org/Top10/A03_2021-Injection/
- https://cwe.mitre.org/data/definitions/89.html

## Research Provenance

Primary: OWASP Top 10:2021 A03; CWE-89 (2026-09-15).  
Secondary: AXGuard `rules/sql.json`; HF CyberNative DPO / UVID — derived pattern concepts only.
