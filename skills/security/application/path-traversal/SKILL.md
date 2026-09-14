---
name: path-traversal
description: Analyze path traversal and unsafe file access — use when user input influences file paths, downloads, includes, zip extraction, or static file send APIs (CWE-22 / A01:2021).
version: "1.0.0"
author: AwareXone
license: MIT
domain: application-security
subcategory: web-security
tags: [path-traversal, lfi, zip-slip, cwe-22]
frameworks:
  cwe: [CWE-22]
  owasp_top10: [A01:2021]
  owasp_api_top10: []
  owasp_llm_top10: []
  owasp_wstg: []
  owasp_asvs: []
  mitre_attack: []
  mitre_atlas: []
  nist_csf: []
  nist_ai_rmf: []
related_skills: [file-upload-security, command-injection, api-security, security-triage, security-remediation]
related_commands: [/axguard-path, /axguard-upload, /axguard-audit]
related_rules: [path.]
references:
  - https://owasp.org/Top10/A01_2021-Broken_Access_Control/
  - https://cwe.mitre.org/data/definitions/22.html
last_reviewed: "2026-09-15"
---

# Path Traversal Analysis

## Purpose

Encode defensive reasoning for **path traversal** (and related LFI/zip-slip): attacker-controlled path segments escape an intended directory and read/write unintended files.

## When to Use / When Not to Use

**Use when:**

- `open`, `send_file`, `sendFile`, `include`/`require` of dynamic paths, download-by-name, template path params, archive extraction, cloud key prefixes built from user input.
- After AXguard hits `path.*`.
- Upload features store user-chosen filenames (pair with `file-upload-security`).

**Do not use when:**

- Paths are fully server-derived IDs mapped via DB to stored objects with no filesystem join of raw names.
- Pure URL path routing without filesystem access (authorization issues belong in `authorization-analysis`).

## Security Concepts

Traversal uses `../`, encoded variants, absolute paths, symlink tricks, and archive entries with `../` (zip-slip). Safe pattern: resolve to absolute path, then verify it remains under an allowlisted root (`commonpath` / `startsWith` after normalization).

## Threat Model

Attacker goals:

1. Read secrets (`/etc/passwd`, `.env`, cloud creds, keys).
2. Overwrite app code, templates, or SSH keys (when write sinks exist).
3. Include/execute unintended files (language-specific LFI → RCE).

## Analysis Workflow

1. Find filesystem sinks: open/read/write, download helpers, dynamic includes, unzip/untar.
2. Trace user influence on filename, relative segment, or archive entry name.
3. Check normalization order: decode → normalize → root check (watch double-encoding).
4. Verify **post-resolve** containment under intended root (not prefix string checks alone).
5. For archives: validate each entry path before extract; reject absolute/`..` entries.
6. Note symlink following behavior of the API.
7. Assess impact by readable/writable sensitivity of the process sandbox.

## Evidence Requirements

- Sink file:line and path construction
- Missing canonicalization or root containment
- Attacker-controlled segment
- Impact hypothesis (secret read / overwrite / include)

## False Positive Controls

- Opaque object IDs with server-side path map
- Strict allowlist of filenames/extensions mapped to fixed directory
- Paths constrained to UUID-only with no separators after validation
- Docs/examples not reachable in production code paths

## Remediation

1. Do not concatenate untrusted strings into filesystem paths.
2. Use object storage keys or random stored names; keep display names separate.
3. After resolve, enforce directory containment.
4. Harden zip extraction (strip paths, reject `..`, extract to empty temp dir).
5. Run with least file privileges; no secrets in web-readable trees.

## Verification

```text
Detect path joins → Enforce root containment / ID maps → Re-run axguard → Add tests for ../ and encoded variants (authorized fixtures only)
```

## Related Skills

- `file-upload-security` — malicious names and content types
- `command-injection` — path args passed to shells
- `api-security`, `security-triage`, `security-remediation`

## Framework Mapping

- CWE-22
- OWASP Top 10 2021 A01:2021 Broken Access Control

## References

- https://owasp.org/Top10/A01_2021-Broken_Access_Control/
- https://cwe.mitre.org/data/definitions/22.html

## Research Provenance

Primary sources:

- OWASP Top 10:2021 A01 (accessed 2026-09-15)
- CWE-22 (accessed 2026-09-15)

Secondary / internal:

- AXGuard `rules/path.json`, `/axguard-path`
- AwareXone Agentic-Bug-Hunter path/LFI methodology (concepts only; not copied)

Datasets:

- UVID HF dataset — category linkage concepts only (MIT license metadata review 2026-09-15)
