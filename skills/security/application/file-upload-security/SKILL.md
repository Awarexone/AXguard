---
name: file-upload-security
description: Analyze unsafe file upload handling — use when reviewing multipart uploads, extension/MIME checks, stored filenames, image processors, or user-supplied archives (CWE-434 / A04:2021).
version: "1.0.0"
author: AwareXone
license: MIT
domain: application-security
subcategory: web-security
tags: [file-upload, multipart, cwe-434]
frameworks:
  cwe: [CWE-434]
  owasp_top10: [A04:2021]
  owasp_api_top10: [API8:2023]
  owasp_llm_top10: []
  owasp_wstg: []
  owasp_asvs: []
  mitre_attack: []
  mitre_atlas: []
  nist_csf: []
  nist_ai_rmf: []
related_skills: [path-traversal, command-injection, xss-analysis, deserialization-security, security-triage, security-remediation]
related_commands: [/axguard-upload, /axguard-path, /axguard-audit]
related_rules: [upload., path.]
references:
  - https://owasp.org/Top10/A04_2021-Insecure_Design/
  - https://owasp.org/API-Security/editions/2023/en/api8-security-misconfiguration/
  - https://cwe.mitre.org/data/definitions/434.html
last_reviewed: "2026-09-15"
---

# File Upload Security

## Purpose

Guide pre-ship review of **unrestricted or weakly restricted file uploads**: content that is stored, served, or processed unsafely leading to RCE, XSS, traversal, or malware distribution.

## When to Use / When Not to Use

**Use when:**

- Multipart endpoints, avatar/doc uploads, `multer`, `Busboy`, Django `FileField`, S3 presigned PUT, archive import, antivirus-less pipelines.
- After AXguard hits `upload.*` or related `path.*`.
- Uploaded files are later executed, included, or served as HTML/JS.

**Do not use when:**

- No file ingress exists (JSON-only APIs).
- Upload is delegated entirely to a hardened third-party with app-only metadata (still review URL/XSS when displaying).

## Security Concepts

Upload risk is a **pipeline**: accept → name → store → process → serve. Controls must cover type (magic bytes + allowlist), size, path, virus/content policy, and Content-Type when serving. Extension checks alone are insufficient.

## Threat Model

Attacker goals:

1. Upload executable/script into a webroot or template path.
2. Store HTML/SVG that executes as XSS when served.
3. Zip-slip / oversized archives (DoS) during extract.
4. Polyglot files that bypass MIME sniffing or image pipelines (ImageTragick-class).

## Analysis Workflow

1. Map upload endpoints and storage destinations (disk, S3, CDN).
2. Check extension allowlist vs denylist; confirm MIME and magic-byte validation.
3. Inspect filename handling — user-controlled names vs random object keys.
4. Determine if files are served from the app origin with user Content-Type / inline disposition.
5. Review processors (ImageMagick, LibreOffice, ffmpeg, unzip) for known unsafe flags and shelling out.
6. Check authZ: who can upload / overwrite / read whose objects.
7. Confirm size limits, rate limits, and malware scanning expectations for the threat model.

## Evidence Requirements

- Upload handler location
- Missing type/size/name controls
- Dangerous serve or process path
- Impact class (RCE / stored XSS / traversal / DoS)

## False Positive Controls

- Strict allowlist + random keys + non-executable storage + safe Content-Disposition
- Uploads never served back as active content
- Admin-only internal tooling with compensating network controls (still note residual risk)

## Remediation

1. Allowlist extensions and verify content signatures; reject mismatches.
2. Store under random keys outside webroot; never use raw user filenames on disk.
3. Serve via separate domain with `Content-Disposition: attachment` and fixed safe Content-Type where possible.
4. Process in isolated workers with resource limits; patch converters.
5. Enforce authN/authZ, quotas, and malware scanning for high-risk products.

## Verification

```text
Review accept→serve pipeline → Apply allowlist + random keys → Re-run axguard → Confirm no executable serve path
```

## Related Skills

- `path-traversal`, `xss-analysis`, `command-injection`, `deserialization-security`
- `security-triage`, `security-remediation`

## Framework Mapping

- CWE-434
- OWASP Top 10 2021 A04:2021 Insecure Design
- OWASP API Security Top 10 2023 API8:2023 Security Misconfiguration

## References

- https://owasp.org/Top10/A04_2021-Insecure_Design/
- https://owasp.org/API-Security/editions/2023/en/api8-security-misconfiguration/
- https://cwe.mitre.org/data/definitions/434.html

## Research Provenance

Primary sources:

- OWASP Top 10:2021 A04; OWASP API8:2023; CWE-434 (accessed 2026-09-15)

Secondary / internal:

- AXGuard `rules/upload.json`, `/axguard-upload`
- AwareXone Agentic-Bug-Hunter upload methodology (concepts only; not copied)

Datasets:

- UVID HF dataset — category linkage concepts only (MIT license metadata review 2026-09-15)
