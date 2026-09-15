---
name: deserialization-security
description: Analyze unsafe deserialization and object-decode sinks — use when reviewing pickle, YAML load, Java ObjectInputStream, PHP unserialize, or untrusted serialized blobs (CWE-502 / A08:2021).
version: "1.0.0"
author: AwareXone
license: MIT
domain: application-security
subcategory: injection
tags: [deserialization, pickle, unserialize, cwe-502]
frameworks:
  cwe: [CWE-502]
  owasp_top10: [A08:2021]
  owasp_api_top10: []
  owasp_llm_top10: []
  owasp_wstg: []
  owasp_asvs: []
  mitre_attack: []
  mitre_atlas: []
  nist_csf: []
  nist_ai_rmf: []
related_skills: [command-injection, ssti-analysis, api-security, security-triage, security-remediation]
related_commands: [/axguard-inject, /axguard-audit, /axguard-scan]
related_rules: [injection.]
references:
  - https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/
  - https://cwe.mitre.org/data/definitions/502.html
last_reviewed: "2026-09-15"
---

# Deserialization Security

## Purpose

Encode practitioner analysis of **insecure deserialization**: untrusted data is decoded into objects/code paths that invoke unexpected constructors, magic methods, or gadgets, often causing RCE or auth bypass.

## When to Use / When Not to Use

**Use when:**

- `pickle.loads`, `yaml.load` (unsafe), `ObjectInputStream`, `unserialize(`, `BinaryFormatter`, `Marshal.load`, JavaScript `node-serialize`-class patterns, Redis/cache storing pickled objects, signed-but-not-encrypted cookies of serialized state.
- After AXguard hits `injection.*pickle*`, `*unserialize*`, `*objectinput*`.

**Do not use when:**

- Data is pure JSON/structured text parsed into primitive DTOs with schema validation and no polymorphic type attacker control.
- Serialization is only outbound (encoding) with no decode of untrusted input.

## Security Concepts

Many serializers can reconstruct arbitrary types. Integrity of the blob (HMAC) helps only if the key is secret and verification happens **before** deserialize. Prefer data-only formats (JSON) + explicit schema.

## Threat Model

Attacker goals:

1. Remote code execution via gadget chains.
2. Forge session/auth objects.
3. DoS via deeply nested / expensive object graphs.

## Analysis Workflow

1. Inventory decode sinks and libraries/versions.
2. Trace whether the blob is attacker-reachable (HTTP body, cookie, queue, file upload, cache key value).
3. Check for cryptographic integrity (HMAC/signature) and whether verification precedes deserialize.
4. Determine allowed types / allowlists (`yaml.safe_load`, Java allowlists, PHP allowed_classes).
5. Prefer replacing the format over “hardening” unsafe loaders when possible.
6. Assess impact based on process privileges and available gadgets in classpath/deps.

## Evidence Requirements

- Decode sink location
- Untrusted source of serialized bytes
- Missing integrity check or unsafe loader API
- Impact hypothesis (RCE / auth forge / DoS)

## False Positive Controls

- `yaml.safe_load` / JSON-only parsers
- Deserialize only of trusted operator-controlled backups offline
- Integrity-protected blobs with server-side keys and no attacker key access (residual risk if types still dangerous — note)

## Remediation

1. Prefer JSON (or similar) with schema validation.
2. Never `pickle`/`unserialize` untrusted data; use safe loaders and type allowlists if unavoidable.
3. Authenticate then decrypt/verify before decode; rotate keys.
4. Isolate deserializers in hardened workers; keep deps patched.
5. Remove unused gadget-heavy libraries from classpath.

## Verification

```text
Find unsafe loaders → Replace with safe format/API → Re-run axguard → Confirm no untrusted deserialize path
```

## Related Skills

- `command-injection`, `ssti-analysis` — alternate RCE
- `api-security` — untrusted message bodies
- `security-triage`, `security-remediation`

## Framework Mapping

- CWE-502
- OWASP Top 10 2021 A08:2021 Software and Data Integrity Failures

## References

- https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/
- https://cwe.mitre.org/data/definitions/502.html

## Research Provenance

Primary sources:

- OWASP Top 10:2021 A08; CWE-502 (accessed 2026-09-15)

Secondary / internal:

- AXGuard `rules/injection.json`, `rules/advanced.json` (unserialize/ObjectInput patterns)
- AwareXone Agentic-Bug-Hunter deserialization methodology (concepts only; not copied)

Datasets:

- UVID HF dataset — category linkage concepts only (MIT license metadata review 2026-09-15)
