---
name: supply-chain-security
description: Assess install hooks, curl|sh, untrusted indexes, and integrity gaps in dependency/build pipelines before ship (CWE-494 / CWE-506 / A06:2021 / A08:2021).
version: "1.0.0"
author: AwareXone
license: MIT
domain: infrastructure
subcategory: supply-chain
tags: [supply-chain, dependencies, install-hooks, cwe-494, cwe-506]
frameworks:
  cwe: [CWE-494, CWE-506]
  owasp_top10: [A06:2021, A08:2021]
  owasp_api_top10: []
  owasp_llm_top10: []
  owasp_wstg: []
  owasp_asvs: []
  mitre_attack: []
  mitre_atlas: []
  nist_csf: []
  nist_ai_rmf: []
related_skills: [secrets-detection, cloud-security, configuration-security, mcp-security, security-triage]
related_commands: [/axguard-supply, /axguard-audit]
related_rules: [supply.]
references:
  - https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/
  - https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/
  - https://cwe.mitre.org/data/definitions/494.html
  - https://cwe.mitre.org/data/definitions/506.html
last_reviewed: "2026-09-15"
---

# Supply Chain Security

## Purpose

Reason about **how code and dependencies enter the build** — malicious or untrusted install scripts, remote scripts piped to a shell, alternate package indexes, and missing integrity checks — before publish.

## When to Use

- Reviewing `package.json` lifecycle scripts, `requirements`/pip flags, Dockerfiles, CI install steps
- After `axguard` hits `supply.*`
- Onboarding a new dependency or private registry

## When Not to Use

- Dumping exploit payloads or weaponized packages into the repo
- Attacking public registries or other tenants’ packages

## Security Concepts

A06:2021 covers vulnerable/outdated components; A08:2021 covers integrity failures (unsigned updates, CI/CD tampering, insecure deserialization of updates). CWE-494 (download without integrity check) and CWE-506 (embedded malicious code in install paths) are common concrete shapes in app repos.

## Threat Model

Attacker goals:

1. Run arbitrary code at `npm install` / `pip install` via lifecycle hooks.
2. Redirect installs to a malicious index (dependency confusion / typosquat adjacency).
3. Land a foothold via `curl|bash` in Docker/CI/docs that operators actually run.
4. Persist through compromised maintainers or unsigned artifacts.

## Analysis Workflow

1. Run `axguard scan` / `audit`; collect `supply.*`.
2. Inspect package manifests for `preinstall` / `postinstall` / `install` scripts that fetch or eval remote code.
3. Search Dockerfiles, CI YAML, and `install.sh` for `curl|sh`, `wget|bash`, or equivalent.
4. Flag non-default indexes (`--extra-index-url`, untrusted registries) without auth + pinning.
5. Check lockfiles / hash pinning presence (npm lock, pip hashes, poetry.lock, go.sum).
6. Review whether CI verifies signatures/checksums before executing downloaded tools.
7. For AI/MCP tool packages, also apply `mcp-security` trust checks — still no payload dumps.

## Evidence Requirements

- Manifest or script path + line
- Whether the path runs in CI or user install (not docs-only)
- Integrity control present or absent (lockfile, hash, signature)
- Secret exposure in install scripts → escalate with `secrets-detection`

## False Positive Controls

- Documented example commands in README never invoked by CI/Dockerfile
- Benign `postinstall` that only runs local `tsc` / asset build with no network
- Official indexes only (`pypi.org`, default npm registry) with lockfiles
- Vendored scripts reviewed and pinned by hash in-repo

## Remediation

- Remove or audit install hooks; prefer packages without remote exec at install time.
- Pin versions + lockfiles; enable hash checking where the ecosystem supports it.
- Download, verify checksum/signature, then run from a reviewed local file — never pipe remote content to a shell.
- Use authenticated private registries; avoid dual-index confusion patterns.
- Monitor dependency advisories; rebuild on known-bad versions (A06 hygiene).

## Verification

Re-run `/axguard-supply` / `axguard audit`. Confirm install hooks and curl-pipe patterns are gone from ship paths. Spot-check lockfile freshness and registry configuration.

## Related Skills

`secrets-detection`, `configuration-security`, `mcp-security`, `security-triage`, `security-remediation`

## Framework Mapping

- CWE-494 Download of Code Without Integrity Check
- CWE-506 Embedded Malicious Code
- OWASP A06:2021 Vulnerable and Outdated Components
- OWASP A08:2021 Software and Data Integrity Failures

## References

- https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/
- https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/
- https://cwe.mitre.org/data/definitions/494.html
- https://cwe.mitre.org/data/definitions/506.html

## Research Provenance

Primary: OWASP Top 10:2021 A06/A08; CWE-494/506 (2026-09-15).  
Internal: AXGuard `rules/supply.json`, `/axguard-supply`.  
Secondary: Trivy / nuclei-templates / Semgrep methodology concepts only (no template or rule dumps).
