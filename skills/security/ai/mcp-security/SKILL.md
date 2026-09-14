---
name: mcp-security
description: Review Model Context Protocol servers/clients and tool bridges for trust, supply-chain, and over-privileged tool exposure before ship.
version: "1.0.0"
author: AwareXone
license: MIT
domain: ai-security
subcategory: mcp
tags: [mcp, tools, supply-chain, agent]
frameworks:
  cwe: [CWE-494, CWE-78, CWE-94]
  owasp_top10: [A06:2021, A08:2021, A03:2021]
  owasp_api_top10: []
  owasp_llm_top10: [LLM03:2026, LLM04:2026]
  owasp_wstg: []
  owasp_asvs: []
  mitre_attack: []
  mitre_atlas: []
  nist_csf: []
  nist_ai_rmf: []
related_skills: [ai-agent-security, prompt-injection, supply-chain-security, secrets-detection, security-triage]
related_commands: [/axguard-agent, /axguard-supply, /axguard-audit]
related_rules: [agent., supply.]
references:
  - https://genai.owasp.org/resource/owasp-genai-llm-top-10-2026/
  - https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/
  - https://cwe.mitre.org/data/definitions/494.html
last_reviewed: "2026-09-15"
---

# MCP Security

## Purpose

Secure **Model Context Protocol (MCP)** and similar tool-bridge deployments: which servers are trusted, how tools are described and invoked, and how install/update integrity is enforced — defensive pre-ship only.

## When to Use

- Apps or IDE agents that load MCP servers / tool registries
- Reviewing MCP server implementations that expose filesystem, shell, DB, or HTTP tools
- After `agent.*` or `supply.*` hits near tool packaging

## When Not to Use

- Products with no MCP or equivalent external tool protocol
- Publishing malicious MCP servers or exploit payloads

## Security Concepts

MCP expands the agent attack surface: **third-party servers** are a supply chain; **tool descriptions** can carry indirect prompt injection; **broad tools** recreate unrestricted shell risks. Treat server identity, pin versions, and validate arguments like any privileged plugin system.

## Threat Model

Attacker goals:

1. Ship a malicious MCP server package (typosquat / compromised publisher).
2. Poison tool descriptions or resources so the model follows attacker instructions.
3. Abuse connected tools for local RCE, data theft, or SSRF.
4. Escalate via confused-deputy: user authorizes a benign server that later gains dangerous tools.

## Analysis Workflow

1. Inventory MCP clients/servers in the repo (configs, manifests, install docs).
2. Apply `supply-chain-security`: pin versions, verify checksums/signatures, avoid curl|sh installs of servers.
3. List tools each server exposes; classify side effects (read / write / egress / exec).
4. Ensure clients allowlist servers and tools; disable unused capabilities.
5. Inspect tool schemas: no free-form shell string if a typed API suffices; validate args server-side.
6. Check whether tool descriptions / resources are attacker-influable (user-edited markdown, remote URLs) → `prompt-injection`.
7. Confirm secrets for tools are scoped and not logged; cross-check `secrets-detection`.
8. Align runtime behavior with `ai-agent-security` approval gates for high-impact tools.

## Evidence Requirements

- MCP config paths and server identifiers
- Tool list with privilege notes
- Integrity controls on install/update
- Any path from tool output → privileged sink

## False Positive Controls

- Local first-party MCP server with reviewed code, pinned in lockfile, tools read-only and scoped
- Dev-only MCP disabled in production builds
- Documentation mentioning MCP without shipping a client

## Remediation

- Pin and verify MCP server packages; prefer first-party or vetted registries.
- Least-privilege tools; separate servers per trust domain.
- Sanitize/ignore untrusted tool metadata for instruction-like content; keep system policy outside tool text.
- Require explicit user consent when adding servers; show tool permissions clearly.
- Monitor and revoke compromised servers quickly (A06/A08 hygiene).

## Verification

Confirm production configs only load allowlisted, pinned servers. Re-run `/axguard-agent` and `/axguard-supply`. Hostile tool-description text must not unlock new tools or bypass approvals.

## Related Skills

`ai-agent-security`, `prompt-injection`, `supply-chain-security`, `secrets-detection`, `security-remediation`

## Framework Mapping

- CWE-494 / CWE-78 / CWE-94 as applicable to install and tool exec paths
- OWASP A03:2021 / A06:2021 / A08:2021
- OWASP LLM03:2026 Excessive Agency; LLM04:2026 Supply Chain

## References

- https://genai.owasp.org/resource/owasp-genai-llm-top-10-2026/
- https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/
- https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/
- https://cwe.mitre.org/data/definitions/494.html
- https://cwe.mitre.org/data/definitions/78.html

## Research Provenance

Primary: OWASP Top 10:2021 A03/A06/A08; CWE-494/78/94; OWASP LLM Top 10:2026 LLM03/LLM04 (accessed 2026-09-15).  
Internal: AXGuard `rules/agent.json`, `rules/supply.json`, `/axguard-agent`, `/axguard-supply`.
