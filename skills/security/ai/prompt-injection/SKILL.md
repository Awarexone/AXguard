---
name: prompt-injection
description: Assess direct and indirect prompt-injection risks in LLM/AI features — use for chatbots, RAG, agents, and tool-calling apps.
version: "1.0.0"
author: AwareXone
license: MIT
domain: ai-security
subcategory: llm
tags: [prompt-injection, llm, rag, agent]
frameworks:
  cwe: []
  owasp_top10: []
  owasp_api_top10: []
  owasp_llm_top10: [LLM01:2026]
  owasp_wstg: []
  owasp_asvs: []
  mitre_attack: []
  mitre_atlas: [AML.T0051, AML.T0054, AML.T0056]
  nist_csf: []
  nist_ai_rmf: []
related_skills: [ai-agent-security, ai-application-security, mcp-security, security-triage]
related_commands: [/axguard-agent, /axguard-audit]
related_rules: [agent.]
references:
  - https://genai.owasp.org/resource/owasp-genai-llm-top-10-2026/
  - https://atlas.mitre.org/techniques/AML.T0051
last_reviewed: "2026-09-15"
---

# Prompt Injection

## Purpose

Reason about attacks where untrusted text steers model behavior — including **indirect** injection via retrieved documents or tool outputs.

## When to Use

- LLM chat, RAG, copilots, agents with tools
- After `agent.*` rule hits
- Features that concatenate user/doc content into system prompts

## When Not to Use

- Apps with no model/prompt component

## Security Concepts

Models follow instructions in context. If attacker content is mixed into trusted instructions, the model may exfiltrate data or invoke tools unsafely.

Mapped to **OWASP LLM01:2026 Prompt Injection** and MITRE ATLAS **AML.T0051** (related: jailbreak AML.T0054, system-prompt extraction AML.T0056).

## Analysis Workflow

1. Inventory prompts: system, developer, user, tool, retrieved chunks.
2. Find concatenation / template assembly of untrusted content into privileged prompts.
3. List tools the model can call (shell, HTTP, DB, file, email).
4. Ask: can retrieved content instruct “ignore previous” / exfiltrate secrets / trigger tools?
5. Check trust boundaries: is tool execution allowlisted? Human approval for mutate/egress?
6. Never execute model output as code (`eval`, shell) — cross-check `agent.*` rules.

## Evidence Requirements

- Prompt assembly locations
- Untrusted content sources (user, web, uploads, tickets)
- Privileged actions reachable via model decisions

## False Positive Controls

- Model used only for offline classification with no tools and no sensitive context
- Strict output schema with server-side enforcement (not just prompt requests)

## Remediation

- Separate trusted instructions from untrusted content; treat docs as hostile.
- Tool allowlists + typed args; no raw shell from model text.
- Output encoding / server-side authorization independent of model claims.
- Least-privilege credentials for tools.

## Verification

Re-test with hostile document/user content; confirm tools cannot be coerced; re-run `axguard audit`.

## Related Skills

`ai-agent-security`, `mcp-security`, `secrets-detection`, `security-remediation`

## Framework Mapping

- OWASP LLM Top 10:2026 — LLM01:2026 Prompt Injection
- MITRE ATLAS 2026.08 — AML.T0051, AML.T0054, AML.T0056
- NIST AI RMF 1.0 — GOVERN/MAP/MEASURE/MANAGE (conceptual)

## References

- https://genai.owasp.org/resource/owasp-genai-llm-top-10-2026/
- https://atlas.mitre.org/techniques/AML.T0051
- https://www.nist.gov/itl/ai-risk-management-framework

## Research Provenance

Primary: OWASP GenAI LLM Top 10 **2026** publication; MITRE ATLAS 2026.08 YAML (`AML.T0051` et al.); NIST AI RMF 1.0 (accessed 2026-09-15).  
Internal: AXGuard `rules/agent.json`, `/axguard-agent`.
