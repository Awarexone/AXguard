---
name: ai-application-security
description: Pre-ship security review for LLM-powered apps — RAG, chat APIs, output handling, and data exposure — without agent/tool focus.
version: "1.0.0"
author: AwareXone
license: MIT
domain: ai-security
subcategory: llm-apps
tags: [llm, rag, genai, output-handling]
frameworks:
  cwe: []
  owasp_top10: [A01:2021, A03:2021, A04:2021]
  owasp_api_top10: [API1:2023, API3:2023]
  owasp_llm_top10: [LLM01:2026, LLM02:2026, LLM09:2026, LLM10:2026]
  owasp_wstg: []
  owasp_asvs: []
  mitre_attack: []
  mitre_atlas: [AML.T0051, AML.T0093]
  nist_csf: []
  nist_ai_rmf: []
related_skills: [prompt-injection, ai-agent-security, mcp-security, secrets-detection, api-security]
related_commands: [/axguard-agent, /axguard-audit, /axguard-secrets]
related_rules: [agent., secrets.]
references:
  - https://genai.owasp.org/resource/owasp-genai-llm-top-10-2026/
  - https://www.nist.gov/itl/ai-risk-management-framework
  - https://owasp.org/Top10/A04_2021-Insecure_Design/
last_reviewed: "2026-09-15"
---

# AI Application Security

## Purpose

Provide a **defensive pre-ship checklist** for applications that embed LLMs (chat, RAG, summarization, copilots) focusing on trust boundaries, sensitive data in context, and unsafe handling of model output — before specializing into agents or MCP.

## When to Use

- Product features that call an LLM API or host a model
- RAG pipelines (ingest → embed → retrieve → generate)
- After high-level AI risk questions where tools/agency are limited or absent

## When Not to Use

- Apps with no model/prompt component
- Deep agent/tool RCE paths only — prefer `ai-agent-security` / `prompt-injection`
- Offensive jailbreak recipe generation

## Security Concepts

LLM apps mix **untrusted content** (users, documents, web) with **privileged context** (system prompts, PII, tenant data). Failures include leaking secrets via prompts/logs, retrieving chunks across tenants, rendering model HTML unsafely, and trusting model text as authorization. NIST AI RMF functions GOVERN / MAP / MEASURE / MANAGE apply conceptually to inventory and control lifecycle — subcategory IDs are not asserted here.

## Threat Model

Attacker goals:

1. Steal secrets or tenant data from prompts, logs, or retrieved chunks.
2. Poison or influence RAG corpora / uploads (integrity of inputs).
3. Trigger XSS or injection by reflecting model output into HTML/SQL/shell sinks.
4. Abuse unbounded calls for cost/DoS (rate and quota abuse).

## Analysis Workflow

1. Inventory AI surfaces: chat endpoints, batch jobs, RAG ingest, embedding stores, eval harnesses that hit prod data.
2. Map data classes entering prompts (PII, secrets, other tenants) and egress (logs, analytics, third-party model APIs).
3. Apply `prompt-injection` reasoning to any concatenation of untrusted text into privileged prompts.
4. Check authorization on retrieval: embeddings/search must enforce tenant/user ACLs **before** context assembly (API1/API3 adjacency).
5. Trace model output to sinks: HTML (`xss-analysis`), SQL, shell, `eval` — never trust “the model said it was safe.”
6. Review secret handling: API keys in client bundles → `secrets-detection`; redact prompts in logs.
7. Confirm rate limits, max tokens, and cost controls on public-facing generation endpoints.

## Evidence Requirements

- Prompt assembly and retrieval code locations
- AuthZ enforcement (or absence) on document/chunk access
- Output sink types and any server-side validation
- Model provider / logging destinations for sensitive context

## False Positive Controls

- Offline classification with no sensitive context and no user-facing rendering
- Strict structured outputs validated server-side against a schema, with no privileged side effects
- Synthetic demo data only in non-prod

## Remediation

- Minimize sensitive data in prompts; tokenize/redact; prefer retrieval scoped by auth.
- Treat retrieved documents as hostile; separate system instructions from content channels.
- Validate/encode model output for the sink context; authorize actions independently of model claims.
- Encrypt and ACL vector stores; avoid dumping embeddings as a substitute for access control.
- Align with NIST AI RMF-style MAP of assets and MANAGE of residual risk (process-level).

## Verification

Re-test with hostile documents and cross-tenant IDs; confirm no cross-ACL retrieval and no unsafe sink execution. Re-run `axguard audit` / `/axguard-agent` for overlapping `agent.*` hits.

## Related Skills

`prompt-injection`, `ai-agent-security`, `mcp-security`, `secrets-detection`, `security-remediation`

## Framework Mapping

- OWASP A01:2021 / A03:2021 / A04:2021
- OWASP API1:2023 / API3:2023
- OWASP LLM01:2026, LLM02:2026, LLM09:2026, LLM10:2026
- MITRE ATLAS AML.T0051, AML.T0093
- NIST AI RMF: GOVERN/MAP/MEASURE/MANAGE (conceptual; `nist_ai_rmf: []`)

## References

- https://genai.owasp.org/resource/owasp-genai-llm-top-10-2026/
- https://www.nist.gov/itl/ai-risk-management-framework
- https://owasp.org/Top10/A04_2021-Insecure_Design/

## Research Provenance

Primary: OWASP Top 10:2021; API Top 10:2023; LLM Top 10:2026 publication; ATLAS 2026.08; NIST AI RMF 1.0 (accessed 2026-09-15).  
Internal: AXGuard `rules/agent.json`, `/axguard-agent`.
