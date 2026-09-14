---
name: ai-agent-security
description: Review AI agents with tools — shell, HTTP, files, browsers — for excessive agency, unsafe exec of model output, and missing human gates (CWE-78 / CWE-94).
version: "1.0.0"
author: AwareXone
license: MIT
domain: ai-security
subcategory: agents
tags: [agent, tools, excessive-agency, cwe-78, cwe-94]
frameworks:
  cwe: [CWE-78, CWE-94]
  owasp_top10: [A03:2021, A04:2021]
  owasp_api_top10: []
  owasp_llm_top10: [LLM01:2026, LLM03:2026]
  owasp_wstg: []
  owasp_asvs: []
  mitre_attack: []
  mitre_atlas: [AML.T0051]
  nist_csf: []
  nist_ai_rmf: []
related_skills: [prompt-injection, mcp-security, ai-application-security, command-injection, secrets-detection]
related_commands: [/axguard-agent, /axguard-audit, /axguard-inject]
related_rules: [agent.]
references:
  - https://genai.owasp.org/resource/owasp-genai-llm-top-10-2026/
  - https://cwe.mitre.org/data/definitions/78.html
  - https://cwe.mitre.org/data/definitions/94.html
last_reviewed: "2026-09-15"
---

# AI Agent Security

## Purpose

Assess **agents that can act** — tool-calling loops with shell, filesystem, network, email, or code execution — focusing on least privilege, approval gates, and never treating model text as trusted code.

## When to Use

- LangChain/LlamaIndex/OpenAI-tools style agents, IDE copilots with terminal, browser agents
- After `axguard` hits `agent.*`
- Any feature where model output selects or parameterizes privileged actions

## When Not to Use

- Pure chat/RAG without tools (use `ai-application-security` / `prompt-injection`)
- Writing offensive agent jailbreaks or exploit PoCs

## Security Concepts

Excessive agency appears when tools are broad (unrestricted shell), credentials are over-scoped, or autonomy lacks human approval for mutate/egress. Prompt injection (direct or via documents/tool output) becomes high impact when tools exist. Executing model output via `eval` / `subprocess` / `child_process` is classic CWE-94 / CWE-78.

## Threat Model

Attacker goals:

1. Coerce the agent to run shell commands or exfiltrate secrets.
2. Abuse HTTP tools for SSRF into cloud metadata or intranet.
3. Overwrite files, exfiltrate repos, or send emails as the victim.
4. Chain tool outputs (indirect injection) to escalate in the next loop turn.

## Analysis Workflow

1. Run `axguard scan` / `audit`; collect `agent.*` (and related `injection.*`, `ssrf.*`, `secrets.*`).
2. Inventory tools: name, side effects (read/write/egress/exec), argument schema, who can invoke.
3. Confirm model text never flows into `eval`, `exec`, `os.system`, or `shell=True` without a hard allowlist intermediary.
4. Check allowlists: commands, hosts, paths, HTTP methods; deny-by-default.
5. Require human approval (or strong policy engine) for destructive and egress actions.
6. Apply `prompt-injection` to tool descriptions, retrieved docs, and tool results re-entering context.
7. Ensure tool credentials are least-privilege and not the developer’s personal cloud keys.
8. Cross-check MCP-exposed tools with `mcp-security`.

## Evidence Requirements

- Tool registration sites and permission scope
- Code path from model/tool args → sink
- Presence or absence of allowlist + approval gate
- Secret material reachable by tools

## False Positive Controls

- Tools that only call typed internal APIs with server-side authZ independent of the model
- Dry-run / plan-only agents with no execution backend enabled in prod
- Shell tool strings that are fully static and unreachable from model args (still prefer removal)

## Remediation

- Replace shell tools with narrow typed actions; sandbox where shell is unavoidable.
- Structured tool calls + schema validation; reject unknown tools/args.
- Human-in-the-loop for high impact; session budget limits (steps, tokens, spend).
- Separate privileges: retrieval identity ≠ mutate identity ≠ egress identity.
- Never `exec` model output; treat all natural-language “code” as untrusted.

## Verification

Hostile prompt + hostile document tests should fail closed (no shell, no secret egress). Re-run `/axguard-agent`. Confirm approval gates cannot be skipped via prompt text alone.

## Related Skills

`prompt-injection`, `mcp-security`, `ai-application-security`, `command-injection`, `ssrf-analysis`, `security-remediation`

## Framework Mapping

- CWE-78 OS Command Injection
- CWE-94 Improper Control of Generation of Code ('Code Injection')
- OWASP A03:2021 Injection; A04:2021 Insecure Design
- OWASP LLM01:2026 Prompt Injection; LLM03:2026 Excessive Agency
- MITRE ATLAS AML.T0051

## References

- https://genai.owasp.org/resource/owasp-genai-llm-top-10-2026/
- https://cwe.mitre.org/data/definitions/78.html
- https://cwe.mitre.org/data/definitions/94.html
- https://www.nist.gov/itl/ai-risk-management-framework

## Research Provenance

Primary: CWE-78/94; OWASP Top 10:2021 A03/A04; OWASP LLM Top 10:2026 (LLM01/LLM03); ATLAS 2026.08 AML.T0051 (accessed 2026-09-15).  
Internal: AXGuard `rules/agent.json`, `/axguard-agent`.
