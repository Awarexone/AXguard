---
description: AI agent / LLM app risks — exec of model output, unrestricted shell tools. Usage: /axguard-agent [path]
---

# /axguard-agent

**Specialist:** Agent Security

For apps built with AI agents, tool routers, or LLM-driven automation.

## Usage

```
/axguard-agent
```

## Focus

- Executing or `eval`ing model/assistant text
- Shell tools without allowlists
- Indirect prompt injection via retrieved docs (manual)

## Steps

1. Scan → keep `agent.*`.
2. Inventory tools the agent can call; mark destructive ones.
3. Require structured tool calls + human approval for mutate/egress.
