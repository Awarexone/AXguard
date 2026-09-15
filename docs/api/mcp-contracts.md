# MCP Contracts (design only)

MCP servers should treat this local API as the source of truth:

- Tools map to `/v1/*` resources (projects, scans, findings, attack-paths, twin, memory).
- Prefer deterministic engine results; LLM enrichment is optional and user-owned.
- Never embed AwareXone cloud credentials or hosted inference.

This document is a contract sketch — MCP implementation lives separately and is not required to use the API.
