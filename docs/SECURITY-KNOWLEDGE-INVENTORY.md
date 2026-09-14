# AXGuard Security Knowledge Inventory

Accessed: 2026-09-15  
Repo: https://github.com/Awarexone/AXguard  
Status: **30 core domain skills landed** (plus 7 orchestration skills)

## Orchestration skills (`skills/axguard-*`)

| Skill | Role |
|---|---|
| `axguard-audit` | Full A→Z audit driver |
| `axguard-preship` | Fast ship checklist |
| `axguard-cso` | Threat frame + go/no-go |
| `axguard-triage` | Keep/drop gates |
| `axguard-remediate` | Fix + re-audit |
| `axguard-report` | Report authoring |
| `axguard-knowledge` | Vuln-class digest → links to domain skills |

## Domain skills (`skills/security/`) — 30 core

### Discovery (3)
`threat-modeling`, `attack-surface-mapping`, `security-architecture-review`

### Identity (5)
`authentication-analysis`, `authorization-analysis`, `session-security`, `jwt-security`, `oauth-security`

### Application (12)
`api-security`, `sql-injection`, `xss-analysis`, `ssrf-analysis`, `ssti-analysis`, `command-injection`, `path-traversal`, `file-upload-security`, `deserialization-security`, `prototype-pollution`, `graphql-security`, `websocket-security`

### Infrastructure (4)
`secrets-detection`, `cloud-security`, `configuration-security`, `supply-chain-security`

### AI (4)
`ai-application-security`, `prompt-injection`, `ai-agent-security`, `mcp-security`

### Operations (2)
`security-triage`, `security-remediation`

Registry: [`skills/index.yaml`](../skills/index.yaml)  
Schema: [`docs/SKILL-SCHEMA.md`](SKILL-SCHEMA.md)  
Validator: `python scripts/validate_skills.py`

## Commands / rules / engines (unchanged architecture)

- Commands: `/axguard-*` specialists + ops
- Rules: secrets, auth, injection, sql, ssti, path, ssrf, xss, cloud, crypto, supply, graphql, upload, debug, agent, advanced
- Engines: regex SAST + audit phases + MD/HTML/JSON reports

## Provenance layer (`references/`)

| File | Contents |
|---|---|
| `sources.yaml` | Primary frameworks + AwareXone + HF notes |
| `repositories.yaml` | AwareXone + methodology GitHub repos |
| `datasets.yaml` | HF datasets (metadata / derived knowledge only) |
| `frameworks/README.md` | Verified OWASP/CWE ID tables |

## Design decisions

1. Keep `axguard-*` orchestration; add domain depth under `skills/security/`.
2. Never invent framework IDs; leave arrays empty when UNVERIFIED (e.g. LLM Top 10 frontmatter).
3. Defensive / authorized pre-ship use only.
4. Install flattens domain skills by basename via `install_security_skills` in `install.sh`.

## Next high-value expansions (ranked, not auto-created)

csrf-analysis, cors-security, cryptography-review, cicd-security, container-security, business-logic-security, race-condition-analysis, xml-security / XXE (CWE-611).
