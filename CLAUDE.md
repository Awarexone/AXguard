# AXguard — Claude Code / agent plugin

Pre-ship security gate. Skills + slash commands for auditing source and build artifacts before publish.

## Install

```bash
git clone https://github.com/Awarexone/AXguard.git
cd AXguard
chmod +x install.sh
./install.sh
./install.sh --agent cursor
./install.sh --agent all
pip install -e .
```

## Start Using AXguard

| What you are doing | Start here |
|---|---|
| About to publish | `/axguard-audit` |
| Quick check while coding | `/axguard-scan` |
| New / unknown codebase | `/axguard-threat-model` → `/axguard-audit` |
| Secrets | `/axguard-secrets` |
| Auth / IDOR | `/axguard-auth` |
| Injection | `/axguard-inject` |
| SSRF | `/axguard-ssrf` |
| XSS | `/axguard-xss` |
| Cloud | `/axguard-cloud` |
| AI agent apps | `/axguard-agent` |
| Triage noise | `/axguard-triage` |
| Fix bugs | `/axguard-fix` |
| HTML/MD report | `/axguard-report` |
| CI gate | `/axguard-ci` |

Full catalog: [COMMANDS-QUICK-REF.md](COMMANDS-QUICK-REF.md) · [README.md](README.md)

## Pipeline

```text
threat-model → audit → triage → fix → report → ci
```

## Skills

| Skill | Role |
|---|---|
| `axguard-audit` | Pre-ship Lead — full A→Z |
| `axguard-cso` | Chief Security Officer — confidence-gated lead pass |
| `axguard-preship` | Focused checklist |
| `axguard-triage` | False-positive filter |
| `axguard-remediate` | Patch + re-audit |
| `axguard-report` | HTML/MD deliverables |
