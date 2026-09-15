<p align="center">
  <img src="assets/cover.jpg" alt="AXguard by AwareXone — open-source AI security tool to scan and fix vulnerabilities in vibe-coded apps before you ship" width="100%"/>
</p>

# AXguard

> **Open-source AI security tool to scan and fix vulnerabilities in your vibe-coded apps before you ship.**
>
> **AXguard by [AwareXone](https://awarexone.com/)**

### Built by [Shuvonsec](https://github.com/shuvonsec)

AXguard is built by **[Shuvonsec](https://github.com/shuvonsec)** — Ethical hacker and security researcher. He ranked **#1 worldwide** on the TryHackMe monthly leaderboard in 2025. He works on AI security and cybersecurity agents, and builds open-source tools to make AI-built applications safer.

<p align="center">
  <a href="https://github.com/shuvonsec">
    <img src="assets/shuvonsec-contributions.png" alt="Shuvonsec GitHub contributions — open-source security work across the year" width="100%"/>
  </a>
</p>

<p align="center">
  <a href="https://github.com/shuvonsec"><img src="https://img.shields.io/badge/GitHub-shuvonsec-181717?style=flat-square&logo=github" alt="shuvonsec on GitHub"></a>
  <a href="https://shuvonsec.com"><img src="https://img.shields.io/badge/Web-shuvonsec.com-3dd6c6?style=flat-square" alt="shuvonsec.com"></a>
  <a href="https://awarexone.com/"><img src="https://img.shields.io/badge/AwareXone-awarexone.com-0c1117?style=flat-square" alt="AwareXone"></a>
</p>

[![MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)
[![Version](https://img.shields.io/badge/version-0.2.0-purple.svg)](#)
[![CI](https://github.com/Awarexone/AXguard/actions/workflows/ci.yml/badge.svg)](https://github.com/Awarexone/AXguard/actions/workflows/ci.yml)
[![CodeQL](https://github.com/Awarexone/AXguard/actions/workflows/codeql.yml/badge.svg)](https://github.com/Awarexone/AXguard/actions/workflows/codeql.yml)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/Awarexone/AXguard/badge)](https://scorecard.dev/viewer/?uri=github.com/Awarexone/AXguard)
[![Claude Code](https://img.shields.io/badge/Claude%20Code-plugin-black.svg)](https://claude.ai/claude-code)
[![Cursor](https://img.shields.io/badge/Cursor-skills-black.svg)](https://cursor.com/)

**CLI + AI agent plugin for Claude Code, Cursor, OpenCode, Codex, and shared Agent Skills.**

Pre-ship security gate — not a full pentest platform. Scan source, triage noise, fix what matters, and gate releases before you publish.

[Website](https://awarexone.com/) · [GitHub](https://github.com/Awarexone) · [X](https://x.com/awarexone) · [Dev Docs](DEV.md) · [Commands](COMMANDS-QUICK-REF.md)

**Contact:** [hello@awarexone.com](mailto:hello@awarexone.com) · [b2b@awarexone.com](mailto:b2b@awarexone.com) · [shuvon@awarexone.com](mailto:shuvon@awarexone.com)

---

## What is AXguard?

**AXguard is a pre-ship security gate.**

Before you publish an app — especially one built with AI — AXguard checks your code for common security problems, helps you fix them, and writes clear reports.

It ships as:

* A **standalone CLI** (`axguard`)
* An **AI agent plugin** (skills + slash commands for Claude Code, Cursor, OpenCode, Codex, and shared Agent Skills)
* An optional **local-first Security Intelligence API** (`axguard api start` → `http://127.0.0.1:8787`) — no AwareXone account or hosted LLM; use **no-llm** (default), Ollama/local, or BYOK (`pip install -e '.[api]'`). See [docs/api/overview.md](docs/api/overview.md).

```text
AI builds it → AXguard checks it → You fix it → You ship it
```

Source scanning is current. Artifact/bytecode scanners (JS bundles, WASM, etc.) are planned — see [CONTRIBUTING.md](CONTRIBUTING.md).

---

## Why AXguard?

AI tools can build an app in minutes. They can also ship security bugs in minutes.

AXguard sits between:

```text
"the AI built it"
        ↓
     AXguard
        ↓
"we shipped it"
```

Built for developers, founders, security engineers, and teams that want a simple security checkpoint — without a heavy enterprise setup.

---

## Workflow

```text
threat-model → audit → triage → fix → re-scan → report → CI
```

| Step | What happens |
|---|---|
| **threat-model** | Map the app, trust boundaries, and likely risks before a deep pass. |
| **audit** | Run the full pre-ship scan and write HTML / MD / JSON plus diagnostics. |
| **triage** | Drop false positives; keep confirmed and likely issues. |
| **fix** | Patch confirmed bugs with remediation guidance. |
| **re-scan** | Re-run scan/audit to verify the fix held. |
| **report** | Produce a shareable security report for PRs and stakeholders. |
| **CI** | Fail the pipeline on high/critical so regressions do not ship. |

---

## Quick Start

### 1. Install the plugin

```bash
git clone https://github.com/Awarexone/AXguard.git
cd AXguard

chmod +x install.sh uninstall.sh
./install.sh
```

For Cursor:

```bash
./install.sh --agent cursor
```

For all supported agents:

```bash
./install.sh --agent all
```

Supported install targets (`./install.sh --agent …`): **claude**, **cursor**, **opencode**, **codex**, **agents** (shared Agent Skills), and **all**.

### 2. Install the CLI

```bash
python3 -m venv .venv
source .venv/bin/activate

pip install -e .

axguard help
axguard audit .
```

Open the report:

```bash
open .findings/axguard/axguard-report.html
```

| | |
|---|---|
| Package | `axguard` |
| Version | `0.2.0` |
| Python | `3.10+` |
| License | MIT |

---

## Start Using AXguard

> **Start with the workflow you need, not the full list.**

| What are you doing? | Start here |
|---|---|
| About to ship | `/axguard-audit` |
| Quick check while coding | `/axguard-scan` |
| New or unknown codebase | `/axguard-threat-model` |
| Map attack surface / app model | `/axguard-surface` |
| Dataflow / taint paths | `/axguard-flow` |
| Hunter → Judge verification | `/axguard-verify` |
| False-positive adversary | `/axguard-adversary` |
| Evidence & confidence | `/axguard-evidence` |
| Attack graph / vuln chaining | `/axguard-paths` |
| AI-generated / agent app | `/axguard-agent` |
| Looking for leaked keys | `/axguard-secrets` |
| Auth / IDOR issues | `/axguard-auth` |
| Injection / RCE | `/axguard-inject` |
| SQL injection | `/axguard-sql` |
| SSTI | `/axguard-ssti` |
| Path traversal / LFI | `/axguard-path` |
| SSRF | `/axguard-ssrf` |
| XSS | `/axguard-xss` |
| Cloud / CORS | `/axguard-cloud` |
| Crypto misuse | `/axguard-crypto` |
| Supply chain | `/axguard-supply` |
| GraphQL | `/axguard-graphql` |
| File upload | `/axguard-upload` |
| Debug / error leaks | `/axguard-debug` |
| Too many findings | `/axguard-triage` |
| Fix confirmed bugs | `/axguard-fix` |
| Need a report | `/axguard-report` |
| Add a CI gate | `/axguard-ci` |
| Training-data pipeline | `/axguard-data` |
| Contribute (local, opt-in) | `/axguard-contribute` |
| Privacy prefs (local) | `/axguard-privacy` |
| Security Twin | `axguard twin build .` → [docs/twin](docs/twin/README.md) |
| Security Memory | `axguard memory record .` → [docs/memory](docs/memory/README.md) |
| Investigation Agent | `axguard investigate .` → [docs/investigation](docs/investigation/README.md) |
| Predictive security risk | `axguard predict .` → [docs/predictive](docs/predictive/README.md) |
| Local Security Intelligence API | `axguard api start` → [docs/api](docs/api/overview.md) |
| GitHub PR bot (self-host) | `axguard github setup` → [docs/github](docs/github/README.md) |
| Full security-lead pass | skill `axguard-cso` |
| Short pre-ship checklist | skill `axguard-preship` |

See the [command cheat sheet](COMMANDS-QUICK-REF.md).

---

## Commands & Specialists

Each command has a clear job. Slash commands install via `./install.sh`; most also have a CLI equivalent.

| Command | Specialist | Key CLI | What it does |
|---|---|---|---|
| `/axguard-audit` | Pre-ship Lead | `axguard audit .` | Full audit + HTML / MD / JSON (+ diagnostics) |
| `/axguard-scan` | Scanner | `axguard scan .` | Fast check while you code |
| `/axguard-threat-model` | CSO | — | Map risks before a deep scan |
| `/axguard-surface` | Surface Mapper | `axguard surface .` | Application model (routes, sinks, stack) |
| `/axguard-flow` | Dataflow | `axguard flow .` | Dataflow / taint paths (diagnostic) |
| `/axguard-verify` | Verifier | `axguard verify .` | Hunter → Judge verification (diagnostic) |
| `/axguard-adversary` | FP Adversary | `axguard adversary .` | False-positive adversary (diagnostic) |
| `/axguard-evidence` | Evidence | `axguard evidence .` | Evidence & confidence (diagnostic) |
| `/axguard-paths` | Attack Graph | `axguard paths .` | Attack graph + vuln chaining (diagnostic) |
| `/axguard-secrets` | Secrets Hunter | — | Find keys and credentials |
| `/axguard-auth` | Access Control | — | Auth, IDOR, JWT, CSRF |
| `/axguard-inject` | Injection Hunter | — | Injection and RCE patterns |
| `/axguard-sql` | SQL Hunter | — | SQL / ORM injection sinks |
| `/axguard-ssti` | Template Hunter | — | Server-side template injection |
| `/axguard-path` | Path Hunter | — | Traversal / LFI / dynamic includes |
| `/axguard-ssrf` | Egress Hunter | — | Unsafe outbound requests |
| `/axguard-xss` | Client Security | — | Dangerous XSS sinks |
| `/axguard-cloud` | Cloud Reviewer | — | Cloud and CORS issues |
| `/axguard-crypto` | Crypto Reviewer | — | Weak hashing, hard-coded keys, TLS verify-off |
| `/axguard-supply` | Supply Chain | — | Install hooks, curl\|sh, untrusted indexes |
| `/axguard-graphql` | GraphQL Reviewer | — | Introspection / CSRF footguns |
| `/axguard-upload` | Upload Hunter | — | Unsafe file upload patterns |
| `/axguard-debug` | Debug Hunter | — | DEBUG mode, stack traces, actuators |
| `/axguard-agent` | Agent Security | — | AI-agent and LLM risks |
| `/axguard-triage` | Triage Lead | — | Cut noise, keep real issues |
| `/axguard-fix` | Remediation | — | Fix and re-check |
| `/axguard-report` | Report Author | — | Clean security reports |
| `/axguard-ci` | Release Gate | `axguard audit . --fail-on high` | Fail CI on high / critical |
| `/axguard-data` | Data Pipeline | `axguard data …` | Training-data registry & pipeline |
| `/axguard-contribute` | Contributor | `axguard contribute …` | Local contribution suggest/prepare (no auto-push) |
| `/axguard-privacy` | Privacy | `axguard privacy …` | Local opt-in / export / delete prefs |
| skill `axguard-cso` | Chief Security Officer | — | End-to-end security pass |
| skill `axguard-preship` | Release Reviewer | — | Short pre-ship checklist |

---

## Which workflow?

| Situation | Start with | Then |
|---|---|---|
| Shipping soon | `/axguard-audit` | `/axguard-triage` → `/axguard-fix` → re-scan |
| AI-built app | `/axguard-agent` | `/axguard-audit` |
| Auth-heavy API | `/axguard-auth` | `/axguard-audit` |
| New codebase | `/axguard-threat-model` | `/axguard-surface` → `/axguard-audit` |
| Noisy results | `/axguard-triage` or `/axguard-adversary` | `/axguard-fix` |
| Need a shareable report | `/axguard-report` | Open the HTML |
| Want CI protection | `/axguard-ci` | Add it to your pipeline |

---

## CLI

**No AI agent required.**

```bash
axguard help
axguard version
axguard about
axguard engage disable|enable|dismiss

# Scan & audit
axguard scan .
axguard scan . --format json -o out.json
axguard audit .
axguard audit . --fail-on high
axguard audit . --fail-on high --out-dir .findings/axguard --no-banner
axguard audit . --open-summary

# Diagnostics (not vuln reports)
axguard surface .
axguard flow .
axguard verify .
axguard adversary .
axguard evidence .
axguard paths .              # alias: axguard attack-paths .
axguard paths . --current --critical --shortest
axguard paths . --predictive
axguard paths . --what-if remove_authz

# Security Twin (symbolic model; local)
axguard twin build .
axguard twin show .
axguard twin attack .
axguard twin blast-radius . --entity ENTITY
axguard twin controls .
axguard twin what-if .
axguard twin compare .
axguard twin regression .
axguard twin query .
axguard twin scenarios
axguard twin export-dataset .

# Security Memory (longitudinal; local)
axguard memory record .
axguard memory show
axguard memory history
axguard memory changes
axguard memory regressions
axguard memory findings
axguard memory controls
axguard memory paths
axguard memory unknowns
axguard memory query "what changed"

# Investigation Agent
axguard investigate .
axguard investigate . --fast
axguard investigate . --deep
axguard investigate . --finding FINDING_ID
axguard investigate --explain FINDING_ID

# Predictive security (risk signals — not confirmed findings)
axguard predict .
axguard predict --pr --base ./base-checkout
axguard predict --architecture
axguard predict --agent
axguard predict --mcp
axguard predict --what-if

# Training-data pipeline (no model training)
axguard data discover
axguard data inspect
axguard data report fixtures/data_pipeline

# Contribute / privacy (local prefs; no telemetry by default)
axguard privacy status
axguard privacy opt-in
axguard privacy opt-out
axguard privacy export
axguard contribute status
axguard contribute suggest
axguard contribute prepare

# Optional GitHub Security Bot adapter
axguard github setup .
axguard github validate .
axguard github test .
axguard github status .

# Local Security Intelligence API (optional extra: pip install -e '.[api]')
axguard api start
axguard api status
axguard api projects
axguard api keys list

open .findings/axguard/axguard-report.html
```

Common flags on scan/audit: `--fail-on {critical,high,medium,low,none}`, `--rules DIR`, `--no-banner`, `--no-engage`. Audit also accepts `--out-dir` and `--open-summary`. Scan also accepts `--format {text,json,md,html}` and `-o` / `--output`.

Docs: [docs/twin](docs/twin/README.md) · [docs/memory](docs/memory/README.md) · [docs/investigation](docs/investigation/README.md) · [docs/predictive](docs/predictive/README.md) · [docs/api](docs/api/overview.md) · [docs/github](docs/github/README.md) · [docs/contributors](docs/contributors/README.md) · [docs/engagement.md](docs/engagement.md)

---

## What it finds

Detections come from `rules/*.json` (deterministic pattern/heuristic rules).

| Area | Examples (from shipped rules) |
|---|---|
| **Secrets** | AWS access keys, hard-coded API key assignments, PEM private keys, GitHub PATs, Slack tokens |
| **Auth** | Missing ownership heuristics (IDOR-style), JWT `none`, JWT decode-without-verify, CSRF disabled |
| **Injection / RCE** | `eval` / `exec`, `pickle.loads`, `subprocess(shell=True)`, `os.system` / `popen`, JS `child_process.exec`, PHP `unserialize`, Java `ObjectInputStream` |
| **SQL / NoSQL** | String-built SQL (Python/JS/PHP), ORM raw SQL, Mongo `$where` / operator injection |
| **SSTI** | Jinja2 / Flask `render_template_string`, dynamic Pug compile |
| **Path / LFI** | User paths in `open` / `send_file` / PHP `include` |
| **SSRF** | Variable URLs in Python HTTP clients / JS `fetch` concatenation |
| **XSS** | `innerHTML`, `document.write`, React `dangerouslySetInnerHTML` |
| **Upload** | Original client filenames saved, Multer `.any()` |
| **Crypto** | Hard-coded keys/IVs, MD5/SHA1 near passwords, `Math.random` tokens, TLS verify off |
| **Supply chain** | Risky npm install scripts, pip extra indexes, `curl\|sh` |
| **GraphQL** | Introspection left on, CSRF prevention off |
| **Debug** | Django/Flask debug, Express stack handlers, Spring Actuator hints |
| **Cloud** | AWS metadata URLs, wildcard CORS + credentials, public S3 ACL |
| **AI agents** | Executing model/agent output, unrestricted shell tools, prompt/tool-arg shell execution |

---

## Reports

Every full audit writes **primary** vulnerability reports:

```text
.findings/axguard/
├── axguard-report.html   # easy to read
├── axguard-report.md     # for PRs and docs
└── axguard-report.json   # for CI and tools
```

The same audit also writes **diagnostic** artifacts (not the primary vuln report):

```text
.findings/axguard/
├── application-model.{json,md}   # surface / app model
├── dataflow.{json,md}            # taint / dataflow paths
├── verification.{json,md}        # Hunter → Judge
├── adversary.{json,md}           # false-positive adversary
├── final-findings.json           # post-adversary finding statuses
├── evidence.{json,md}            # evidence & confidence
├── attack-paths.{json,md}        # attack graph / chaining
├── memory/                       # soft Security Memory snapshot (best-effort)
└── investigation/                # soft Investigation Agent pass (best-effort)
```

A full audit may also embed a twin **summary** in the main report; full `security-twin.*` files come from `axguard twin …` (default under `.findings/axguard/twin/`). Dedicated commands can write more under `predictive/`, `data/`, and `contribute/`.

---

## CI / Release Gate

```text
Code → AXguard → High/Critical?
                 ├── Yes → Fix → Re-scan
                 └── No  → Ship
```

Example for your app:

```bash
axguard audit . --fail-on high --no-banner
```

### What this repository runs

[`.github/workflows/axguard.yml`](.github/workflows/axguard.yml) dogfoods **runtime code only** (`engines/` and `cli/`). Fixtures, skills, commands, and rules intentionally contain vulnerable examples for regression tests and are excluded:

```bash
axguard audit engines --fail-on high --no-banner
axguard audit cli --fail-on high --no-banner
```

---

## GitHub Security Bot

Optional GitHub App that reviews pull requests with Check Runs and one updatable summary comment. Runs AXGuard Core behind a thin webhook adapter (`engines/github/`). Local CLI scanning does **not** require it.

### Add the bot to a repository

**A. GitHub App (Check Runs + PR comment)** — preferred when you can self-host:

1. Create a GitHub App with the permissions in [docs/github/permissions.md](docs/github/permissions.md).
2. Install it on **Only select repositories** (e.g. this repo).
3. Point the webhook at your adapter and export credentials (never commit them):

```bash
export AXGUARD_GITHUB_APP_ID=…
export AXGUARD_GITHUB_WEBHOOK_SECRET=…
export AXGUARD_GITHUB_PRIVATE_KEY_PATH=/path/to/app.pem
```

4. In the target repo:

```bash
axguard github setup .          # writes .axguard.yml (no secrets)
axguard github validate .
# run the adapter — see docs/github/self-hosting.md
axguard github status .
```

**B. Actions-only (no webhook host)** — what this repository uses in CI:

```bash
# .github/workflows/axguard.yml on pull_request / push to main:
axguard audit engines --fail-on high --no-banner
axguard audit cli --fail-on high --no-banner
```

That path runs Core in CI; it does not replace App Check Runs unless you also wire the App.

### CLI

```bash
axguard github setup .
axguard github validate .
axguard github test .
axguard github status .
```

- Install & permissions: [docs/github/install.md](docs/github/install.md) · [docs/github/permissions.md](docs/github/permissions.md)
- Config (`.axguard.yml`): [docs/github/config.md](docs/github/config.md)
- Self-host (preferred): [docs/github/self-hosting.md](docs/github/self-hosting.md)
- Privacy / AI: [docs/github/privacy.md](docs/github/privacy.md) · [docs/github/ai-providers.md](docs/github/ai-providers.md)
- Architecture research: [docs/research/github-security-bot.md](docs/research/github-security-bot.md)
- Marketplace prep only (no approval claimed): [docs/github/marketplace.md](docs/github/marketplace.md)

---

## Predictive Security

Predict **security risk expansion** from observable changes — not CVEs, not guaranteed future bugs. Separates Verified Issues from Predictive Risks.

```bash
axguard predict .
axguard predict --pr --base ./base-checkout
axguard predict --architecture
axguard predict --agent
axguard predict --mcp
axguard predict --what-if
```

- Guide: [docs/predictive/README.md](docs/predictive/README.md)
- Research: [docs/research/predictive-security.md](docs/research/predictive-security.md)

---

## Built for vibe-coded apps

AI can generate an app quickly. Security review should still happen before you publish.

```text
AI builds it
     ↓
AXguard checks it
     ↓
You fix it
     ↓
AXguard checks again
     ↓
You ship it
```

Use `/axguard-agent` when the app gives models access to shells, files, APIs, or tools.

---

## AwareXone

AXguard is built by **[AwareXone](https://awarexone.com/)**.

We build open-source security tools for the AI era — for people who **build** and people who **hunt**.

```text
BUILD                         HUNT
  │                             │
AXguard                 Agentic Bug Hunter
  │                             │
Secure what you create   Find bugs that are live
```

> **Same security DNA. Different job.**

### Agentic Bug Hunter

<p align="center">
  <a href="https://github.com/Awarexone/Agentic-Bug-Hunter">
    <img src="assets/agentic-bug-hunter-banner.jpg" alt="Agentic Bug Hunter by AwareXone — AI-powered bug bounty hunting toolkit" width="100%"/>
  </a>
</p>

**AI-powered bug bounty toolkit** ([4.8k+ stars](https://github.com/Awarexone/Agentic-Bug-Hunter)).

Point it at a live target. It helps you recon, find vulnerabilities, validate findings, and write reports. Claude Code plugin + standalone `bughunter` CLI.

→ [github.com/Awarexone/Agentic-Bug-Hunter](https://github.com/Awarexone/Agentic-Bug-Hunter)

### More from AwareXone

| Tool | What it is |
|---|---|
| [**Agentic Bug Hunter**](https://github.com/Awarexone/Agentic-Bug-Hunter) | AI bug bounty toolkit |
| [**Public Skills Builder**](https://github.com/Awarexone/public-skills-builder) | Turn public security research into reusable skills |
| [**Web3 Bug Bounty AI Skills**](https://github.com/Awarexone/web3-bug-bounty-hunting-ai-skills) | Smart-contract and DeFi security skills |

[awarexone.com](https://awarexone.com/) · [GitHub](https://github.com/Awarexone) · [X @AwareXone](https://x.com/awarexone)

Beyond open-source tools, AwareXone also builds AI-driven defenses against scams, fraud, and social engineering, and provides human-risk security services for organizations.

| | |
|---|---|
| General | [hello@awarexone.com](mailto:hello@awarexone.com) |
| Business / B2B | [b2b@awarexone.com](mailto:b2b@awarexone.com) |
| Founder | [shuvon@awarexone.com](mailto:shuvon@awarexone.com) |

→ [Get in touch](https://awarexone.com/)

---

## Project structure

```text
AXguard/
├── cli/                 # axguard CLI entrypoints
├── engines/             # scanners, diagnostics, adapters
├── rules/               # detection rule packs (*.json)
├── commands/            # slash-command markdown
├── skills/              # orchestration + domain skills
├── fixtures/            # vuln / safe regression apps
├── tests/               # pytest suite
├── docs/                # architecture, API, twin, memory, …
├── references/          # framework / dataset provenance
├── scripts/             # validation helpers
├── data/                # data-pipeline seeds / fixtures
├── assets/              # README images
├── install.sh           # agent plugin installer
├── uninstall.sh
├── pyproject.toml
├── COMMANDS-QUICK-REF.md
├── DEV.md
├── CONTRIBUTING.md
└── LICENSE
```

---

## Developer Docs

| Doc | For |
|---|---|
| [DEV.md](DEV.md) | Setup and day-to-day development |
| [COMMANDS-QUICK-REF.md](COMMANDS-QUICK-REF.md) | Slash + CLI cheat sheet |
| [docs/architecture.md](docs/architecture.md) | How the scanner works |
| [docs/attack-graph.md](docs/attack-graph.md) | Attack-graph diagnostics |
| [docs/github/README.md](docs/github/README.md) | GitHub Security Bot (App adapter) |
| [docs/predictive/README.md](docs/predictive/README.md) | Predictive security intelligence |
| [docs/api/overview.md](docs/api/overview.md) | Local Security Intelligence API |
| [docs/twin/README.md](docs/twin/README.md) | Security Twin |
| [docs/memory/README.md](docs/memory/README.md) | Security Memory |
| [docs/investigation/README.md](docs/investigation/README.md) | Investigation Agent |
| [docs/data/README.md](docs/data/README.md) | Training-data pipeline |
| [docs/contributors/README.md](docs/contributors/README.md) | Contribute / privacy (local, opt-in) |
| [docs/engagement.md](docs/engagement.md) | Engagement prefs (no telemetry) |
| [docs/adding-rules.md](docs/adding-rules.md) | Adding detections |
| [docs/plugin.md](docs/plugin.md) | Agent plugin setup |
| [docs/SKILL-SCHEMA.md](docs/SKILL-SCHEMA.md) | Domain skill frontmatter + sections |
| [docs/SECURITY-KNOWLEDGE-INVENTORY.md](docs/SECURITY-KNOWLEDGE-INVENTORY.md) | Knowledge-layer inventory |
| [skills/index.yaml](skills/index.yaml) | Skill registry (30 core + orchestration) |
| [references/](references/) | Framework / repo / dataset provenance |
| [CONTRIBUTING.md](CONTRIBUTING.md) | Contributing to AXguard |
| [CONTRIBUTORS.md](CONTRIBUTORS.md) | Contributors |
| [skills/axguard-knowledge/](skills/axguard-knowledge/SKILL.md) | Vuln-class knowledge pack |

---

## Security knowledge layer

AXguard pairs a **deterministic CLI scanner** with a **research-backed skill system** so agents can reason, not just match regexes.

```text
Frameworks (OWASP / CWE / …)
        ↓
references/ (provenance index)
        ↓
skills/security/* (30 core domain skills)
        ↓
skills/axguard-* (orchestration: audit → triage → fix → report)
        ↓
commands/ + rules/ + CLI
```

- **Orchestration skills** drive workflows (`/axguard-audit`, triage, remediate).
- **Domain skills** teach source→sink analysis, evidence gates, FP controls, and fixes per class (SSRF, SQLi, authZ, prompt injection, MCP, …).
- **Provenance** lives in `references/` — cite official IDs only; no invented CWE/OWASP mappings; HF datasets are metadata/derived-knowledge only.
- Validate with: `python scripts/validate_skills.py`

---

## Security checks

AXGuard checks *your* apps before ship. This repository also runs automated checks on itself:

| Check | Workflow |
|---|---|
| CI tests + fixture self-scan | [`ci.yml`](.github/workflows/ci.yml) |
| AXGuard Security Review (PR bot / Core) | [`axguard.yml`](.github/workflows/axguard.yml) |
| CodeQL (Python) | [`codeql.yml`](.github/workflows/codeql.yml) |
| Secret detection (Gitleaks) | [`gitleaks.yml`](.github/workflows/gitleaks.yml) |
| Dependency vulns (OSV-Scanner) | [`osv-scanner.yml`](.github/workflows/osv-scanner.yml) |
| Actions audit (zizmor) | [`zizmor.yml`](.github/workflows/zizmor.yml) |
| OpenSSF Scorecard | [`scorecard.yml`](.github/workflows/scorecard.yml) |
| Dependency updates | [Dependabot](.github/dependabot.yml) |

Report vulnerabilities in AXGuard via [SECURITY.md](.github/SECURITY.md) (GitHub Private Vulnerability Reporting preferred).

---

## Contributing

Contributions are welcome.

Help with:

* Detection rules
* Scanners
* Test fixtures
* Agent skills
* Reports
* Documentation
* Bug fixes

```bash
pip install -e ".[dev]"
pytest -q
axguard audit fixtures/vuln_app --no-banner
```

See [CONTRIBUTING.md](CONTRIBUTING.md). Artifact/bytecode scanners are on the roadmap there — not claimed as current features.

Local contribution packaging is opt-in and never auto-pushes:

```bash
axguard privacy opt-in
axguard contribute suggest
axguard contribute prepare
```

---

## Responsible Use

AXguard is for **authorized security testing and defense**.

Only scan systems, applications, repositories, and infrastructure that you own or have permission to test.

---

## Support

AXguard is free and open source.

If it helps you build safer software, a **star on GitHub** helps more builders find it.

You can also support the project and help fund more open-source security tools.

**Website:** [awarexone.com](https://awarexone.com/)  
**Email:** [hello@awarexone.com](mailto:hello@awarexone.com) · [b2b@awarexone.com](mailto:b2b@awarexone.com) · [shuvon@awarexone.com](mailto:shuvon@awarexone.com)  
**Buy Me a Coffee:** [buymeacoffee.com/shuvonsec](https://www.buymeacoffee.com/shuvonsec)

| | |
|---|---|
| **Bitcoin** | `1GXwGqmLcnbZWgVNskUAZyw2cmqenkUFNY` |
| **Solana** | `4ArkPu1E7tkrt3d5X84grWzF1xjuLpScgGEy12Bp2cmE` |

---

## License

MIT. See [LICENSE](LICENSE).

<!--
SEO: ai-security · vibe-coding · security-scanner · vulnerability-scanner ·
appsec · devsecops · ai-agent-security · llm-security · sast · owasp ·
secret-scanning · claude-code · cursor · awarexone
-->
