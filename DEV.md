# AXguard — Developer Guide

How to build, test, extend, and ship AXguard.

| Doc | Audience |
|---|---|
| [This guide](DEV.md) | Contributors & maintainers |
| [Architecture](docs/architecture.md) | Anyone changing engines/rules |
| [Adding rules](docs/adding-rules.md) | Detection authors |
| [Plugin / skills](docs/plugin.md) | Agent harness wiring |
| [Commands quick ref](COMMANDS-QUICK-REF.md) | End users & agents |
| [Cover prompt](assets/COVER-PROMPT.md) | Branding / assets |

---

## Prerequisites

- Python **3.10+**
- `git`
- Optional: Claude Code / Cursor (to exercise the plugin install path)

---

## Clone & setup

```bash
git clone https://github.com/Awarexone/AXguard.git
cd AXguard

python3 -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -e ".[dev]"

axguard version
axguard help
```

Editable install gives you the `axguard` entry point and picks up local `engines/` + `cli/` changes immediately. Rules load from the repo `rules/` directory via `engines.paths.default_rules_dir()`.

---

## Day-to-day commands

```bash
# Fast scan
axguard scan fixtures/vuln_app --no-banner

# Full A→Z audit + HTML/MD/JSON
axguard audit fixtures/vuln_app --out-dir .findings/axguard --no-banner

# Tests
pytest -q

# Plugin install (local harness)
./install.sh --agent cursor --project
./uninstall.sh --agent cursor --project
```

Reports land in `.findings/axguard/` (gitignored).

---

## Repository map

```text
cli/                CLI entrypoint (scan, audit, help, version)
engines/            Scan orchestration, rule loader, reporters, banner
rules/              JSON rule packs (secrets, auth, injection, …)
commands/           Slash commands installed into agent harnesses
skills/             Agent Skills (SKILL.md)
fixtures/           Intentional vulnerable samples for tests
tests/              pytest suite
assets/             Cover art + brand prompts
.claude-plugin/     Plugin manifest
install.sh          Install skills/commands into Claude/Cursor/…
uninstall.sh        Remove installed skills/commands
docs/               Deeper developer docs
```

---

## Architecture (short)

```text
axguard audit|scan
        │
        ▼
  engines.scanner.run_scan
        │
        ├─ rules_loader.load_rules(rules/)
        └─ source_scan.scan_source(target, rules)
                │
                ▼
           findings[]
                │
        ┌───────┴────────┐
        ▼                ▼
  text / json      audit + write_reports
                   (md + html + json)
```

- **Deterministic path:** CLI + `rules/*.json` regex packs  
- **Agent path:** `commands/` + `skills/` teach the model when/how to run the CLI and how to triage  

Details: [docs/architecture.md](docs/architecture.md)

---

## Adding a detection rule

1. Pick or create a pack under `rules/` (e.g. `rules/injection.json`).
2. Add a rule object with `id`, `title`, `severity`, `pattern`, `message`, `fix`.
3. Add a fixture under `fixtures/` that should match.
4. Assert in `tests/`.
5. If it is a new class, add a slash command under `commands/` and update `COMMANDS-QUICK-REF.md` + README Start Using table.

Full schema and examples: [docs/adding-rules.md](docs/adding-rules.md)

---

## Adding a slash command or skill

**Command** — `commands/axguard-<name>.md`  
Front matter `description:` becomes the agent help text. Keep steps concrete: run which CLI, which paths, what to output.

**Skill** — `skills/axguard-<name>/SKILL.md`  
YAML front matter: `name`, `description`. Description must say *when* to load the skill.

After adding files:

```bash
./install.sh --agent cursor --project   # or claude / all
```

Update `uninstall.sh` skill/command lists if you add new names.

---

## Tests

```bash
pytest -q
pytest tests/test_scan.py -q
pytest tests/test_audit_report.py -q
```

CI runs the same suite via `.github/workflows/ci.yml` (needs a token with `workflow` scope when editing workflows).

**Expectations**

- New rules → fixture hit + assertion  
- Reporter changes → assert MD/HTML contain expected markers  
- Do not commit live secrets; fixtures use obvious fake values  

---

## Versioning & package

| Field | Location |
|---|---|
| Version | `pyproject.toml` → `[project].version` (currently `0.2.0`) |
| Package name | `axguard` |
| Console script | `axguard = cli.main:main` |
| License | MIT (`LICENSE`) |

Bump version in `pyproject.toml`, README badges, and `engines/audit.py` / CLI `version` strings together.

---

## Code style

- Python 3.10+ typing (`list[dict]`, `Path | None`)
- No heavy deps in the default install (stdlib-first)
- Keep CLI output terse; banner optional via `--no-banner`
- Agent docs: professional hunter tone, no filler

---

## PR checklist

- [ ] `pytest -q` green  
- [ ] New behavior covered by a test or fixture  
- [ ] Rules / commands / skills documented in quick-ref or README if user-facing  
- [ ] No real secrets in fixtures  
- [ ] `uninstall.sh` lists updated if you added installable names  

---

## Related AwareXone tools

| Tool | Role |
|---|---|
| [Agentic Bug Hunter](https://github.com/Awarexone/Agentic-Bug-Hunter) | Live hunting (offense) |
| [AXguard](https://github.com/Awarexone/AXguard) | Pre-ship gate (defense) |
| [public-skills-builder](https://github.com/Awarexone/public-skills-builder) | Generate hunt skills |
| [web3 skills](https://github.com/Awarexone/web3-bug-bounty-hunting-ai-skills) | Smart-contract skills |

Questions / sponsorship: [awarexone.com](https://awarexone.com) · [awarexone@gmail.com](mailto:awarexone@gmail.com)
