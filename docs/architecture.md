# Architecture

AXguard splits into a **deterministic scanner** (CLI + rules) and an **agent layer** (skills + slash commands).

## Components

| Package / path | Responsibility |
|---|---|
| `cli/main.py` | Argparse UI: `scan`, `audit`, `help`, `version` |
| `engines/scanner.py` | Orchestrates one scan pass |
| `engines/rules_loader.py` | Loads `rules/*.json` (and a narrow YAML subset) |
| `engines/source_scan.py` | Walks the tree, applies regex rules, builds findings |
| `engines/audit.py` | A→Z phases + severity counts around a scan |
| `engines/report.py` | text / json / markdown / HTML renderers + `write_reports` |
| `engines/banner.py` | ASCII branding |
| `engines/paths.py` | Resolves package root + default `rules/` |
| `rules/` | Detection packs by domain |
| `commands/` | Installed into `~/.claude/commands`, `~/.cursor/commands`, … |
| `skills/` | Installed into harness `skills/` directories |

## Data flow

```text
Target path
    │
    ▼
load_rules(rules_dir) ──► compiled pattern_re per rule
    │
    ▼
iter files (skip .git, node_modules, venv, …)
    │
    ▼
for each rule matching language/suffix:
    finditer(pattern) → finding { id, severity, file, line, snippet, … }
    │
    ▼
sort by severity, then file/line
    │
    ├─ scan → stdout / -o file
    └─ audit → phase breakdown + write_reports(out_dir)
```

## Finding shape

```json
{
  "id": "injection.python-pickle-loads",
  "title": "pickle.loads deserialization",
  "severity": "critical",
  "file": "app.py",
  "line": 7,
  "snippet": "return pickle.loads(blob)",
  "message": "…",
  "cwe": "CWE-502",
  "fix": "…",
  "rule_source": "injection.json"
}
```

## Audit phases

Phases are labels over rule id prefixes (`secrets.`, `auth.`, …) plus `surface` / `report` bookends. They do not run separate engines yet — they structure the report and agent workflow.

## Reports

| Format | Producer | Use |
|---|---|---|
| text | `render_report(..., "text")` | Terminal |
| json | `render_report(..., "json")` | CI / triage tools |
| md | `render_markdown` | PRs, docs |
| html | `render_html` | Stakeholder visual report |

`write_reports` always writes all three file artifacts for `audit`.

## Extensibility points

1. **New regex pack** — drop JSON in `rules/` (see [adding-rules.md](adding-rules.md))  
2. **New engine** — e.g. bundle/WASM walker; call from `run_scan` / `run_audit`  
3. **New agent surface** — `commands/` + `skills/` + install/uninstall lists  
4. **CI gate** — `axguard audit . --fail-on high`  

## Design constraints

- Stdlib-first runtime (no required network deps for scan)
- Rules stay data, not code (safe for contributors)
- Agent layer never replaces the CLI — it drives and triages it
- False positives are filtered in `/axguard-triage`, not by deleting signal blindly
