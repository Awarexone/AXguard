# Architecture

AXguard splits into a **deterministic scanner** (CLI + rules) and an **agent layer** (skills + slash commands).

## Components

| Package / path | Responsibility |
|---|---|
| `cli/main.py` | Argparse UI: `scan`, `audit`, `surface`, `flow`, `verify`, `adversary`, `evidence`, `paths`, `help`, `version` |
| `engines/scanner.py` | Orchestrates one scan pass |
| `engines/rules_loader.py` | Loads `rules/*.json` (and a narrow YAML subset) |
| `engines/source_scan.py` | Walks the tree, applies regex rules, builds findings |
| `engines/audit.py` | A→Z phases + severity counts around a scan |
| `engines/app_model/` | Application understanding + attack-surface graph (`axguard surface`) |
| `engines/dataflow/` | Source→sink taint paths over the app model (`axguard flow`) |
| `engines/verify/` | Hunter → Judge verification diagnostic (`axguard verify`) |
| `engines/adversary/` | False Positive Adversary — challenge Judge outcomes (`axguard adversary`) |
| `engines/evidence/` | Evidence & Confidence engine — evidence graph + explainable confidence (`axguard evidence`) |
| `engines/attack_graph/` | Attack Graph — chains Phase 1-5 findings into multi-hop attack paths (`axguard paths`) |
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

Phases are labels over rule id prefixes (`secrets.`, `auth.`, …) plus `surface` / `report` bookends. The `surface` phase builds an application model via `engines/app_model` (routes, sinks, stack) and writes `application-model.json` / `.md` alongside reports; it also soft-runs Phase 2 dataflow, Phase 3 Hunter→Judge verification, Phase 4 False Positive Adversary, Phase 5 Evidence & Confidence, and Phase 6 Attack Graph / vulnerability chaining (diagnostic artifacts only — never fails the audit). Other phases still structure findings by rule prefix.

### Hunter → Judge → Adversary → Evidence → Confidence → Attack Graph pipeline

```text
app_model → dataflow → hunters → Judge (VERIFIED/LIKELY/…)
                              ↓
                    False Positive Adversary
                              ↓
         CONFIRMED | LIKELY | UNVERIFIED | FALSE_POSITIVE | REQUIRES_REVIEW
                              ↓
                Evidence & Confidence engine
        (supporting + counter evidence, dedupe/reuse, chains,
         conflicts, quality → explainable confidence)
                              ↓
      VERY_HIGH | HIGH | MEDIUM | LOW | UNKNOWN   (+ unknowns / conflicts)
                              ↓
                 Attack Graph (composition layer)
        (entrypoint → finding → … → asset; barriers → BLOCKED)
                              ↓
        CONFIRMED | LIKELY | UNVERIFIED | INVALID | BLOCKED  (per path)
```

The adversary searches counter-evidence and control effectiveness after Judge; it does not replace hunters or invent SAFE without evidence. The evidence engine then builds a deduplicated evidence graph per finding and derives an **explainable** confidence: quality is scored from provenance + exact location + analysis strength (never an arbitrary LLM percentage), unknowns pull confidence down, and a single strong signal never hides a critical unknown. Repository comments are never treated as evidence of safety, name-only controls never raise confidence, and the LLM stub can only explain existing evidence — it never invents any.

The attack graph is a **composition layer** on top: it chains individual findings into multi-hop attack paths (`entrypoint → … → sensitive outcome`) and reuses the same confidence vocabulary (Phase 5 `confidence_level` for `path.confidence_level`; legacy `confirmed|likely|unknown` per hop/edge). A path's status is its weakest hop plus barrier state — an **effective** control (fails-closed crypto auth) on a required edge marks the *path* `BLOCKED` (the finding still stands standalone); a `FALSE_POSITIVE` hop or a co-location-only link is `INVALID`; unknown reachability is `UNVERIFIED`, never a public claim. Where the upstream hunters miss a pattern, the attack graph emits its own deterministic, evidence-gated `candidate_seed` nodes (`LIKELY` at best, never `CONFIRMED`), and its LLM stub is inert (`invent()` raises).

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
3. **Application model adapters** — extend `engines/app_model/adapters/` for new frameworks; `axguard surface` and the audit `surface` phase consume the shared model
4. **New agent surface** — `commands/` + `skills/` + install/uninstall lists
5. **CI gate** — `axguard audit . --fail-on high`

## Design constraints

- Stdlib-first runtime (no required network deps for scan)
- Rules stay data, not code (safe for contributors)
- Agent layer never replaces the CLI — it drives and triages it
- False positives are filtered in `/axguard-triage`, not by deleting signal blindly
