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

### HTML report approval / consent model

The HTML report (`render_html` + `engines/report_ux.py`) is **read-only** and self-contained: no network calls, no source mutation, secrets already `[REDACTED]` upstream. It applies the AXguard consent principle — *analyze automatically, but ask before actions that create / export / expose / run heavier secondary analysis; never nag for harmless read-only ops*:

- **AUTO** (no dialog) — parse, path composition, evidence, and generating the report already ran server-side. A top banner states the mode (`READ-ONLY`), target, generated time, coverage, and "No source files were modified. No external requests were made." If advanced stages are missing it shows `LIMITED ANALYSIS` + a *Review Available Analysis* jump.
- **APPROVAL REQUIRED** (Approve / Cancel dialog) — expand the full attack graph, reveal full source context, export a detailed report, or run the extended-analysis placeholder. All effects are client-side. Expanding a large graph (> `FULL_GRAPH_EDGE_THRESHOLD` edges or `> FULL_GRAPH_PATH_THRESHOLD` paths) asks one extra "Load full attack graph?" approval.
- **HIGH-RISK** (dialog, then stubbed) — Apply Fix / Active Verification / External Share open a dialog and are **never executed** by the report; approving only records a `BLOCKED` "not available in this report build (requires CLI)" outcome.

State lives in an embedded `#axguard-session-state` script (`{"analysis_mode":"read_only","approved_actions":[],"activity_log":[]}`): scoped, temporary, auditable — one approval never implies another. Every action button routes through `axguardRequestApproval(...)`; there is no direct runner `onclick`. Interactive actions surface states (`AVAILABLE → WAITING FOR APPROVAL → RUNNING → COMPLETED / BLOCKED / FAILED / CANCELLED`), an *Analysis activity* trail logs approvals/expansions/exports (no secrets), and there are no dark patterns: Cancel is always present, Escape and the backdrop cancel, focus defaults to Cancel, and no dangerous action is preselected or auto-run. Detailed attack-path hops are read from an embedded `#axguard-attack-paths` `application/json` block (redacted via `ensure_no_secret_values`).

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
