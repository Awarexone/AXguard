---
name: axguard-report
description: Produce or polish AXguard Markdown and HTML audit reports from verified evidence. Use with /axguard-report. Prefer regenerating via axguard audit; tighten narrative only with confirmed findings.
---

# AXguard Report

Visual HTML is the human deliverable; Markdown for PRs/docs; JSON for CI. Prefer regenerating with the CLI; polish prose only with **verified** evidence. No filler. No exploit playbooks.

## Generate (preferred)

```bash
axguard audit . --out-dir .findings/axguard
```

Artifacts:

```
.findings/axguard/axguard-report.html
.findings/axguard/axguard-report.md
.findings/axguard/axguard-report.json
```

If a report already exists, refine MD from triage Keep list; do not invent findings the scanner and review did not support.

## Narrative structure (Markdown polish)

1. **Executive summary** — decision hint (blockers Y/N), C/H/M/L counts, scope (path, date).
2. **Method** — `axguard audit` / `axguard scan` + human triage. One short paragraph.
3. **Findings** — confirmed only, severity-sorted. Each item:

```
### [SEVERITY] Title
- CWE / OWASP: …
- Location: path:line
- Impact: one sentence
- Evidence: source → sink (no live exploit steps)
- Fix: one or two sentences
- Status: open | fixed | accepted risk
```

4. **Dropped / noise** — optional short appendix (count + themes), not a second findings list.
5. **Next steps** — fix order, re-audit, CI gate (`/axguard-ci`).

## Evidence rules

- Every finding cites file:line or config key.
- Impact language matches confidence (`axguard-cso` gate).
- Map classes using `axguard-knowledge` names (IDOR, SQLi, SSRF, …) for consistency.
- Screenshots/HTML: keep scanner HTML as visual source of truth; do not strip severity colors when hand-editing.

## Tone

Shuvonsec / AwareXone: professional, terse, ship-oriented. State blast radius; skip drama and padding.

## Output contract

Tell the user exact paths and tally:

```
Critical: N
High: N
Medium: N
Low: N
Reports: .findings/axguard/axguard-report.{md,html,json}
```
