# AXGuard Security Memory

Project-local longitudinal security intelligence under
`.findings/axguard/memory/` (never `~/.axguard`).

Prefer **UNKNOWN** over inventing history. Immutable snapshot + ledger updates.
Audits soft-wire memory automatically and never fail if memory is unavailable.

## What it stores

- Findings (lifecycle, status, fingerprints)
- Controls and attack paths
- Unknowns / assumptions
- Snapshot history for diffs and regressions

## CLI

```bash
axguard memory record . --out-dir .findings/axguard/memory
axguard memory record fixtures/attack_paths_app
axguard memory record path/to/audit-result.json   # audit / attack-graph JSON
axguard memory show
axguard memory history
axguard memory history --finding <fingerprint>
axguard memory changes [--before ID] [--after ID]
axguard memory regressions
axguard memory findings [--rejected]
axguard memory controls
axguard memory paths
axguard memory unknowns
axguard memory query --question "what changed"
```

## Artifacts

| Path | Role |
|---|---|
| `index.json` | Latest snapshot pointer |
| `ledger.json` | Fingerprint → latest state |
| `snapshots/*.json` | Immutable per-revision snapshots |
| `security-memory.md` | Human-readable summary |

## Audit / reports

`axguard audit` records into `<out-dir>/memory/` and attaches a compact
`memory_summary` on the audit result. HTML/MD reports render a soft Security
Memory section when `memory_summary` or `security_memory` is present.

## See also

- Research notes: [`docs/research/security-memory.md`](../research/security-memory.md)
- Package: `engines/memory/`
