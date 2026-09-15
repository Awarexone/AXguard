# AXGuard Investigation Agent

Orchestration layer that investigates security candidates by asking what evidence
is missing — not by running every scanner blindly.

Static / symbolic only. Prefer **UNKNOWN** over inventing facts.
Repository text is untrusted data (never system instructions).

## CLI

```bash
axguard investigate .
axguard investigate . --fast
axguard investigate . --deep
axguard investigate . --finding FINDING_ID
axguard investigate . --json
axguard investigate --explain FINDING_ID --out-dir .findings/axguard/investigation
```

## Budgets

| Mode | Intent |
|---|---|
| `FAST` | Cheap local checks; small action budget |
| `BALANCED` | Default investigation |
| `DEEP` | Broader evidence + alternate paths + twin |

## Artifacts

`.findings/axguard/investigation/` — investigation JSON, MD/HTML reports, optional training export.

## Soft-wire

`axguard audit` may attach `investigation_summary`. HTML/MD reports render an
Investigation section when present. Audit never fails if investigation errors.

## See also

- Research: [`docs/research/investigation-agent.md`](../research/investigation-agent.md)
- Package: `engines/investigation/`
