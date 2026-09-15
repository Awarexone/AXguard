# AXGuard Training Data Pipeline (Phase 9)

> **No model training in this phase.** This is dataset *infrastructure*:
> discover → license-gate → normalize → scrub → dedupe → validate → prepare → report.

## Philosophy

Prefer **better data** over more data. AXGuard should learn to distinguish real,
evidence-backed security problems from plausible but incorrect claims.
False-positive resistance is a first-class objective.

```text
Don't teach AXGuard to find everything.
Teach AXGuard to find what it can prove.
```

## Layout

| Path | Role |
|---|---|
| `engines/data/` | Registry, license gate, normalize, scrub, poison, prepare, report |
| `data/registry/datasets.json` | Local machine-readable registry (no row dumps) |
| `fixtures/data_pipeline/` | Tiny synthetic fixtures for tests |
| `references/datasets.yaml` | Existing HF metadata (merged on discover) |
| `docs/data/research/` | Optional research notes from discovery agents |

## CLI

```bash
axguard data discover
axguard data inspect
axguard data inspect --id axguard/synthetic-fp-corpus
axguard data approve --id …          # blocked for Proprietary/Unknown
axguard data approve --id … --force-research-only
axguard data reject --id …
axguard data normalize fixtures/data_pipeline
axguard data prepare fixtures/data_pipeline
axguard data benchmark fixtures/data_pipeline
axguard data report fixtures/data_pipeline --out-dir .findings/axguard/data
```

## License gate

Public TRAINING corpus **never** auto-includes:

- `Proprietary`
- `Unknown`
- unverified licenses (`license_verified=false`)

Share-alike / non-commercial licenses default to `EVALUATION_ONLY` / human review.

## Contamination guard

Datasets marked `BENCHMARK_ONLY` or `EVALUATION_ONLY` are excluded from TRAINING
splits during `prepare`.

## Artifacts

`.findings/axguard/data/data-pipeline.{json,md,html}`
