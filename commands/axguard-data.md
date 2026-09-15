---
description: Training-data registry and pipeline (Phase 9 — no model training). Usage: /axguard-data …
---

# /axguard-data

**Specialist:** Training Data Intelligence

Builds and validates AXGuard's **security reasoning corpus infrastructure** —
registry, license gate, normalize/scrub/dedupe, contamination guards, and
quality reports. Does **not** train models or download giant datasets.

## Usage

```
/axguard-data discover
/axguard-data inspect
/axguard-data approve --id <dataset>
/axguard-data reject --id <dataset>
/axguard-data report fixtures/data_pipeline
```

CLI equivalent: `axguard data <subcommand>`.

## Focus

- Dataset registry statuses: DISCOVERED → UNDER_REVIEW → APPROVED / REJECTED / …
- Mandatory license gate for public training
- Synthetic fixtures for vulnerability / FP / attack-path / AI-security examples
- Secret scrubbing + poison heuristics
- BENCHMARK_ONLY exclusion from TRAINING

## Steps

1. `axguard data discover` — merge seed + `references/datasets.yaml`
2. Review `axguard data inspect`
3. Approve only verified, redistributable licenses (or `--force-research-only`)
4. `axguard data report` on fixtures / curated JSONL
5. Read `.findings/axguard/data/data-pipeline.md`

See [docs/data/README.md](../docs/data/README.md).
