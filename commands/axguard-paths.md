---
description: Attack graph + vulnerability chaining (Phase 6). Chains Phase 1-5 findings into multi-hop attack paths. Usage: /axguard-paths [path]
---

# /axguard-paths

**Specialist:** Attack Graph + Vulnerability Chaining

Chains findings from earlier phases into multi-hop **attack paths** —
`entrypoint → … → sensitive outcome` — instead of reporting vulnerabilities in
isolation. It is a **composition / rollup layer**: it detects no new
vulnerabilities and invents no second confidence system — it reuses the Phase
1-5 confidence + evidence vocabulary and marks a *path* BLOCKED when an
effective control sits on it (the underlying finding still stands).

## Usage

```
/axguard-paths
/axguard-paths ./app
```

## Focus

- Reuses Phase 1-5 confidence + evidence (Phase 5 `confidence_level`
  `VERY_HIGH…UNKNOWN` for `path.confidence_level`; legacy
  `confirmed|likely|unknown` for per-hop/edge confidence)
- Node types: entrypoint, finding, control, asset, identity, ai_component,
  tool, external_service, trust_boundary (+ `candidate_seed` for
  evidence-gated structural seeds)
- Edge types: `reaches`, `triggers`, `exposes`, `escalates_to`,
  `crosses_tenant`, `invokes`, `yields`, `blocked_by`, `chains_to`
- Path status: `CONFIRMED` | `LIKELY` | `UNVERIFIED` | `INVALID` | `BLOCKED`
  (weakest-link across hops; never averaged, never invented)
- Controls are graph barriers — an **effective** control (fails-closed crypto
  auth) on a required edge marks the path `BLOCKED`; name-only / mutable-field
  controls do not
- Selects both the shortest-credible and the highest-impact path per
  (entrypoint, asset) pair; dedupes equivalent finding-id sequences
- Dead ends (findings with no chainable next hop) are reported standalone,
  never forced into a fabricated chain
- Same-file / co-located findings are never chained without an actual
  data/control-flow link (see `false_chain.py`)
- Covers AI/agent chains: prompt injection → agent → privileged tool →
  sensitive resource
- No LLM API calls in the default pipeline (same constraint as Phase 3/4); the
  `LLMAttackPathStub` can only restate existing graph elements — its
  `invent()` raises

This is a **diagnostic chaining layer**, not a replacement for the underlying
Phase 3/4 finding reports.

## Steps

1. Run:

```bash
axguard paths .
# alias:
axguard attack-paths .
# soft-attaches after the evidence block during audit (never fails the audit):
axguard audit . --out-dir .findings/axguard
```

2. Read:

- `.findings/axguard/attack-paths.json`
- `.findings/axguard/attack-paths.md`

3. Prioritize `CONFIRMED`/`LIKELY` paths reaching high-impact assets over
   standalone findings of the same severity; treat `BLOCKED` paths as "worth
   monitoring if the control regresses," not as safe to ignore entirely; treat
   `UNVERIFIED` reachability as a question for a human, not as public or as
   safe.

## Output shape

Each path prints as:

```
Entry → Finding → … → Impact
status / confidence / score
```

with a `score_factors` breakdown (weakest-link confidence, asset impact,
reachability, directness, AI multiplier) documented in
[docs/attack-graph.md](../docs/attack-graph.md).

See also [`/axguard-flow`](axguard-flow.md), [`/axguard-adversary`](axguard-adversary.md),
and [`/axguard-evidence`](axguard-evidence.md) for the phases this layer composes.
