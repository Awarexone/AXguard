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

## Risk aggregation & posture summaries (Phase 6 Part 2)

Two additional, **optional** helper modules roll `paths[]`/`graph` up into
higher-level views on top of the same vocabulary above — neither invents a
new confidence/status system, and neither is currently wired into the CLI or
`engines/report.py`; call them directly when you want the rollup:

```python
from engines.attack_graph import run_attack_graph
from engines.attack_graph.aggregate import build_risk_summary
from engines.attack_graph.posture import build_posture_summary

result = run_attack_graph(".")
risk = build_risk_summary(result)        # engines/attack_graph/aggregate.py
posture = build_posture_summary(result)  # engines/attack_graph/posture.py
```

- **`aggregate.build_risk_summary(result)`** — findings count, root causes,
  credible paths (`CONFIRMED`/`LIKELY`), critical chains (high-impact asset or
  AI/agent-multiplied), blocked paths, predictive risks (paths that are only
  safe *today* because of a control or an unresolved prerequisite — watch,
  don't ignore), and choke points (nodes shared by multiple paths — fix once,
  break many chains). Also groups by `root_cause` / `asset` / `privilege` /
  `tenant` — grouping is a lens, never a filter: `summary["findings"]` always
  lists every finding, grouped or not.
- **`posture.build_posture_summary(result)`** — an eight-stage narrative of
  the whole surface: `Entry → Trust → Controls → Weak → Vulns → Priv → Assets
  → Impact`. "Weak" is the subset of "Controls" that isn't actually
  effective (`ineffective`/`unknown`), so a reader sees both how many
  barriers exist and how many of them do nothing. Ends in a single
  `posture_rating` (`AT_RISK` / `MIXED` / `BLOCKED_OR_UNVERIFIED_ONLY` /
  `NO_OBSERVED_EXPOSURE`) plus a plain-language `narrative` list.

Both expose a `render_*_markdown()` function for a quick human-readable
rollup, and both degrade gracefully on an empty/minimal graph (see
`tests/test_attack_graph_corpus.py`). CLI flags for these (e.g. a future
`axguard paths . --aggregate` / `--posture`) are **not yet wired up** — this
section documents the modes/flags landing here so downstream tooling and
in-flight work on this branch can target a stable import surface; treat any
flag name above as a stated intent, not a guarantee, until `cli/main.py`
actually parses it.

## Regression corpus

`fixtures/attack_paths_corpus/` is a second, additive fixture corpus (next
to `fixtures/attack_paths_app/`) built specifically to regression-test this
phase end-to-end, including two forward-looking cases not yet detected by
any shipped chaining builder:

| File | Pattern | Status today |
|---|---|---|
| `confirmed_path.py` | direct sink chain, no control | hard-tested: CONFIRMED/LIKELY |
| `blocked_path_case.py` | effective admin auth gates a real bug | hard-tested: BLOCKED |
| `false_path.py` | two unrelated findings, same file | hard-tested: no path |
| `unknown_prerequisite.py` | vuln gated by an unresolvable remote flag | hard-tested: UNVERIFIED |
| `privilege_escalation.py` | mass-assignment → ineffective role gate | hard-tested: CONFIRMED/LIKELY |
| `cross_tenant_access.py` | tenant-scoped control that never re-checks the object | hard-tested: CONFIRMED/LIKELY |
| `ai_mcp_tool_abuse.py` | prompt injection → MCP tool-calling agent → secret | hard-tested: CONFIRMED/LIKELY |
| `confused_deputy.py` | service uses its own creds on an attacker-chosen object | **soft** — no detector yet |
| `state_dependent_chain.py` | cross-request / TOCTOU session-state trust | **soft** — no detector yet |

`tests/test_attack_graph_corpus.py` drives this off
`fixtures/attack_paths_corpus/expected.json`; cases marked `"soft": true`
skip (never fail) until a matching chaining detector lands, so the suite
stays green regardless of the order engine work merges in.

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
