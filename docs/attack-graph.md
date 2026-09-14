# Attack Graph — Phase 6 Design (implemented)

> **Status:** implemented. `engines/attack_graph/` composes Phase 1-5 output
> into multi-hop attack paths, is wired into `cli/main.py` (`axguard paths`,
> alias `axguard attack-paths`) and soft-wired into `engines/audit.py` (after
> the Phase 5 evidence block; never fails the audit). Artifacts:
> `attack-paths.json` + `attack-paths.md`. This document is the contract the
> engine satisfies; the sections below match the shipped behaviour.
>
> **One confidence system, reused.** Phase 6 invents no second
> `CONFIRMED`/`LIKELY`/`UNKNOWN` scale and no second evidence-weight table. It
> reuses the Phase 5 `confidence_level` (`VERY_HIGH…UNKNOWN`) for
> `path.confidence_level`, the legacy `confirmed|likely|unknown` vocabulary for
> per-hop/edge confidence, and `engines.dataflow.schema.ensure_no_secret_values`
> for redaction.

## Goal

Chain individually-reported findings (Phase 3 Judge candidates, Phase 4
adversary-final findings, Phase 1 app-model graph, Phase 2 taint paths) into
**multi-hop attack paths**: `entrypoint → … → sensitive outcome`. An attack
path answers "can an attacker actually get from the internet (or a low-priv
identity) to something that matters," not just "is there a vulnerability
somewhere."

Phase 6 is a **rollup / composition layer**. It does not detect new
vulnerabilities and it does not compute its own notion of confidence — it
consumes the confidence + evidence vocabulary that already exists in
`engines/app_model`, `engines/dataflow`, `engines/verify`, `engines/adversary`,
and `engines/evidence`. **One confidence system, reused everywhere.**

## Inputs (reused, not reinvented)

| Artifact | Produced by | What Phase 6 reads from it |
|---|---|---|
| `application-model.json` | Phase 1 (`app_model`) | entrypoints, sinks, assets, `ai_components`, `security_controls`, `trust_boundaries`, `graph.nodes` / `graph.edges` |
| `dataflow.json` | Phase 2 (`dataflow`) | `taint_paths`, `controls[]` (kind + `effectiveness`), `taint_state` |
| `verification.json` | Phase 3 (`verify`) | Judge `judgments[]` (`VERIFIED`/`LIKELY`/`UNVERIFIED`/`FALSE_POSITIVE`) + evidence lists |
| `adversary.json` / `final-findings.json` | Phase 4 (`adversary`) | final finding status (`CONFIRMED`/`LIKELY`/`UNVERIFIED`/`FALSE_POSITIVE`/`REQUIRES_REVIEW`) + counter-evidence + control-bypass evidence |
| Phase 5 evidence ledger (`evidence.json`) | Phase 5 (`engines/evidence`) | canonical per-finding confidence rollup + store records (`id`/`type`/`quality`/`description`/`file`/`line_*`/`symbol`/`provenance`); paths attach via `evidence_refs` ids — do not re-copy fields |

Phase 6 must not invent a second `CONFIRMED`/`LIKELY`/`UNKNOWN` scale, a
second evidence-weight table, or a second redaction routine
(`ensure_no_secret_values`, `_redact_snippet` already exist in
`engines/dataflow/schema.py` and must be reused as-is for any snippet a
path evidence record carries).

## Node types

| Node type | Source | Notes |
|---|---|---|
| `entrypoint` | app_model | HTTP route, webhook, queue consumer, CLI entry |
| `finding` | verify/adversary | a specific Judge/adversary-scored vulnerability instance (carries its own status + evidence, never re-scored by Phase 6) |
| `control` | dataflow `controls[]` / app_model `security_controls` | barrier candidate — auth check, tenant-scoping filter, allowlist, sanitizer |
| `asset` | app_model `assets[]` | sensitive resource: DB table, secret, credential store, PII |
| `identity` | app_model `identities[]` (extended) | user / tenant / role — needed for priv-esc and cross-tenant chains |
| `ai_component` | app_model `ai_components[]` | agent/orchestrator, LLM call, MCP client |
| `tool` | ai_component sub-type or dataflow `SINK_AI_TOOL` | a callable the agent can invoke (file write, shell, HTTP, email, DB) |
| `external_service` | app_model `external_services[]` | third-party API, cloud resource |
| `trust_boundary` | app_model `trust_boundaries[]` | internet↔app, app↔db, agent↔tool, tenant↔tenant |

Every node keeps a `refs` list pointing back at the source artifact + id
(e.g. `{"source": "verification.json", "id": "cand-0007"}`) instead of
copying fields — Phase 6 is a graph over existing records, not a fork of
them.

## Edge types

| Edge type | Meaning |
|---|---|
| `reaches` | trust boundary crossed (internet → entrypoint), from app_model `graph` |
| `triggers` | entrypoint/finding → next finding (e.g. SSRF response is fed to a second sink) |
| `exposes` | finding → asset it directly discloses/modifies |
| `escalates_to` | identity(role=user) → identity(role=admin) via an authz weakness |
| `crosses_tenant` | identity(tenant=A) → asset/identity(tenant=B) via a missing tenant-scope check |
| `invokes` | ai_component → tool |
| `yields` | tool → asset/external_service affected by the tool call |
| `blocked_by` | edge annotated with the control node sitting on it, plus that control's `effectiveness` |
| `chains_to` | generic fallback link when dataflow/call-graph co-location connects two findings without a more specific edge type applying |

Edges always carry `confidence` (Phase 1–5 vocabulary: `confirmed` /
`likely` / `unknown`) and an `evidence` list — never a bare boolean.

## Path status

A **path** is an ordered list of edges from one `entrypoint` (or attacker-
controlled `identity`) to one `asset` (or privileged outcome). Status is a
property of the whole chain, computed from its weakest hop plus barrier
state — never averaged, never invented independent of the underlying
findings:

| Status | Meaning | Derivation |
|---|---|---|
| `CONFIRMED` | Every hop is backed by a `CONFIRMED`/`VERIFIED` finding or `confirmed`-confidence edge, and no un-bypassed effective control sits on the path | `min()` across hop statuses == top tier, no active `blocked_by` |
| `LIKELY` | At least one hop is only `LIKELY`/`likely`, none are `FALSE_POSITIVE`/`INVALID`, chain is still plausibly connected | weakest hop is `LIKELY`, no blocking control |
| `UNVERIFIED` | A hop's own status is `UNVERIFIED`, or the *link* between two otherwise-real findings is unconfirmed (missing dataflow link, unknown network reachability, ambiguous reachability) | mirrors `EV_MISSING_LINK` / reachability `unknown` |
| `INVALID` | Any hop's underlying finding is `FALSE_POSITIVE`, or two findings do not actually share data/control flow (co-located only, no taint/call link) — the chain must not be presented as exploitable | hard veto, same spirit as adversary's `FP_*` reason codes |
| `BLOCKED` | The chain would otherwise be real, but an **effective** control (`effectiveness == confirmed`, or `likely` with no documented bypass) sits on a required edge | `blocked_by` edge present and not countered by adversary `controls_bypass` evidence |

`INVALID` and `BLOCKED` are both terminal-safe states but mean different
things to a reader: `INVALID` says "this chain doesn't exist," `BLOCKED`
says "this chain exists but a barrier currently stops it" (worth flagging
if the control ever regresses).

## Scoring factors

Score is a ranking aid for triage order, not a new severity system:

1. **Weakest-link confidence** (dominant factor) — a chain is only as
   strong as its worst hop; never let one `CONFIRMED` hop paper over an
   `UNVERIFIED` one.
2. **Hop count** — shorter, more direct paths to the same asset outrank
   longer ones at equal confidence (fewer assumptions).
3. **Asset impact tier** — credentials/secrets/admin-control >
   PII/financial data > generic internal data > low-value info. Reuses
   `asset.kind` from app_model (`secret`, `credential`, `database`, `token`, …).
4. **Reachability** — public unauthenticated entrypoint > authenticated
   entrypoint > internal-only/queue-only > requires a prior compromise on
   this same graph.
5. **Control effectiveness along the path** — mirrors the existing
   `EFFECT_CONFIRMED` / `EFFECT_LIKELY` / `EFFECT_UNKNOWN` /
   `EFFECT_INEFFECTIVE` weighting in `engines/dataflow/controls.py`;
   ineffective/name-only controls (`sanitize()` that doesn't sanitize) do
   **not** reduce score, only genuinely effective ones do.
6. **AI/agent multiplier** — a chain that ends in autonomous tool
   execution (vs. a human reading a report) is flagged with higher
   priority at equal confidence, because impact can be automated /
   repeated.

### Implemented scoring formula (`engines/attack_graph/scoring.py`)

`score ∈ [0, 1]` is a **triage-ordering aid**, not a severity or confidence
value. It is a transparent weighted sum with an AI multiplier, and every path
carries a `score_factors` breakdown so a reader can see exactly why one path
outranks another:

```text
base  = 0.50 · confidence(status)      # weakest-link status weight (dominant)
      + 0.25 · asset_impact(target)    # secret/credential/admin > pii > db > info
      + 0.15 · reachability(entry)     # public > authenticated > internal/queue > unknown
      + 0.10 · directness              # 1.0 for a 1-hop path, gently decaying, floor 0.30
score = min(1.0, base · ai_multiplier) # ai_multiplier = 1.15 iff the chain ends in a tool
```

- `confidence(status)` weights (`SCORE_STATUS_WEIGHT`): `CONFIRMED 1.0`,
  `LIKELY 0.65`, `UNVERIFIED 0.35`, `BLOCKED 0.15`, `INVALID 0.0` — so a
  blocked/invalid chain never outranks a live one.
- `asset_impact` (`ASSET_IMPACT_TIER`) and `reachability` (`REACHABILITY_TIER`)
  reuse `asset.kind` and entrypoint reachability from Phase 1.
- Only **genuinely effective** controls change the picture: an effective
  barrier flips the *status* to `BLOCKED` (which then dominates the score via
  the confidence weight); a name-only / ineffective control leaves the score
  untouched, exactly as the design requires.

Ranking within the output uses `(status tier, score, fewer hops, id)`, and each
`(entry, target)` group tags its **shortest-credible** and **highest-impact**
framing in `path.selection`.

## Path selection

- **Shortest path**: BFS over `graph` edges from every public/reachable
  entrypoint or attacker-controllable identity to every `asset`/privileged
  node, cost = 1 per hop, tie-broken by weakest-link confidence (prefer
  the higher-confidence of two equal-length paths).
- **Highest-impact path**: separate ranking by `(status tier, asset impact
  tier, aggregate confidence)` — a longer `CONFIRMED` path to a credential
  store should outrank a 1-hop `UNVERIFIED` path to a low-value asset. Both
  the shortest and the highest-impact path per (entrypoint, asset) pair are
  worth reporting; they are often the same path but not always.
- **De-duplication**: paths sharing the same ordered set of finding ids
  collapse to one record with multiple `(entrypoint, asset)` framings noted.

## Dead ends

A `finding` node with no outgoing `triggers`/`exposes`/`invokes` edge to
anything else chainable is a **dead end**: it is still reported by Phase 3/4
as a standalone vulnerability, but Phase 6 must not fabricate a next hop to
make a more dramatic story. Mark it `"dead_end": true` and leave it out of
the `paths[]` list (or include it as a zero-hop "path" only if explicitly
requested) — see `unknown_reachability.py` and the "no relation" half of
`false_chain.py` for fixture cases that must terminate here.

## AI / agent chains

Distinct edge sequence, still built from the same node/edge/status
vocabulary:

```text
entrypoint (chat/doc-ingest) --reaches--> ai_component[agent]
ai_component[agent] --invokes--> tool[privileged: fs/http/shell/email]
tool --yields--> asset (secret, internal API, filesystem)
```

- The "vulnerability" at the start is prompt injection: untrusted content
  (user message, ingested document, tool output) reaches the model's
  instruction context — treat this as a `finding` node like any other
  (source-controlled, sink = agent instruction context).
- The critical edge is `invokes`: does the agent framework let an
  injected instruction reach a **privileged** tool (write/exec/network/
  send) without a human-in-the-loop or allowlist check?
- `BLOCKED` applies when the tool call requires explicit user confirmation
  or the tool is allowlisted/scoped narrowly (`effectiveness=confirmed`
  control on the `invokes` edge) — see `ai_chain.py`.

## Controls as barriers

Controls are graph nodes/edges, not silent modifiers:

- Reuse `dataflow.controls[]` (`kind`, `effectiveness`) and app_model
  `security_controls[]` directly — do not re-derive control detection.
- A control sits **on an edge** between two nodes. If effectiveness is
  `confirmed`, or `likely` with no adversary `controls_bypass` evidence
  contradicting it, the edge is annotated `blocked_by` and downstream
  reachability through that edge is cut for scoring purposes (path status
  → `BLOCKED`).
- A named-but-ineffective control (`EFFECT_INEFFECTIVE`, or
  `EFFECT_UNKNOWN` with no reject branch — same heuristic already in
  `find_controls_in_region`) does **not** block the path; the chain keeps
  whatever status its findings otherwise earn. This mirrors the adversary
  philosophy: "name-only `sanitize()`/`require_auth`-that-doesn't-check is
  not enough."
- If Phase 4 adversary evidence shows a documented bypass of an otherwise-
  effective control, the control's blocking effect is lifted for that
  specific path and the path reverts to whatever status its findings
  otherwise earn.

## Structural seed nodes (honesty note)

The Phase 1-5 hunters do not yet detect every pattern the fixtures exercise
(mass-assignment / BOLA are not in the verify hunters, and the adversary
conservatively drops the `multi_chain` SSRF over a spurious `timeout=` "control").
To compose those chains **honestly**, the attack-graph package runs its own
deterministic, evidence-gated structural detectors (scoped entirely to
`engines/attack_graph/nodes.py`). They emit finding-like `candidate_seed`
nodes with explicit `evidence` and `origin: "attack_graph_seed"`:

- A seed is **`LIKELY`** at best — a structural pattern is never `CONFIRMED`.
- A seed is **`UNVERIFIED`** when reachability is unknown.
- A detector that does not match emits nothing; seeds never fabricate a chain
  from co-location, and a `FALSE_POSITIVE` finding hop still vetoes a chain
  (`INVALID`).

Adversary-scored `CONFIRMED`/`LIKELY`/`UNVERIFIED` findings are always
preferred over seeds when both are available for the same location.

## Output artifacts

`engines/attack_graph/` writes `attack-paths.json` (machine-readable graph +
`paths[]` + `dead_ends[]` + `alternate_paths[]`) and `attack-paths.md` (human
summary), following the same `write_reports`-style convention as other phases.
Sketch:

```json
{
  "schema_version": "1.0.0",
  "tool": "axguard",
  "graph": {"nodes": [...], "edges": [...]},
  "paths": [
    {
      "id": "path-0001",
      "status": "CONFIRMED",
      "tags": ["ssrf_chain"],
      "entry": "entrypoint:...",
      "target": "asset:...",
      "hops": ["entrypoint:...", "finding:...", "finding:...", "asset:..."],
      "confidence": "confirmed",
      "score": 0.0,
      "controls_encountered": [{"id": "control:...", "effectiveness": "ineffective"}],
      "dead_end": false,
      "evidence_refs": [{"source": "adversary.json", "id": "..."}]
    }
  ],
  "dead_ends": [{"finding": "finding:...", "reason": "no outgoing chainable edge"}]
}
```

## Non-goals (this phase)

- No new confidence/evidence system — strictly consumes Phase 1–5 output.
- No Business Logic / Dynamic Exploit / Auto-Fix / Continuous Learning engines.
- No LLM calls in the default pipeline (same constraint as Phase 3/4). The
  `LLMAttackPathStub` is inert: it can only restate existing graph nodes and
  its `invent()` raises — it never adds a node, edge, credential, impact, or
  reachability claim.

## Package layout (implemented)

```
engines/attack_graph/
  __init__.py       ATTACK_GRAPH_VERSION, run_attack_graph, write_attack_graph_report, render_attack_paths_markdown
  schema.py         node/edge/status vocabulary, scoring constants, empty_attack_graph()
  nodes.py          node factories + evidence-gated structural detectors (assets/ai/tools/seeds)
  edges.py          evidence-backed edge factory (confidence + evidence, never a bare bool)
  preconditions.py  per-hop auth/role/input/network/tenant preconditions
  barriers.py       control effectiveness — BLOCKED (fails-closed crypto) vs ineffective
  chaining.py       vulnerability chaining (ssrf→internal, idor/bola, mass-assignment, ai tool)
  paths.py          bounded enumeration, dedupe by finding-id signature, shortest/highest-impact
  scoring.py        transparent prioritization (documented factors)
  confidence.py     weakest-link path status + Phase 5 confidence_level reuse
  llm_stub.py       inert explain-only stub (invent() raises)
  summarize.py      summary + attack-paths.md renderer
  writers.py        attack-paths.json + attack-paths.md
  pipeline.py       run_attack_graph(target, evidence=None)
```

---

# Attack Graph — Phase 6 **Part 2** Foundation (implemented)

> **Status:** implemented. Part 2 is an *intelligence* layer built **over** the
> Part 1 chains — it does not rewrite them. Part 1 still assembles the
> evidence-backed `graph` + `paths[]`; Part 2 reasons about *who* the attacker
> becomes, *what state* the app moves through, *how privilege shifts*, *how
> sensitive* the reached data is, *what one compromise exposes* (blast radius),
> *what one fix removes* (fix impact), and *which paths are really the same bug*
> (equivalence). It adds new result fields and a public query `api`, and adds
> optional view filters to `axguard paths`. **Same one confidence system,
> reused** — Part 2 invents no second confidence scale and no second
> evidence-weight table, and every derived record is anchored to evidence that
> already exists on a node/edge.

## What Part 2 adds (at a glance)

| Concern | Module | Public entry (`engines.attack_graph.api`) |
|---|---|---|
| Bounded, deterministic graph search | `search.py` | (used internally by blast/reachability) |
| AND/OR three-valued precondition logic | `logic.py` | — |
| Identity types + transitions | `identity.py` | `get_path_identities`, `get_identity_transitions` |
| Application states + transitions | `state_model.py` | `get_path_state`, `get_state_transitions` |
| Privilege transitions (vert/horiz/deputy) | `privilege.py` | `get_privilege_transitions`, `get_confused_deputy_paths` |
| Sensitive-data categories + impact | `sensitivity_data.py` | `get_sensitive_assets`, `analyze_path_sensitivity` |
| Search modes | `modes.py` | (via `run_attack_graph(search_mode=…)` / CLI `--mode`) |
| Blast radius | `blast.py` | `get_blast_radius` |
| Choke points / minimal cut | `choke.py` | `get_choke_points` |
| Fix impact (analysis only) | `fix_impact.py` | `analyze_fix_impact` |
| Plain-language explanation + rejection reasons | `explain.py` | `explain_path`, `get_rejected_path_reason` |
| Equivalence grouping (shared root cause) | `equivalence.py` | `get_equivalent_paths` |
| Tenant boundaries / AI paths / temporal | `api.py` | `get_tenant_boundaries`, `get_ai_attack_paths`, `get_temporal_dependencies` |

## Three-valued precondition logic (`logic.py`)

Reachability is rarely a flat list; it is an expression such as
`(public_network OR authenticated_session) AND attacker_controlled_input`.
Part 2 represents such expressions as JSON-serialisable `AND` / `OR` / `ATOM`
trees and evaluates them with **Kleene three-valued logic**:

- `AND` → `FALSE` if any operand is `FALSE`; else `UNKNOWN` if any is `UNKNOWN`;
  else `TRUE`.
- `OR`  → `TRUE` if any operand is `TRUE`; else `UNKNOWN` if any is `UNKNOWN`;
  else `FALSE`.

**The hard rule: `UNKNOWN` is never promoted to `TRUE`.** An attacker-supplied
atom (`satisfied_by == "attacker"`) is `TRUE`; everything else stays `UNKNOWN`
until an explicit resolver proves it. This mirrors the whole-project honesty
contract (unknown reachability → `UNVERIFIED`, never a confident claim).
`preconditions.py` gains opt-in `*_precondition_expr()` builders that emit these
trees; the original flat `*_preconditions()` helpers are unchanged.

## Identity model & transitions (`identity.py`)

Identity types: `ANONYMOUS`, `ATTACKER`, `AUTHENTICATED_USER`, `TENANT_USER`,
`PRIVILEGED_USER`, `SERVICE`, `SYSTEM`, `AI_AGENT`, `UNKNOWN`. A path is also a
sequence of identities the attacker occupies. Transitions are **evidence-backed
only**: a transition is emitted when a real `escalates_to` / `crosses_tenant` /
`invokes` / `yields` edge or an authenticated entrypoint justifies it, and it
carries that edge's evidence. The starting identity is derived from the
entrypoint's reachability (public → `ATTACKER`, authenticated → low-priv
session), never over-claimed.

## Application state model (`state_model.py`)

States: `UNAUTHENTICATED`, `AUTHENTICATED`, `AUTHORIZED`, `TENANT_SCOPED`,
`PRIVILEGED`, `TOOL_EXECUTION`, `COMPROMISED`, `UNKNOWN`. State is inferred
**lightly** and only from code-visible signals already in the graph — an
authenticated entrypoint, a control/guard node on the path, an
escalation/tenant/invoke edge, or a reached asset. With no code-visible guard
the state stays `UNKNOWN` rather than being invented. Each transition carries
the evidence that justified it.

## Privilege transitions (`privilege.py`)

Every identity transition is classified into a well-known pattern:

- **`vertical`** — a lower role becomes a higher one (user → admin), typically
  via `escalates_to` (see `priv_esc.py`).
- **`horizontal`** — same tier, different scope (tenant-A → tenant-B), via
  `crosses_tenant` (see `cross_tenant.py`).
- **`confused_deputy`** — a *trusted* component performs a privileged action on
  the attacker's behalf: SSRF (the server fetches an internal resource for the
  attacker — see `multi_chain.py`) or an agent that `invokes` a privileged tool
  from injected instructions (see `ai_chain.py`).

`privilege_graph()` rolls these up into a small identity→identity graph;
`get_confused_deputy_paths()` lists the path ids exhibiting the deputy pattern.

## Sensitive-data categories & impact (`sensitivity_data.py`)

Categories (with impact weight in `[0,1]`): `PUBLIC` 0.10, `INTERNAL` 0.40,
`CONFIDENTIAL` 0.60, `AI_CONTEXT` 0.70, `PII` 0.75, `FINANCIAL` 0.80,
`CREDENTIAL` 0.95, `SECRET` 1.00, `UNKNOWN` 0.30. The weight is an **impact**
dimension only — not a confidence, not a severity — and it never upgrades a
path's status. Categorisation reads the existing `asset.kind`; anything unmapped
falls back to `UNKNOWN` (deliberately *low*), so impact is never over-claimed
for data we cannot categorise.

## Search modes (`modes.py`)

A mode is an explicit, opt-in **status filter** over live paths:

- `CONFIRMED_ONLY` — only `CONFIRMED`.
- `CONFIRMED_AND_LIKELY` — `CONFIRMED` + `LIKELY` (the credible set).
- `INCLUDE_UNKNOWN` (default) — also `UNVERIFIED` (surface-for-review set).

`BLOCKED` / `INVALID` are **never live in any mode** — a blocked chain has an
effective barrier and an invalid chain does not exist. Modes never mutate the
written `attack-paths.json` `paths[]`: they filter a copy for display/querying.
`run_attack_graph(target, search_mode=…)` records the mode and re-derives the
`posture` view; the enumerated path set is identical regardless of mode.

## Bounded graph search (`search.py`)

A generic, **bounded, deterministic** BFS/DFS over `graph.nodes` / `graph.edges`
(depth-capped by `MAX_SEARCH_DEPTH`, result-capped by `MAX_SEARCH_RESULTS`). It
traverses **only edges that already exist** (never invents a hop), and prunes
(a) edges blocked by an *effective* control and (b) edges into a
`FALSE_POSITIVE` / `INVALID` finding. Neighbours are visited in a stable
`(edge type, to id)` order so results are reproducible.

## Blast radius (`blast.py`)

`get_blast_radius(node_id)` returns everything reachable from a compromised node
over evidence-backed, unblocked edges — grouped by type, with the reachable
sensitive assets, the single most-sensitive category reachable, and
representative shortest paths. A non-existent origin returns an empty, honest
result. `rank_blast_origins()` ranks likely compromise origins by radius impact.

## Choke points / minimal cut (`choke.py`)

`get_choke_points()` ranks nodes by **path-betweenness** (how many distinct
paths they lie on), weighting controls/findings slightly higher because they are
the natural remediation targets. `minimal_cut()` is a greedy set-cover
heuristic that picks choke points until all live paths are covered — advertised
as a heuristic, not an exact min-cut solver.

## Fix impact (`fix_impact.py`) — analysis only

`analyze_fix_impact(finding_or_control)` projects the effect of one remediation
**without editing code or re-running hunters**:

- Fixing a **finding** *removes* every path that traverses it.
- Hardening a **control** *blocks* (weakens) every path it gates — those chains
  become `BLOCKED`; the finding may still stand for an already-authorised actor.

`rank_fixes()` orders remediable nodes by how many paths a fix removes/weakens.

## Equivalence grouping (`equivalence.py`)

`get_equivalent_paths()` groups paths that reduce to the same underlying bug:
two paths are equivalent when they share a finding/candidate-seed node, or when
Part 1 already linked them via `shares_root_cause_with`. Each group names a
representative (highest-status, shortest) and the shared finding(s) — the single
fix target — so the path count is not inflated by re-framings of one root cause.

## Explanation & rejection reasons (`explain.py`)

`explain_path()` restates a path in plain language built **only** from the
evidence already on its nodes/edges (like `llm_stub`, it can never invent a
node, edge, credential, impact or reachability claim; `invented` is always
`False`). `rejected_path_reason()` / `get_rejected_path_reason()` render *why* a
path is not live (BLOCKED / INVALID / UNVERIFIED) from the path's own
`status_reasons`.

## New result fields (additive, backward compatible)

`run_attack_graph(...)` keeps every existing field and adds:

| Field | Meaning |
|---|---|
| `search_mode` | the active mode (default `INCLUDE_UNKNOWN`) — does **not** filter `paths[]` |
| `identity_transitions` | evidence-backed identity moves across all paths |
| `privilege_transitions` | vertical / horizontal / confused-deputy transitions |
| `state_transitions` | application-state moves across all paths |
| `rejected_paths` | BLOCKED / INVALID paths with plain-language reasons |
| `posture` | rollup: reachable identities/states, max sensitivity, privilege-pattern counts, confused-deputy paths, top choke points, top blast origins, live-vs-rejected counts |

`ensure_no_secret_values` runs over the whole result (including these fields),
and the private `_evidence` ref is still stripped by the writer.

## Public query API (`engines.attack_graph.api`)

Deterministic, read-only helpers over a `run_attack_graph(...)` result:
`get_path_state`, `get_path_identities`, `get_privilege_transitions`,
`get_tenant_boundaries`, `get_sensitive_assets`, `get_blast_radius`,
`get_equivalent_paths`, `get_choke_points`, `analyze_fix_impact`,
`analyze_path_sensitivity`, `get_rejected_path_reason`,
`get_temporal_dependencies` (thin but real: per-path ordered prerequisites),
`get_state_transitions`, `get_identity_transitions`,
`get_confused_deputy_paths`, `get_ai_attack_paths`, plus `explain_path`.

## CLI (`axguard paths` — new optional view filters)

Display-only filters (the written `attack-paths.json` is always the full,
unfiltered set):

- `--mode CONFIRMED_ONLY|CONFIRMED_AND_LIKELY|INCLUDE_UNKNOWN`
- `--current` — only currently-exploitable paths (`CONFIRMED`/`LIKELY`)
- `--blocked` — only paths blocked by an effective control
- `--unknown` — only `UNVERIFIED` paths (for review)
- `--critical` — only paths reaching high-sensitivity assets (PII and above)
- `--shortest` — only the shortest-credible path per `(entry, target)`
- `--predictive` — attack-surface / architecture-drift signals (never current findings)
- `--diff PATH_A PATH_B` — compare two saved `attack-paths.json` artifacts
- `--what-if SCENARIO` — counterfactual paths marked `hypothetical: true` / `PREDICTIVE`

Distinguish clearly: **Current Finding** ≠ **Current Attack Path** ≠ **Blocked Path** ≠
**Predictive Risk** ≠ **Hypothetical Path**.

## Package layout (Part 2 additions)

```
engines/attack_graph/
  logic.py            AND/OR three-valued precondition logic (UNKNOWN never TRUE)
  identity.py         identity types + evidence-backed identity transitions
  state_model.py      application states + light, evidence-backed state transitions
  privilege.py        vertical / horizontal / confused-deputy privilege transitions
  sensitivity_data.py sensitive-data categories + impact weighting
  modes.py            search modes (status filters over live paths)
  search.py           bounded, deterministic BFS/DFS with blocked/impossible pruning
  blast.py            blast radius from a compromised node (evidence-backed edges)
  choke.py            choke-point / greedy minimal-cut heuristics
  fix_impact.py       analyze_fix_impact() — analysis only, no code edits
  explain.py          plain-language explanation + rejected-path reasons
  equivalence.py      group equivalent paths sharing a root cause
  api.py              public, deterministic query surface
  whatif.py           counterfactual scenarios (hypothetical only)
  diff.py             attack-graph artifact comparison
  predictive.py       surface / drift signals (not vulns)
  sbom.py             manifest-only dependency graph (no CVE DB)
  temporal.py         multi-step temporal chain heuristics
  cross_service.py    cross-service trust edges from app model
  aggregate.py        risk rollup (paths / root causes / choke points)
  posture.py          Entry→…→Impact posture narrative helper
  benchmark.py        fixture evaluation harness (measured counts only)
```

## Non-goals (Part 2)

- No new confidence/evidence system (unchanged from Part 1).
- No CVE database lookups; SBOM is declared-deps only.
- No automatic source modification or active exploitation.
- No LLM calls; `LLMAttackPathStub.invent()` still raises and is never invoked.
- `fix_impact` is projection only — it never edits source or re-runs hunters.
- HTML report approval UX lives in `engines/report_ux.py` (separate from this engine).
