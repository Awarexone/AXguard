# Security Twin

Symbolic security model built on top of the AXguard attack graph. The twin
aggregates application-model entities, attack-graph nodes/edges, and
evidence-backed relationships into a single queryable artifact — without
network access, exploit execution, or MCP/shell actions.

## Safety

- **OBSERVED** — directly from scan artifacts (app model, attack graph)
- **INFERRED** — derived with explicit uncertainty (e.g. unknown tool permissions)
- **SIMULATED** — counterfactual paths and attack simulation
- **ASSUMED** — virtual attacker profiles and what-if premises

SIMULATED and ASSUMED sections are never presented as confirmed findings.

## CLI

```bash
axguard twin build .
axguard twin show .
axguard twin attack . --profile PUBLIC_USER
axguard twin blast-radius . --entity agent:customer-support
axguard twin controls .
axguard twin what-if . --scenario remove_authz
axguard twin what-if . --remove-control tenant-isolation
axguard twin compare --before before.json --after after.json
axguard twin query . --question "Which controls protect customer data?"
axguard twin scenarios
axguard twin export-dataset . --out-dir .findings/axguard/twin
```

Artifacts default to `.findings/axguard/twin/` (`security-twin.{json,md,html}`).

## Quick start (Python)

```python
from pathlib import Path
from engines.twin import build_security_twin, run_twin

twin = build_security_twin(Path("."))
print(twin["summary"])

result = run_twin(Path("fixtures/attack_paths_app"), simulate=True, controls=True)
```

## CLI

```bash
pip install -e .

axguard twin build . --out-dir .findings/axguard/twin
axguard twin show .
axguard twin attack . --profile PUBLIC_USER
axguard twin blast-radius . --entity <ID>
axguard twin controls .
axguard twin what-if . --scenario remove_authz
axguard twin compare --before before.json --after after.json
axguard twin regression --before ./before --after ./after
axguard twin query . --question "Which controls protect the most paths?"
axguard twin scenarios
axguard twin export-dataset . --out-dir .findings/axguard/twin
```

Artifacts land under `.findings/axguard/twin/` (`security-twin.{json,md,html}`).

## Modules

| Module | Purpose |
|--------|---------|
| `build` | Construct twin from attack graph + app model |
| `simulate` | Symbolic path simulation with step explanations |
| `counterfactual` | What-if scenarios (wraps `attack_graph.whatif`) |
| `controls` | Control effectiveness / choke analysis |
| `blast_radius` | Entity blast radius with impact tags |
| `query` | Deterministic keyword Q/A |
| `regression` | Before/after twin comparison |
| `report` | Markdown + offline HTML reports |

## Research

See [docs/research/security-twin.md](../research/security-twin.md) for design notes.
