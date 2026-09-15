# AXguard — Commands Quick Ref

> Start with the workflow you need.

| Doing this | Run |
|---|---|
| Full pre-ship audit + HTML/MD | `/axguard-audit` |
| Fast scan | `/axguard-scan` |
| Map app / attack surface | `/axguard-surface` |
| Dataflow / taint paths | `/axguard-flow` |
| Hunter → Judge verification | `/axguard-verify` |
| False Positive Adversary | `/axguard-adversary` |
| Evidence & Confidence | `/axguard-evidence` |
| Attack graph / vuln chaining | `/axguard-paths` |
| Security Memory | `axguard memory …` |
| Investigation Agent | `axguard investigate …` |
| Training-data pipeline | `/axguard-data` |
| Threat model first | `/axguard-threat-model` |
| Secrets only | `/axguard-secrets` |
| Auth / IDOR | `/axguard-auth` |
| Injection / RCE sinks | `/axguard-inject` |
| SQL injection | `/axguard-sql` |
| SSTI | `/axguard-ssti` |
| Path traversal / LFI | `/axguard-path` |
| SSRF | `/axguard-ssrf` |
| XSS | `/axguard-xss` |
| Cloud / CORS | `/axguard-cloud` |
| Crypto misuse | `/axguard-crypto` |
| Supply chain | `/axguard-supply` |
| GraphQL | `/axguard-graphql` |
| File upload | `/axguard-upload` |
| Debug exposure | `/axguard-debug` |
| AI agent risks | `/axguard-agent` |
| Kill false positives | `/axguard-triage` |
| Patch confirmed bugs | `/axguard-fix` |
| Regenerate reports | `/axguard-report` |
| Add CI gate | `/axguard-ci` |
| About / engagement prefs | `axguard about` · `axguard engage disable` |

## Default pipeline

```text
/axguard-surface → /axguard-threat-model → /axguard-audit → /axguard-triage → /axguard-fix → /axguard-report → /axguard-ci
```

## Report paths

```
.findings/axguard/axguard-report.html
.findings/axguard/axguard-report.md
.findings/axguard/application-model.json
.findings/axguard/application-model.md
.findings/axguard/dataflow.json
.findings/axguard/dataflow.md
.findings/axguard/verification.json
.findings/axguard/verification.md
.findings/axguard/adversary.json
.findings/axguard/adversary.md
.findings/axguard/evidence.json
.findings/axguard/evidence.md
.findings/axguard/attack-paths.json
.findings/axguard/attack-paths.md
.findings/axguard/memory/
.findings/axguard/investigation/
.findings/axguard/data/data-pipeline.json
.findings/axguard/data/data-pipeline.md
.findings/axguard/data/data-pipeline.html
.findings/axguard/axguard-report.json
```

## CLI

```bash
axguard help
axguard version   # 0.2.0
axguard audit .
axguard scan .
axguard surface .
axguard flow .
axguard verify .
axguard adversary .
axguard evidence .
axguard paths .   # alias: axguard attack-paths .
axguard memory record .
axguard investigate . --fast
axguard investigate . --deep
axguard investigate . --finding FINDING_ID
axguard investigate --explain FINDING_ID
axguard about
axguard engage disable
axguard data discover
axguard data report fixtures/data_pipeline
axguard twin build .   # Security Twin — see docs/twin/README.md
axguard audit . --fail-on high --out-dir .findings/axguard
```

## Risk aggregation & posture (Phase 6 Part 2)

`engines/attack_graph/aggregate.py` (risk rollup: root causes, credible/
blocked paths, choke points) and `engines/attack_graph/posture.py`
(`Entry → Trust → Controls → Weak → Vulns → Priv → Assets → Impact` narrative)
are importable helpers on top of `run_attack_graph()` — not yet CLI-wired.
See [`commands/axguard-paths.md`](commands/axguard-paths.md). A regression
corpus for this phase lives in `fixtures/attack_paths_corpus/`.
