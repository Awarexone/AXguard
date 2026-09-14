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
axguard audit . --fail-on high --out-dir .findings/axguard
```
