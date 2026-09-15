# AXGuard GitHub Actions

CI and repository security workflows for this project.

| Workflow | Purpose |
|---|---|
| `ci.yml` | Unit tests, skill validation, fixture self-scan |
| `axguard.yml` | AXGuard Security Review on PRs / main (`audit engines` + `cli` `--fail-on high`; fixtures excluded) |
| `codeql.yml` | CodeQL static analysis (Python) |
| `gitleaks.yml` | Secret detection (Gitleaks CLI) |
| `osv-scanner.yml` | Dependency vulns via OSV |
| `zizmor.yml` | GitHub Actions workflow security audit |
| `scorecard.yml` | OpenSSF Scorecard supply-chain posture |

All workflows are free/open-source oriented: no paid scanners or API keys.

GitHub App (Check Runs + PR comment) is separate — see [docs/github/README.md](../../docs/github/README.md).
Actions `axguard.yml` dogfoods Core without a webhook receiver.

See [SECURITY.md](../SECURITY.md) for vulnerability reporting.
