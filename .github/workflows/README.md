# AXGuard GitHub Actions

CI and repository security workflows for this project.

| Workflow | Purpose |
|---|---|
| `ci.yml` | Unit tests, skill validation, fixture self-scan |
| `codeql.yml` | CodeQL static analysis (Python) |
| `gitleaks.yml` | Secret detection (Gitleaks CLI) |
| `osv-scanner.yml` | Dependency vulns via OSV |
| `zizmor.yml` | GitHub Actions workflow security audit |
| `scorecard.yml` | OpenSSF Scorecard supply-chain posture |

All workflows are free/open-source oriented: no paid scanners or API keys.

See [SECURITY.md](../SECURITY.md) for vulnerability reporting.
