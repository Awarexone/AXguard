# AXguard — Agent Skills

```bash
./install.sh --agent agents
./install.sh --agent agents --project
```

## Start here

| Doing | Command / skill |
|---|---|
| Full audit | `/axguard-audit` or skill `axguard-audit` |
| Security lead pass | skill `axguard-cso` |
| Triage | `/axguard-triage` |
| Fix | `/axguard-fix` / skill `axguard-remediate` |
| Report | `/axguard-report` |

CLI:

```bash
pip install -e .
axguard help
axguard audit .
```
