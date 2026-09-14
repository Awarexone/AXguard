# Adding rules

Rules are JSON objects in `rules/*.json`. Each file is a pack:

```json
{
  "rules": [
    {
      "id": "injection.python-pickle-loads",
      "title": "pickle.loads deserialization",
      "severity": "critical",
      "cwe": "CWE-502",
      "languages": ["python"],
      "pattern": "pickle\\.loads\\s*\\(",
      "message": "pickle.loads on untrusted data enables RCE.",
      "fix": "Use json/msgpack; never unpickle attacker input."
    }
  ]
}
```

## Fields

| Field | Required | Notes |
|---|---|---|
| `id` | yes | Stable dotted id: `domain.name` (e.g. `secrets.aws-access-key`) |
| `title` | yes | Short human title |
| `severity` | yes | `critical` \| `high` \| `medium` \| `low` \| `info` |
| `pattern` | yes | Python regex (`re.MULTILINE`) |
| `message` | yes | Why it matters |
| `fix` | recommended | Concrete remediation |
| `cwe` | recommended | e.g. `CWE-798` |
| `languages` | optional | Filters by suffix (`python`→`.py`, `javascript`→`.js`/`.jsx`, …) |

## Naming

- Pack file ≈ domain: `secrets.json`, `auth.json`, `injection.json`, …
- Rule ids must start with the phase prefix used in `engines/audit.py` (`PHASE_RULE_PREFIX`) so audit phase counts stay accurate.
- Prefer precise patterns over broad keyword spam.

## Workflow

```bash
# 1. Add rule to rules/<pack>.json
# 2. Add a vulnerable snippet under fixtures/
# 3. Test
pytest -q
axguard scan fixtures/vuln_app --no-banner

# 4. If new domain: add commands/axguard-<domain>.md + skill if needed
# 5. Update COMMANDS-QUICK-REF.md and README Start Using table
```

## If you add a new pack file

Also register it in `pyproject.toml` under `[tool.setuptools.data-files]` so non-editable installs still ship the pack:

```toml
"share/axguard/rules" = [
  "rules/secrets.json",
  # …
  "rules/your-pack.json",
]
```

Editable installs read directly from the repo `rules/` tree.

## Quality bar

- Must hit a fixture (or documented real-world pattern)
- Message + fix must be actionable
- Avoid matching unit-test-only noise when possible (or document that fixtures are intentional)
- Never commit live credentials — use obvious fakes (`sk_live_example_…`)
