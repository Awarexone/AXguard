---
description: Supply-chain risks — install scripts, untrusted indexes, curl|bash. Usage: /axguard-supply [path]
---

# /axguard-supply

**Specialist:** Supply-Chain Reviewer

## Usage

```
/axguard-supply
/axguard-supply ./
```

## Focus

- npm `preinstall`/`postinstall` that curl/wget/eval
- pip `--extra-index-url` / non-PyPI indexes
- `curl|bash` / `wget|sh` bootstrap patterns

## Steps

1. Scan → keep `supply.*`.
2. Audit lockfiles and CI for the same patterns.
3. Pin versions/hashes; verify downloads before execution; prefer official indexes.
