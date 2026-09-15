---
description: Wire AXguard into CI — fail on high/critical. Usage: /axguard-ci
---

# /axguard-ci

**Specialist:** Release Gate

## Usage

```
/axguard-ci
```

## Steps

1. Detect CI system (GitHub Actions preferred).
2. Add a job that installs AXguard and runs:

```bash
pip install -e .
axguard audit . --fail-on high --out-dir .findings/axguard
```

3. Upload `.findings/axguard/axguard-report.html` as an artifact when possible.
4. Document the gate in README or contributing docs if present.

Do not weaken `--fail-on` without the user asking.
