---
description: Fast vulnerability scan (text/JSON). No full report suite. Usage: /axguard-scan [path]
---

# /axguard-scan

**Specialist:** Scanner

Quick pass while coding. Prefer `/axguard-audit` when the user wants HTML/MD deliverables.

## Usage

```
/axguard-scan
/axguard-scan ./src
```

## Steps

```bash
axguard scan <path>
axguard scan <path> --format json -o .findings/axguard/scan.json
```

Print findings with file:line. Offer `/axguard-audit` if they need a shareable report.
