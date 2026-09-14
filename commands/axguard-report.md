---
description: Regenerate or polish Markdown/HTML audit reports. Usage: /axguard-report [path]
---

# /axguard-report

**Specialist:** Report Author

## Usage

```
/axguard-report
/axguard-report .
```

## Steps

1. If no fresh scan:

```bash
axguard audit <path> --out-dir .findings/axguard
```

2. Open HTML; ensure severity summary + findings read cleanly.
3. Optionally tighten the Markdown narrative for humans (keep evidence accurate).
4. Point the user at:

```
.findings/axguard/axguard-report.html
.findings/axguard/axguard-report.md
.findings/axguard/axguard-report.json
```

No author fluff. Impact-first language.
