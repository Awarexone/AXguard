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

2. Open HTML; ensure severity summary + findings read cleanly. The HTML report is **read-only** with an approval banner ("No source files were modified. No external requests were made."). Interactive actions are approval-gated client-side: expanding the full attack graph, revealing full source context, and exporting a detailed report ask first; high-risk actions (apply fix / active verification / external share) open a dialog but are **never executed** by the report (they require the CLI). See `docs/architecture.md` → "HTML report approval / consent model".
3. Optionally tighten the Markdown narrative for humans (keep evidence accurate).
4. Point the user at:

```
.findings/axguard/axguard-report.html
.findings/axguard/axguard-report.md
.findings/axguard/axguard-report.json
```

No author fluff. Impact-first language.
