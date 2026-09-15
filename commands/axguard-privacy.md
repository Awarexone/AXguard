---
description: Local privacy prefs for contribution learning (opt-in). Usage: /axguard-privacy …
---

# /axguard-privacy

**Specialist:** Contributor privacy center

Shows what AXGuard stores for contribution learning, what stays local, and how
to opt in/out, export, or delete. Defaults are off — no network, no telemetry.

## Usage

```
/axguard-privacy status
/axguard-privacy show
/axguard-privacy opt-in
/axguard-privacy opt-in --learning
/axguard-privacy opt-out
/axguard-privacy export -o .findings/axguard/privacy-export.json
/axguard-privacy delete
/axguard-privacy reset
```

CLI equivalent: `axguard privacy <subcommand>`.

## Focus

- Prefs live at `~/.axguard/privacy.json`
- Packaging and learning require explicit opt-in
- Included vs excluded field lists (no credentials, tokens, private repo IDs)
- Export / delete / reset for local learning data only
- GitHub push/PR is never automatic

## Steps

1. `axguard privacy status` — current opt-in and learning flags
2. `axguard privacy show` — included/excluded fields and notes
3. Opt in only when you intend to prepare a local contribution package
4. `axguard privacy delete` or `reset` to clear local learning copies

See [docs/contributors/README.md](../docs/contributors/README.md).
