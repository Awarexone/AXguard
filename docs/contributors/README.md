# Contributor Engagement & Learning

Transparent, respectful, **opt-in**, privacy-preserving contribution prompts and local packaging.

AXGuard may recognize useful local work (verified findings, false-positive rejections, regressions, attack paths) and optionally invite a contribution. Scoring measures whether a **contribution opportunity** exists — never personal worth, streaks, or rankings.

## Principles

1. **Opt-in** — packaging and learning stay off until you say so.
2. **Local by default** — no network or telemetry for learning.
3. **Prepare only** — never silent push or PR. GitHub OAuth / remote submit is future work.
4. **No dark patterns** — no fake praise, guilt, fake urgency, or fake leaderboards.
5. **Reuse** — scrubbing uses `engines.data.scrub`; messaging reuses the engagement engine.

## Journey

```text
observable work → opportunity signal → quality gate → recognition / invite
                                                      ↓ (explicit)
                                              axguard contribute prepare
                                                      ↓
                                   .findings/axguard/contribute/<id>/
```

Dismissal options:

- `not_now` — cooldown; no more invites this session
- `never_prompts` — stop contribution prompts
- `type` — never suggest that contribution type again

## Privacy

Prefs: `~/.axguard/privacy.json`

```bash
axguard privacy status
axguard privacy show          # includes included/excluded field lists
axguard privacy opt-in
axguard privacy opt-in --learning   # local learning copy only; still no upload
axguard privacy opt-out
axguard privacy export -o .findings/axguard/privacy-export.json
axguard privacy delete        # remove local learning data
axguard privacy reset         # prefs → defaults + clear learning data
```

Defaults:

```yaml
contributions:
  enabled: true
  prompts: true
  auto_prepare: false
  auto_push: false
  auto_pr: false
  learning: false   # opt-in
learning:
  contribution_data:
    enabled: false
```

## CLI

```bash
axguard contribute status
axguard contribute suggest [--context-json FILE] [--force]
axguard contribute prepare [--type TYPE] [--context-json FILE] [--learning]
axguard contribute dismiss not_now|never_prompts|type [--type TYPE]
axguard contribute milestones
axguard contribute templates
```

## Future (not in this MVP)

- GitHub OAuth App / authenticated PR creation
- Remote learning submit
- Hosted contribution dashboards
