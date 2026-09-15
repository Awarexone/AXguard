---
description: Contextual contribution invites and local prepare (no auto-push). Usage: /axguard-contribute …
---

# /axguard-contribute

**Specialist:** Contributor Engagement & Learning

Recognizes meaningful local work, suggests a contribution type when quality is
strong, and prepares a **local** package (templates, commit/PR draft text).
Never pushes or opens a PR. No dark patterns — cooldown and dismiss controls.

## Usage

```
/axguard-contribute status
/axguard-contribute suggest [--context-json FILE] [--force]
/axguard-contribute prepare [--type TYPE] [--context-json FILE] [--learning]
/axguard-contribute dismiss not_now|never_prompts|type [--type TYPE]
/axguard-contribute milestones
/axguard-contribute templates
```

CLI equivalent: `axguard contribute <subcommand>`.

## Focus

- Opportunity score from observable work (not personal worth)
- Quality gate: novelty, reusability, relevance, testability
- Cooldown: at most one invite per meaningful session
- Dismiss: `not_now` / `never_prompts` / type
- Prepare writes under `.findings/axguard/contribute/<id>/`
- Scrubbing via `engines.data.scrub`; learning copy needs `--learning` + opt-in

## Steps

1. `axguard privacy opt-in` (required before prepare)
2. `axguard contribute suggest` after a useful audit/adversary session
3. Review the invite; dismiss if not wanted
4. `axguard contribute prepare` — inspect the package locally
5. Share / push / PR only under your own control (GitHub OAuth is future work)

See [docs/contributors/README.md](../docs/contributors/README.md).
