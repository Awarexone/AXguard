# AXGuard GitHub Bot — PR UX

Tone and presentation rules for check output, inline annotations, and the single PR summary comment.

This document is the contract for how the bot speaks on pull requests. Implementers must follow it; marketing copy does not belong in security findings.

---

## Voice

Write like a professional security engineer reviewing a change:

- Precise, calm, evidence-first
- Short sentences; state what was found, where, and why it matters
- Prefer severity labels and concrete locations over adjectives
- Never hype, never beg, never spam

Findings are engineering communication, not product promotion.

---

## Check conclusions

| Conclusion | When to use |
|---|---|
| `PASS` | No verified issues; no meaningful regressions |
| `PASS_WITH_NOTES` | No blocking findings; informational notes or low-confidence observations only |
| `REVIEW_REQUIRED` | Verified or strong-evidence issues that need human judgment before merge |
| `FAIL` | Blocking verified issues, or a confirmed security regression versus the base |

### Example check output

```text
AXGuard Security Review
Conclusion: PASS
Findings: 0 verified · 0 review · 0 notes
Diff scope: 12 files · +340 / −28
```

```text
AXGuard Security Review
Conclusion: PASS_WITH_NOTES
Findings: 0 verified · 0 review · 2 notes
Notes:
  - auth/session.py: soft cookie flag without Secure in test config (informational)
  - api/upload.py: large multipart limit; confirm intentional for product UX
```

```text
AXGuard Security Review
Conclusion: REVIEW_REQUIRED
Findings: 1 verified · 1 review · 0 notes
Open:
  - [HIGH] IDOR on GET /api/orders/{id} — object ownership not enforced (api/orders.py:88)
  - [MEDIUM] SSRF candidate — user URL reaches requests.get without allowlist (workers/fetch.py:41)
```

```text
AXGuard Security Review
Conclusion: FAIL
Findings: 2 verified · 0 review · 0 notes
Blocking:
  - [CRITICAL] Hardcoded production API key in src/config.py:12
  - [HIGH] REGRESSED — SQL injection path previously RESOLVED on main (db/query.py:55)
```

---

## Annotation rules

Annotate only when the finding meets at least one bar:

1. **Verified** — reproduced or confirmed by the verification pipeline
2. **Strong evidence** — high-confidence static/dataflow signal with a clear sink and reachable source
3. **Meaningful regression** — a previously fixed or absent issue that reappears or worsens on this PR

Do **not** annotate:

- Speculative “might be vulnerable” noise
- Style, lint, or non-security nits
- Duplicate noise for the same root cause (one primary annotation; link related sites in the summary)
- Findings already marked resolved and still fixed on this PR

Annotation text should name the issue class, the evidence, and the risk in one or two lines. No exclamation marks as urgency theater.

---

## Single PR summary comment

Post **one** summary comment per pull request. Update that comment on subsequent runs; do not open a new comment each push.

### Marker

Every AXGuard summary comment must include this HTML comment marker (exact string):

```html
<!-- AXGUARD-SECURITY-REVIEW -->
```

### Update-not-spam

1. Search existing PR comments for `<!-- AXGUARD-SECURITY-REVIEW -->`.
2. If found, **edit** that comment in place with the latest summary.
3. If not found, create exactly one new comment containing the marker.
4. Never reply-thread duplicates, never “bump” with another summary, never re-post after every commit.

### Summary structure (recommended)

```markdown
<!-- AXGUARD-SECURITY-REVIEW -->

## AXGuard Security Review

**Conclusion:** REVIEW_REQUIRED

| Status | Count |
|---|---|
| Open / blocking | … |
| Review required | … |
| Notes | … |
| Resolved this run | … |
| Regressed | … |

### Findings
- …

### Attack path changes
- …

---
AXGuard by Awarexone / Open-source security tooling for the AI era.
```

---

## Finding lifecycle language

Use these status words consistently in check output, annotations, and the summary comment:

| Status | Meaning |
|---|---|
| `RESOLVED` | Issue reported earlier is no longer present / no longer reachable on this PR |
| `REGRESSED` | A previously resolved (or base-clean) issue is present again or worse |
| `FIX VERIFIED` | Remediation was checked; the prior issue no longer reproduces under the same evidence bar |
| `FIX NOT VERIFIED` | Change claims a fix, but verification did not confirm it (still open or inconclusive) |

Examples:

```text
[HIGH] RESOLVED — IDOR on GET /api/orders/{id} (ownership check added)
[HIGH] REGRESSED — hardcoded secret reintroduced in src/config.py:12
[MEDIUM] FIX VERIFIED — SSRF allowlist blocks user-controlled host
[MEDIUM] FIX NOT VERIFIED — sanitize() added but tainted path still reaches sink
```

Do not invent softer synonyms that dilute lifecycle clarity.

---

## Attack path regression wording

When the attack graph / path engine reports a change versus the base or a prior run:

- Prefer concrete path language over vague “risk increased”
- Call out new hops, restored edges, or reopened chains explicitly
- Use `REGRESSED` when a path that was closed returns

Preferred patterns:

```text
Attack path REGRESSED: UserInput → TemplateRender → XSS (was RESOLVED on base)
New attack path: AuthBypass → IDOR → PII export (3 hops; strong evidence)
Attack path shortened (worse): SSRF → CloudMetadata (hop removed; blast radius broader)
Attack path RESOLVED: RCE chain UserInput → Deserialization no longer reachable
```

Avoid:

```text
Potential vulnerability!!! Attack surface got worse somehow.
```

---

## Allowed footer

The PR summary comment may end with exactly this attribution line (or the same text after a horizontal rule):

```text
AXGuard by Awarexone / Open-source security tooling for the AI era.
```

No other promotional footer on findings, annotations, or check titles.

---

## Forbidden

Never include in check output, annotations, or the security summary comment:

- Marketing copy inside findings (“ship faster with AXGuard”, “join the community”)
- Star begging or social CTAs (“⭐ Star us on GitHub”, follow/like asks)
- Spam: duplicate comments, @-mention storms, or re-posting the full report every push
- Hype or scare punctuation: `Potential vulnerability!!!`, `URGENT!!!`, emoji-led panic
- Dark patterns: fake urgency, invented severity, or social-proof claims unrelated to the diff
- Upsell or pricing pitches in findings

Security communication stays clinical. Engagement and product messaging belong elsewhere (if at all)—not in PR security UX.
