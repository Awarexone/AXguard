---
name: axguard-triage
description: Triage AXguard scanner output — false-positive filter, severity promotion, and keep/drop gates per vuln class. Use after an audit when the user wants signal, not volume, or runs /axguard-triage.
---

# AXguard Triage

Fewer confirmed bugs beat a long maybe-list. Read `.findings/axguard/axguard-report.json` when present. If `.findings/axguard/adversary.json` is present, prefer adversary final statuses (`CONFIRMED` / `LIKELY` / `UNVERIFIED` / `FALSE_POSITIVE` / `REQUIRES_REVIEW`) over raw Judge labels when deciding Keep vs Drop. Else if `.findings/axguard/verification.json` is present, use Judge statuses (`VERIFIED` / `LIKELY` / `UNVERIFIED` / `FALSE_POSITIVE`) — hunters emit candidates only; do not promote pattern-only `UNVERIFIED` hits to critical. Defensive reasoning only.

## Gate (all must pass to keep)

1. **Real sink** in shipped code (not a test/fixture unless fixtures ship or CI deploys them).
2. **Reachability** — attacker-influenced data can reach it, or a required control is clearly absent.
3. **Impact** — more than style / theoretical purity.
4. **Actionable fix** — engineer knows what to change.

Fail any → **Drop**. Pass all → **Keep** with severity + evidence. Uncertain reachability → `needs-manual`, do not promote to critical.

## Severity rules

| Action | When |
|--------|------|
| Promote | Confirmed RCE/auth bypass/secret-in-prod with clear path; scanner said medium |
| Hold | Scanner severity matches evidence |
| Demote | Sink real but only authenticated admin on isolated network, or mitigated partially |
| Drop | Test-only, constant input, dead code, already parameterized/sanitized on path |

Critical reserved for: RCE, auth bypass, prod secret leak, unverified JWT / alg=none on auth path.

## Class-specific FP notes

| Lead type | Often false when… | Promote when… |
|-----------|-------------------|----------------|
| IDOR / get-by-id | Query also filters `user_id`/`tenant_id`; BOLA already enforced in middleware | Id-only load on user-facing API |
| JWT decode | Display-only after prior `verify` | Decode used for auth decisions |
| SQL concat | All fragments are constants / bind vars used | Request/body/params interpolated |
| `shell=True` / exec | Fixed string; no user input in command | Any request/file/model field in command |
| pickle / unserialize | Local trusted cache, never from network | Cookie, queue, upload, or request body |
| SSTI | Template **name** dynamic; string is static file | User string compiled as template |
| path open/join | `realpath` + prefix check to jail | User segment joins then opens/sends |
| SSRF | Host allowlist / no user URL | User URL or redirect to internal/metadata |
| XSS sinks | Constant HTML or strict sanitizer in correct context | User/HTML from API into sink |
| upload original name | Random key in object storage + no exec | Saved under web root / executable path |
| CORS `*` | No credentials; public CDN | `*` or reflect-origin **with** credentials |
| DEBUG flags | `.env.example` / local-only compose not used in prod | Prod config or default True |
| supply curl\|sh | Docs-only, not CI/ship script | Dockerfile, CI, install.sh ship path |
| agent exec | Human approval hard-gate always | Model/tool output → shell/exec |

## Workflow

```bash
# Prefer existing report; else regenerate
axguard audit . --out-dir .findings/axguard
```

1. Sort findings critical → low.
2. Apply gate per item; record Keep / Drop / needs-manual.
3. Re-rank kept items by blast radius (see `axguard-cso`).
4. Hand confirmed list to `/axguard-fix` or `/axguard-report`.

## Output

| Keep / Drop / Manual | ID | Severity | Location | One-line reason |
|----------------------|----|----------|----------|-----------------|

Close with: kept count, dropped count, manual count, recommended ship decision hint (blocker if any Keep ≥ high on auth/RCE/secret).
