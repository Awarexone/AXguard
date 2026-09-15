---
name: axguard-remediate
description: Apply concrete defensive fixes for confirmed AXguard findings and re-audit. Use with /axguard-fix after triage. Prefer minimal patches, critical first, then verify with axguard audit/scan.
---

# AXguard Remediate

Fix **confirmed** findings only (post `/axguard-triage`). Critical → high → medium. Minimal diffs. Re-audit and report delta.

Do not invent attack PoCs. Do not “fix” by deleting scanner rules. Class patterns: `axguard-knowledge`.

## Workflow

1. Input: triaged Keep list or `.findings/axguard/axguard-report.json` (kept items only).
2. Patch one class of issue at a time when possible.
3. Re-run:

```bash
axguard audit . --out-dir .findings/axguard
# or faster check:
axguard scan .
```

4. Report: fixed IDs, remaining blockers, new deltas.

## Fix patterns (defensive)

| Class | Do | Don't |
|-------|-----|--------|
| IDOR / AuthZ | Scope queries by principal/tenant; central authorize(object); deny default | Hide id only; check authn but skip authz |
| JWT | Pin alg allowlist; always verify; secrets from env/KMS | `decode` for auth; accept `none` |
| CSRF | Re-enable for cookie-session browsers; SameSite | Exempt entire API “for convenience” |
| SQLi | Bound parameters / query builder placeholders | Escape-and-concat; trust “ORM = safe” with `.raw` |
| Command inj | `subprocess` argv list, `shell=False`; allowlist args | `os.system`; interpolate into shell strings |
| Deser | JSON; reject pickle/unserialize on untrusted | “Only internal” queues without auth |
| SSTI | File templates only; autoescape on | `render_template_string(user)` |
| Path | `resolve()` + prefix jail; random ids for files | Trust `../` strip alone |
| SSRF | Scheme/host allowlist; block link-local/metadata | Blacklist-only hostnames |
| XSS | textContent / framework escape; CSP | Ad-hoc regex “sanitize” |
| Upload | UUID names; magic-byte allowlist; store outside web root | Original filename in static/ |
| GraphQL | Auth per field/mutation; introspection off in prod | Global CSRF off with cookies |
| Crypto | argon2/bcrypt; CSPRNG; TLS verify on | MD5 passwords; hard-coded IV/key |
| Secrets | Rotate + purge history if leaked; secret manager | Comment out key and leave in git |
| CORS | Explicit origins; never `*` with credentials | Reflect Origin unchecked |
| Cloud ACL | Private buckets; signed URLs | public-read for “speed” |
| Supply | Lockfile + hash pin; remove curl\|sh | Extra indexes without pin |
| Debug | DEBUG=False in prod settings; generic 500s | Rely on “we won't deploy this file” |
| Agent | Allowlisted tools; no shell-from-LLM; human gate | Pass tool args straight to bash |

## Patch quality bar

- Fix the **root cause**, not only the matched line if control belongs one layer up.
- Match project style; no drive-by refactors.
- If fix and exploit PoC both requested: **fix only**; refuse exploit/PoC in one short sentence.
- If a finding was wrong, say so and leave code unchanged — prefer triage honesty over cosmetic edits.

## Output contract

```
Fixed: [ids]
Partial: [ids + why]
Unchanged (disputed FP): [ids]
Re-audit: Critical/High/Medium/Low before → after
Reports: .findings/axguard/axguard-report.{md,html,json}
```
