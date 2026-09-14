---
name: axguard-preship
description: Pre-ship security review checklist for the current repository. Use for focused release reviews covering auth, SQL/injection/SSTI, path, SSRF, XSS, uploads, GraphQL, crypto, secrets, cloud, supply chain, debug, and agent risks when a full /axguard-audit is not requested.
---

# AXguard — Pre-ship Review

Ship-blocking review. Prefer real bugs over volume. Defensive static review only.

Load `axguard-knowledge` when a class needs root-cause / fix depth.

## Workflow

1. Map surface: routes, APIs, auth boundaries, outbound HTTP, file/exec sinks, HTML sinks, upload handlers, GraphQL, CI/cloud, agent tools, debug flags.
2. Run when CLI available:

```bash
axguard scan .
# shareable reports:
axguard audit . --out-dir .findings/axguard
```

3. Verify each high/critical lead (source → sink → missing control).
4. Report only issues you can defend with file:line.

## Priority (ship blockers first)

| # | Class | CWE / OWASP | Static sniff |
|---|--------|-------------|--------------|
| 1 | AuthZ / IDOR | CWE-639, A01 | get-by-id without ownership/tenant |
| 2 | RCE / cmd / deser / eval | CWE-78/94/502, A03 | shell=True, pickle, eval, unserialize |
| 3 | SQLi / SSTI | CWE-89/1336 | string-built SQL; render_template_string |
| 4 | SSRF (esp. metadata) | CWE-918, A10 | variable URL → fetch/requests; 169.254.169.254 |
| 5 | Secrets in tree/artifacts | CWE-798 | AWS keys, PEM, PATs, hardcoded API secrets |
| 6 | Path traversal / LFI | CWE-22/98 | open(join), sendFile(user), include($var) |
| 7 | XSS on high-value pages | CWE-79 | innerHTML / dangerouslySetInnerHTML + user data |
| 8 | JWT / CSRF footguns | CWE-347/352 | alg=none, decode w/o verify, csrf=False |
| 9 | Upload RCE path | CWE-434 | original filename; multer.any; webroot writes |
| 10 | Crypto / TLS misuse | CWE-321/328/295 | hard-coded keys, MD5 passwords, verify=False |
| 11 | CORS / cloud ACL | CWE-942/284 | `*` + credentials; public-read buckets |
| 12 | GraphQL exposure | CWE-200/352 | prod introspection; CSRF off |
| 13 | Supply / CI | CWE-494/506 | curl\|sh; extra-index; shady postinstall |
| 14 | Debug in prod path | CWE-489/209 | DEBUG=True; stack traces; open actuators |
| 15 | Agent tool abuse | LLM01/LLM06 | exec model output; unrestricted shell tool |

## Fast pass (15–30 min)

- [ ] Auth on every object-id route; admin gated
- [ ] No string-built SQL / shell / pickle on request data
- [ ] Outbound URL allowlisted if user-influenced
- [ ] No secrets in source, images, or CI logs
- [ ] Client sinks not fed raw user HTML
- [ ] Uploads renamed + type-checked + non-executable storage
- [ ] Prod: DEBUG off, introspection off, TLS verify on
- [ ] Agent tools allowlisted; no blind shell-from-LLM
- [ ] Lockfiles present; no curl|sh install in ship path

## False-positive discipline

Drop: tests/fixtures (unless those ship), constant-only sinks, verified mitigations on the same path, docs examples that never build.

Keep: missing control on a reachable ship path, even if “exploit steps” are incomplete — state impact + fix.

## Output format

```
Title:
Severity:
CWE / OWASP:
Location:
Why it matters:
Evidence:
Fix:
Ship blocker? (Y/N)
```

End with: blocker count, non-blocker count, recommended next (`/axguard-triage`, `/axguard-fix`, or full `/axguard-audit`).
