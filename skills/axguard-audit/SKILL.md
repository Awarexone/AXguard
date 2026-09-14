---
name: axguard-audit
description: Full A-Z pre-ship security audit. Run when the user asks to audit, scan for vulnerabilities, security review before publish, or generate an AXguard report. Covers secrets, auth/IDOR, SQL/SSTI/injection, path traversal, SSRF, XSS, uploads, GraphQL, crypto, CORS/cloud, supply chain, debug exposure, and AI-agent risks; writes Markdown and HTML reports.
---

# AXguard — Full Audit (A → Z)

Pre-ship gate for the current project. Deterministic scan first, then hunter-grade verification. Defensive review only — cite location + trigger path; do not write live exploit playbooks against third parties.

For class deep-dives, load `axguard-knowledge` (`references/vuln-classes.md`).

## Default action

1. Ensure CLI (`axguard version`). If missing, from the AXguard repo:

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -e .
```

2. Full audit:

```bash
axguard audit .
# or
axguard audit ./path/to/app --out-dir .findings/axguard
```

Quick mid-coding pass (no polished deliverable required):

```bash
axguard scan .
```

3. Artifacts:

- `.findings/axguard/axguard-report.md`
- `.findings/axguard/axguard-report.html`
- `.findings/axguard/axguard-report.json`

4. Triage critical/high with source → sink → missing control. Prefer `/axguard-triage` for noise; `/axguard-fix` only after confirmation.

## Phase map (rule packs)

| Phase | Packs | Focus |
|-------|--------|--------|
| surface | — | Routes, APIs, auth boundaries, sinks, configs, build/CI artifacts |
| secrets | `secrets`, `advanced` | Keys, tokens, PEM, GitHub/Slack PATs |
| auth | `auth`, `advanced` | IDOR/ownership, JWT none/decode-without-verify, CSRF off |
| sql | `sql` | Concat/f-string/raw ORM SQL |
| injection | `injection`, `advanced` | eval/exec, pickle, shell, child_process, os.system, unserialize |
| ssti | `ssti` | Jinja/Flask/Pug dynamic templates |
| path | `path` | open/join, sendFile, PHP include |
| ssrf | `ssrf`, `cloud` | User URL → fetch/requests; metadata IPs |
| xss | `xss` | innerHTML, document.write, dangerouslySetInnerHTML |
| upload | `upload` | Original filename save, multer.any |
| graphql | `graphql` | Introspection, CSRF off |
| crypto | `crypto` | Hard-coded keys/IV, MD5/SHA1 passwords, Math.random tokens, verify=False |
| cloud | `cloud` | Wildcard CORS+creds, public S3 ACL |
| supply | `supply` | npm lifecycle scripts, extra-index, curl\|sh |
| debug | `debug` | DEBUG=True, Flask debug, stack traces, Actuator |
| agent | `agent`, `advanced` | Executing model output, unrestricted shell tools |
| report | — | MD + HTML + JSON |

## Hunter checklist (verify scanner leads)

Work critical → high → medium. For each keep candidate: **sink**, **who triggers**, **impact one-liner**, **fix**.

### AuthZ / IDOR — CWE-639, OWASP A01

- Object fetch by id alone (`get(id)`, `find_by_id`, `WHERE id=?`) without `user_id` / `tenant_id` / ACL.
- Cross-tenant list/export endpoints; admin routes missing role gate.
- **FP:** internal admin-only tools with separate network auth; test helpers not shipped.
- **Fix:** authorize on every object access; deny by default; central policy helper.

### JWT / session — CWE-347, CWE-287

- `alg=none`, `jwt.decode` without verify, weak/shared secrets in source.
- **FP:** decode-only for display after prior verify.
- **Fix:** pin algorithms; verify always; rotate secrets out of repo.

### SQL injection — CWE-89, A03

- f-string / `%` / `+` / `` `...${}` `` into execute; ORM `.raw` / `text()` with unbound input.
- **FP:** constants-only SQL; bind params present on adjacent lines.
- **Fix:** parameterized queries / typed query builders only.

### Command / code injection — CWE-78, CWE-94, CWE-95

- `eval`/`exec`, `shell=True`, `child_process.exec(string)`, `os.system`/`popen`.
- **FP:** fixed argv lists; trusted build scripts with no user input.
- **Fix:** argv arrays, `shell=False`; never eval untrusted strings.

### Deserialization — CWE-502

- `pickle.loads`, PHP `unserialize`, Java `ObjectInputStream`/`readObject` on untrusted bytes.
- **FP:** pickle of local trusted cache only (still prefer safer formats).
- **Fix:** JSON/protobuf; allowlisted deserializers.

### SSTI — CWE-1336 / CWE-94

- `render_template_string`, Jinja from variable, Pug `compile` on user text.
- **FP:** static template names only.
- **Fix:** file-based templates; never compile user strings as code.

### Path traversal / LFI — CWE-22, CWE-98

- `open(join(base, user))`, `sendFile(userPath)`, PHP `include($var)`.
- **FP:** path already resolved + allowlisted under chroot.
- **Fix:** resolve + prefix-check against allowed root; never include user paths.

### SSRF — CWE-918, A10

- Variable URL into `requests`/`fetch`; cloud metadata URLs in code.
- **FP:** hardcoded allowlisted hosts; SSRF mitigations (scheme/host allowlist) nearby.
- **Fix:** allowlist schemes/hosts; block link-local/metadata; no user-controlled redirects to internals.

### XSS — CWE-79, A03

- `innerHTML` / `document.write` / `dangerouslySetInnerHTML` with untrusted data.
- **FP:** constant HTML; sanitized via trusted library with correct context.
- **Fix:** textContent / safe framework binding; contextual encode; CSP.

### Upload — CWE-434

- Save with original filename; `multer.any()`; no type/size/content checks.
- **FP:** uploads to isolated object storage with random keys + content-type sniffing.
- **Fix:** random server names; allowlist extensions + magic bytes; store outside web root.

### GraphQL — CWE-200, CWE-352

- Introspection in prod; CSRF protection disabled for cookie sessions.
- **FP:** internal staging with network controls documented.
- **Fix:** disable introspection in prod; auth on mutations; CSRF for cookie auth.

### Crypto misuse — CWE-321, CWE-328, CWE-338, CWE-295

- Hard-coded key/IV; MD5/SHA1 for passwords; `Math.random` for tokens; TLS verify disabled.
- **FP:** non-security checksums; test-only fixtures excluded from ship.
- **Fix:** KDF (bcrypt/argon2/scrypt); CSPRNG; secrets from KMS/env; verify TLS.

### Secrets — CWE-798, CWE-321

- AWS keys, API key assigns, PEM blocks, GitHub/Slack tokens in tree or build artifacts.
- **FP:** clearly fake placeholders (`EXAMPLE`, `changeme` in docs only) — still scrub if shippable.
- **Fix:** rotate; move to secret manager; pre-commit secret scan.

### Cloud / CORS — CWE-942, CWE-284

- `Access-Control-Allow-Origin: *` with credentials; public-read S3 ACL.
- **FP:** truly public static assets with no sensitive data.
- **Fix:** explicit origin allowlist; private buckets + signed URLs.

### Supply chain — CWE-494, CWE-506

- Suspicious `postinstall`; `pip --extra-index-url`; `curl|sh` in README/CI.
- **FP:** pinned official installers with checksums.
- **Fix:** lockfiles; pin hashes; avoid pipe-to-shell; review lifecycle scripts.

### Debug exposure — CWE-489, CWE-209, CWE-200

- Django/Flask DEBUG; verbose Express errors; Spring Actuator wide exposure.
- **FP:** local `.env.example` only — confirm prod config path.
- **Fix:** DEBUG off in prod; generic errors; lock actuators.

### LLM / agent — CWE-77, CWE-78, CWE-94 — OWASP LLM

- Tool executes model output / unrestricted shell; prompt→shell without policy.
- **FP:** dry-run / human-approval gates that always run before exec.
- **Fix:** allowlisted tools; no shell-from-LLM; sandbox + human confirm for high risk.

## Agent behavior

- Prefer `axguard audit` / `axguard scan` over ad-hoc grepping when CLI is installed.
- After scan: severity tally → walk critical/high with file:line evidence.
- Never claim confirmed without location + plausible trigger path.
- Chain: triage → remediate → report → CI as requested.

## Output contract

```
Critical: N
High: N
Medium: N
Low: N
Reports: .findings/axguard/axguard-report.{md,html,json}
```

For each confirmed finding: Title, Severity, CWE/OWASP (if known), Location, Why it matters, Evidence, Fix.
