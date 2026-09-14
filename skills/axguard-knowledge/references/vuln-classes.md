# Pre-ship vulnerability classes

Defensive static-review distillations. Each entry: root cause → what to look for in code/config → fix. Not live exploit playbooks.

---

## 1. Broken access control / IDOR

- **CWE / OWASP:** CWE-639 (and CWE-284/285) · A01:2021
- **Root cause:** Object or action authorized by “is logged in” or by knowing an id, not by ownership/role/tenant policy.
- **Static hints:** `get(id)` / `find_by_id` / `WHERE id = ?` without `user_id`/`tenant_id`; missing middleware on `/admin`; mass-assignment of `role`/`is_admin`.
- **Fix:** Authorize every object access; deny by default; enforce tenant scope in the data layer; never trust client-supplied roles.

## 2. Authentication / session / CSRF

- **CWE / OWASP:** CWE-287, CWE-384, CWE-352 · A07
- **Root cause:** Weak session binding, missing authn on sensitive routes, or cookie-session state-changing requests without anti-forgery.
- **Static hints:** `csrf=False` / `csrf.exempt`; sessions without Secure/HttpOnly/SameSite; password compare not constant-time (language-specific).
- **Fix:** Strong session cookies; CSRF tokens or SameSite strategies appropriate to the stack; authn required before authz.

## 3. JWT misuse

- **CWE / OWASP:** CWE-347, CWE-287 · A07 / A02
- **Root cause:** Trusting token contents without signature verification, or accepting `alg=none` / algorithm confusion.
- **Static hints:** `algorithm(s) = none`; `jwt.decode` / `verify=False` on auth path; hard-coded HMAC secrets.
- **Fix:** Explicit algorithm allowlist; always verify; asymmetric keys from KMS/secrets manager; short TTL + revocation strategy.

## 4. SQL injection

- **CWE / OWASP:** CWE-89 · A03
- **Root cause:** Attacker-influenced strings concatenated or formatted into SQL.
- **Static hints:** f-strings/`%`/`format`/`+`/`` `${}` `` into `execute`; ORM `.raw` / `text()` with unbound user input; PHP `mysqli_query` with `$var`.
- **Fix:** Parameterized queries or typed builders; never interpolate untrusted values into SQL text.

## 5. Command / code injection

- **CWE / OWASP:** CWE-78, CWE-94, CWE-95 · A03
- **Root cause:** OS shell or dynamic code evaluation on untrusted input.
- **Static hints:** `os.system`/`popen`; `subprocess(..., shell=True)`; `child_process.exec(string)`; `eval`/`exec`.
- **Fix:** Argv arrays with `shell=False`; allowlist arguments; never `eval` request or model text.

## 6. Server-side template injection (SSTI)

- **CWE / OWASP:** CWE-1336, CWE-94 · A03
- **Root cause:** User input compiled or rendered as a template (code), not as data.
- **Static hints:** `render_template_string`; Jinja `Template(user)`; Pug/Jade `compile` on request data.
- **Fix:** Templates from files only; pass user data as variables; keep autoescape on.

## 7. Insecure deserialization

- **CWE / OWASP:** CWE-502 · A08 / A03
- **Root cause:** Native object deserialization reconstitutes attacker-controlled types/gadgets.
- **Static hints:** `pickle.loads`; PHP `unserialize`; Java `ObjectInputStream`/`readObject` on network/queue/cookie data.
- **Fix:** JSON or other data-only formats; allowlisted deserializers if native formats are mandatory.

## 8. Path traversal / LFI

- **CWE / OWASP:** CWE-22, CWE-98 · A01 / A03
- **Root cause:** User-controlled path segments escape the intended directory or are included as code.
- **Static hints:** `open(os.path.join(base, user))`; `send_file`/`sendFile` with variable path; PHP `include`/`require` with `$var`.
- **Fix:** Resolve paths and enforce a prefix jail; map ids to server-side paths; never include user-supplied paths.

## 9. SSRF

- **CWE / OWASP:** CWE-918 · A10:2021
- **Root cause:** Server fetches a caller-influenced URL, reaching internal or metadata services.
- **Static hints:** `requests.get(url)` / `fetch(url)` where `url` comes from request; hard-coded metadata IPs in app logic.
- **Fix:** Allowlist schemes and hosts; block link-local and cloud metadata ranges; do not follow redirects to internals.

## 10. Cross-site scripting (XSS)

- **CWE / OWASP:** CWE-79 · A03
- **Root cause:** Untrusted data interpreted as HTML/JS in a victim browser.
- **Static hints:** `innerHTML`, `document.write`, React `dangerouslySetInnerHTML` fed from API/user content; unescaped templates.
- **Fix:** Safe text bindings; contextual encoding; sanitize only with well-maintained libraries; CSP as defense-in-depth.

## 11. Unsafe file upload

- **CWE / OWASP:** CWE-434 · A04
- **Root cause:** Uploaded content becomes executable or overwrites sensitive paths via name/type confusion.
- **Static hints:** Save with `originalname`/`filename`; `multer.any()`; no size/type checks; write under web root.
- **Fix:** Random server-side names; allowlist extensions + content sniffing; store outside executable/static roots; virus/size limits.

## 12. GraphQL issues

- **CWE / OWASP:** CWE-200, CWE-352, CWE-639 · A01 / A05
- **Root cause:** Over-exposed schema, missing field-level authz, or CSRF on cookie-authenticated mutations.
- **Static hints:** Introspection enabled in prod config; CSRF protection disabled on GraphQL endpoint; resolvers that load by id without authz.
- **Fix:** Disable prod introspection; authorize in resolvers/data layer; CSRF strategy for cookie sessions; query depth/cost limits.

## 13. Secrets in source or artifacts

- **CWE / OWASP:** CWE-798, CWE-321 · A07 / A02
- **Root cause:** Long-lived credentials committed or baked into images/build outputs.
- **Static hints:** AWS key patterns, PEM blocks, `api_key = "..."`, GitHub/Slack tokens in repo or CI logs.
- **Fix:** Rotate immediately; move to a secret manager; scrub git history if needed; block via pre-commit/CI secret scan.

## 14. Cloud & CORS misconfiguration

- **CWE / OWASP:** CWE-942, CWE-284 · A05
- **Root cause:** Over-permissive browser or storage trust boundaries.
- **Static hints:** `Access-Control-Allow-Origin: *` with credentials; reflected Origin without allowlist; S3 `public-read` / ACL public.
- **Fix:** Explicit origin allowlists; private buckets with signed URLs; least-privilege IAM.

## 15. Cryptographic misuse

- **CWE / OWASP:** CWE-321, CWE-328, CWE-338, CWE-295 · A02
- **Root cause:** Homegrown or obsolete crypto; hard-coded keys; disabled authenticity checks.
- **Static hints:** Hard-coded key/IV; MD5/SHA1 for passwords; `Math.random` for security tokens; `verify=False` / insecure TLS.
- **Fix:** Battle-tested libraries; password KDFs (argon2/bcrypt/scrypt); CSPRNG; TLS verification on; keys from KMS.

## 16. Supply chain / CI integrity

- **CWE / OWASP:** CWE-494, CWE-506 · A08
- **Root cause:** Untrusted code execution during install or build.
- **Static hints:** `curl|sh` / `wget|sh` in CI or Docker; `pip --extra-index-url`; suspicious npm `preinstall`/`postinstall`.
- **Fix:** Lockfiles and hash pins; review lifecycle scripts; prefer official images with digests; avoid pipe-to-shell.

## 17. Debug & verbose error exposure

- **CWE / OWASP:** CWE-489, CWE-209, CWE-200 · A05
- **Root cause:** Development diagnostics enabled on reachable deployments.
- **Static hints:** Django `DEBUG = True`; Flask `debug=True`; Express verbose error middleware in prod; Spring Actuator exposure without auth.
- **Fix:** Debug off in production config; generic client errors; authenticate and minimize actuators/admin endpoints.

## 18. LLM / agent tool risks

- **CWE / OWASP:** CWE-77, CWE-78, CWE-94 · OWASP Top 10 for LLM Apps (e.g. prompt injection, excessive agency)
- **Root cause:** Model or tool output treated as trusted instructions or shell; tools overly powerful.
- **Static hints:** Execute/shell tools wrapping model text; unrestricted bash tool; prompt content concatenated into `os.system`/`exec`.
- **Fix:** Strict tool allowlists; no raw shell-from-LLM; sandbox; human approval for high-impact actions; separate untrusted content from system control plane.

## Cross-cutting review tips

- Prefer **source → sink → control** over pattern-match faith.
- Ship path matters: prod config and Docker/CI beat local-only examples.
- When a control exists but is bypassable on another route, keep the finding and name the bypass route.
