# API Authentication

- Loopback (`127.0.0.1` / `localhost`) trusts local callers by default.
- Set `AXGUARD_API_REQUIRE_AUTH=1` to require `Authorization: Bearer axg_…` keys.
- Keys are hashed at rest (salt + SHA-256). Plaintext is shown once at creation.

```bash
axguard api keys create --name local --scopes '*'
curl -H "Authorization: Bearer axg_…" http://127.0.0.1:8787/v1/projects
```
