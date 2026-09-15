# Authentication

Default: localhost bind with optional auth.

```bash
# Require keys even on loopback
export AXGUARD_API_REQUIRE_AUTH=1

axguard api keys create --name ci --scopes 'scans:write,findings:read,projects:read'
```

```http
Authorization: Bearer axg_...
```

Keys are hashed at rest, shown once at creation, rotatable via create+revoke. No AwareXone accounts.
