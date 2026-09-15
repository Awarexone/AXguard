---
description: Cloud and CORS misconfig — metadata URLs, wildcard origins. Usage: /axguard-cloud [path]
---

# /axguard-cloud

**Specialist:** Cloud Reviewer

## Usage

```
/axguard-cloud
```

## Focus

- Metadata IP usage in app code
- `Access-Control-Allow-Origin: *` with credentialed APIs
- Overly broad IAM / public buckets (manual when IaC present)

## Steps

1. Scan → keep `cloud.*`.
2. Inspect IaC / CI for public storage and wildcard principals when those files exist.
3. Report concrete blast radius (token theft, cross-origin data read).
