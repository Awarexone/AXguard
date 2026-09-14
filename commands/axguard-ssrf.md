---
description: SSRF and unsafe egress — user-influenced fetch/requests, metadata IPs. Usage: /axguard-ssrf [path]
---

# /axguard-ssrf

**Specialist:** Egress Hunter

## Usage

```
/axguard-ssrf
```

## Focus

- `requests.*` / `fetch` with variable URLs
- Cloud metadata (`169.254.169.254`)
- Redirect + DNS rebinding as escalation notes (manual)

## Steps

1. Scan → keep `ssrf.*` and `cloud.aws-metadata-url`.
2. Confirm URL is request-influenced.
3. Prescribe allowlists + private-range blocks + IMDSv2 for cloud roles.
