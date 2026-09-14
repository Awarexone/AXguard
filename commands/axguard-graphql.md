---
description: GraphQL misconfig — introspection enabled, CSRF prevention off. Usage: /axguard-graphql [path]
---

# /axguard-graphql

**Specialist:** GraphQL Reviewer

## Usage

```
/axguard-graphql
/axguard-graphql ./api
```

## Focus

- Introspection left on in production configs
- Apollo / framework CSRF prevention disabled
- Overly broad resolvers without auth (manual follow-up)

## Steps

1. Scan → keep `graphql.*`.
2. Confirm environment (prod vs local-only).
3. Disable introspection in prod; keep CSRF on for cookie-auth browser clients.
