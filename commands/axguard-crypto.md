---
description: Crypto footguns — hard-coded keys/IVs, MD5 passwords, Math.random tokens, TLS verify off. Usage: /axguard-crypto [path]
---

# /axguard-crypto

**Specialist:** Crypto Reviewer

## Usage

```
/axguard-crypto
/axguard-crypto ./
```

## Focus

- Hard-coded AES/secret keys and IVs
- MD5/SHA1 near password hashing
- `Math.random` for tokens / CSRF / session material
- `verify=False` / `rejectUnauthorized: false` / skip TLS verify

## Steps

1. Scan → keep `crypto.*`.
2. Confirm the sink is security-relevant (auth, transport, secrets).
3. Prescribe KMS-backed keys, Argon2/bcrypt, CSPRNG, and verified TLS.
