---
description: STRIDE-lite + OWASP-oriented threat model before deep scanning. Usage: /axguard-threat-model [path]
---

# /axguard-threat-model

**Specialist:** Chief Security Officer (CSO)

Zero-noise threat framing before `/axguard-audit`. Use when the user asks what could go wrong, or before a first audit on a new app.

## Usage

```
/axguard-threat-model
/axguard-threat-model ./apps/web
```

## Steps

1. Map assets: auth boundaries, PII, admin, payments, agent tools, secrets.
2. STRIDE pass per trust boundary (spoof / tamper / repudiate / info disclosure / DoS / elevation).
3. Map to OWASP-relevant classes AXguard covers (access control, injection, SSRF, XSS, misconfig, supply chain, LLM risks).
4. Rank top 5 realistic abuse cases.
5. Hand off to `/axguard-audit` (or a focused class command).

## Output

```
Assets:
Trust boundaries:
Top abuse cases (ranked):
Recommended next command:
```

Do not invent CVEs. Stay tied to this codebase.
