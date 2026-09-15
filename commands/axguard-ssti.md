---
description: Server-side template injection — Jinja/Flask render_template_string, Pug compile. Usage: /axguard-ssti [path]
---

# /axguard-ssti

**Specialist:** SSTI Hunter

## Usage

```
/axguard-ssti
/axguard-ssti ./app
```

## Focus

- `render_template_string` / Jinja `from_string`
- Pug/Jade `compile`/`render` on request-derived templates
- Any engine that evaluates template source from user input

## Steps

1. Scan → keep `ssti.*`.
2. Prove whether any part of the template source is attacker-controlled.
3. Fix: static templates only + autoescape; never render user-supplied template text.
