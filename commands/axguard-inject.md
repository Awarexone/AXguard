---
description: Injection and RCE sinks — eval, exec, pickle, shell, child_process. Usage: /axguard-inject [path]
---

# /axguard-inject

**Specialist:** Injection Hunter

## Usage

```
/axguard-inject
/axguard-inject ./backend
```

## Focus

- `pickle.loads`, `eval`/`exec`, `shell=True`, `child_process.exec`
- SSTI / unsanitized template render (manual follow-up)
- SQL string concat (manual follow-up when ORM not used)

## Steps

1. Scan → keep `injection.*`.
2. Prove taint: who controls the argument?
3. Fix guidance must name the safe API (`execFile`, `json.loads`, parameterized queries).
