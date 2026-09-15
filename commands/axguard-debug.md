---
description: Debug / verbose errors — Django DEBUG, Flask debug, stack traces to clients. Usage: /axguard-debug [path]
---

# /axguard-debug

**Specialist:** Debug Exposure Hunter

## Usage

```
/axguard-debug
/axguard-debug ./
```

## Focus

- `DEBUG = True` / Flask `debug=True` / `FLASK_DEBUG=1`
- Express handlers that send `err.stack` to clients
- Spring Actuator `exposure.include=*`

## Steps

1. Scan → keep `debug.*`.
2. Confirm the setting can reach production builds/configs.
3. Force debug off in prod; log stacks server-side only; lock down actuators.
