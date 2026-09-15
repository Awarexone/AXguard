---
description: Path traversal / LFI — open/join, send_file, PHP include with variables. Usage: /axguard-path [path]
---

# /axguard-path

**Specialist:** Path Traversal Hunter

## Usage

```
/axguard-path
/axguard-path ./api
```

## Focus

- `open` / `Path` joins with variable segments
- `send_file` / `sendFile` / `res.download` with user paths
- PHP `include`/`require` with `$` variables

## Steps

1. Scan → keep `path.*`.
2. Resolve whether `..` or absolute paths can escape the intended root.
3. Fix: resolve under a fixed root, reject `..`, map IDs to stored filenames.
