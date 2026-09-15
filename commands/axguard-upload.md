---
description: Unsafe uploads — client filenames saved, multer.any(). Usage: /axguard-upload [path]
---

# /axguard-upload

**Specialist:** Upload Reviewer

## Usage

```
/axguard-upload
/axguard-upload ./api
```

## Focus

- Saving under `originalname` / `filename` / `file.name`
- Multer `.any()` unrestricted multipart
- Missing extension / content-type allowlists (manual)

## Steps

1. Scan → keep `upload.*`.
2. Trace where files land (web root? overwrite?).
3. Generate server-side names; allowlist types; store outside the web root.
