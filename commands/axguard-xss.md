---
description: XSS sink hunt — innerHTML, document.write, dangerouslySetInnerHTML. Usage: /axguard-xss [path]
---

# /axguard-xss

**Specialist:** Client Security

## Usage

```
/axguard-xss
/axguard-xss ./web
```

## Steps

1. Scan → keep `xss.*`.
2. Trace whether the RHS is user/HTML/Markdown-controlled.
3. Prefer `textContent` / sanitized HTML with a maintained library.
