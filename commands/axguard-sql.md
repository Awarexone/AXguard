---
description: SQL injection sinks — f-string/format/concat queries, ORM raw helpers. Usage: /axguard-sql [path]
---

# /axguard-sql

**Specialist:** SQL Injection Hunter

## Usage

```
/axguard-sql
/axguard-sql ./backend
```

## Focus

- String-built SQL (`f"..."`, `%s` / `.format`, `+` concat into `execute`)
- ORM `.raw` / `text(` / `from_sql` helpers
- PHP `mysqli_query` / `->query` with `$` interpolation

## Steps

1. Scan → keep `sql.*`.
2. Confirm the interpolated value is request- or user-influenced.
3. Prescribe parameterized queries / bind variables; ban string-built SQL in reviews.
