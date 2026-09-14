#!/usr/bin/env python3
"""Validate AXGuard security skills: frontmatter, duplicates, index paths, structure."""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SKILL_ROOTS = [ROOT / "skills"]
INDEX = ROOT / "skills" / "index.yaml"


def iter_skills():
    for base in SKILL_ROOTS:
        if not base.exists():
            continue
        for path in sorted(base.rglob("SKILL.md")):
            yield path


def parse_frontmatter(text: str) -> tuple[dict[str, str], str]:
    if not text.startswith("---"):
        return {}, text
    parts = text.split("---", 2)
    if len(parts) < 3:
        return {}, text
    meta: dict[str, str] = {}
    for line in parts[1].splitlines():
        if ":" in line and not line.strip().startswith("-"):
            key, val = line.split(":", 1)
            meta[key.strip()] = val.strip().strip("\"'")
    return meta, parts[2]


def parse_index_paths(text: str) -> list[str]:
    paths: list[str] = []
    for line in text.splitlines():
        m = re.match(r"\s*path:\s*(.+)$", line)
        if m:
            paths.append(m.group(1).strip().strip("\"'"))
    return paths


def main() -> int:
    errors: list[str] = []
    names: dict[str, Path] = {}
    count = 0
    for path in iter_skills():
        count += 1
        text = path.read_text(encoding="utf-8")
        meta, body = parse_frontmatter(text)
        if not meta.get("name"):
            errors.append(f"{path}: missing frontmatter name")
            continue
        name = meta["name"]
        if name in names:
            errors.append(f"{path}: duplicate name '{name}' also in {names[name]}")
        names[name] = path
        if not meta.get("description"):
            errors.append(f"{path}: missing description")
        if "skills/security/" in str(path).replace("\\", "/"):
            for key in ("version", "domain", "license"):
                if key not in meta:
                    errors.append(f"{path}: security skill missing '{key}'")
            if "## Purpose" not in body:
                errors.append(f"{path}: missing ## Purpose section")
            if "## Research Provenance" not in body:
                errors.append(f"{path}: missing ## Research Provenance")
            if re.search(r"CWE-XXX|WSTG-XXXX|TODO_FRAMEWORK", body):
                errors.append(f"{path}: placeholder framework IDs present")

    if INDEX.exists():
        index_text = INDEX.read_text(encoding="utf-8")
        for rel in parse_index_paths(index_text):
            p = ROOT / rel
            if not p.is_file():
                errors.append(f"skills/index.yaml: missing path {rel}")
        # Every security domain skill should be registered
        for path in iter_skills():
            if "skills/security/" not in str(path).replace("\\", "/"):
                continue
            rel = str(path.relative_to(ROOT)).replace("\\", "/")
            if rel not in index_text:
                errors.append(f"skills/index.yaml: unlisted security skill {rel}")
    else:
        errors.append("skills/index.yaml missing")

    print(f"skills scanned: {count}")
    if errors:
        print("FAIL")
        for e in errors:
            print(f"  - {e}")
        return 1
    print("OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
