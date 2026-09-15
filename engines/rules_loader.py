"""Load YAML/JSON rule packs from disk."""

from __future__ import annotations

import json
import re
from pathlib import Path


def load_rules(rules_dir: Path) -> list[dict]:
    if not rules_dir.exists():
        return []

    rules: list[dict] = []
    for path in sorted(rules_dir.rglob("*")):
        if path.suffix not in {".json", ".yml", ".yaml"}:
            continue
        if path.name.startswith("_"):
            continue
        data = _read_rule_file(path)
        for rule in data:
            rule.setdefault("id", path.stem)
            rule["_source"] = str(path.relative_to(rules_dir))
            if "pattern" in rule and "pattern_re" not in rule:
                rule["pattern_re"] = re.compile(rule["pattern"], re.MULTILINE)
            rules.append(rule)
    return rules


def _read_rule_file(path: Path) -> list[dict]:
    text = path.read_text(encoding="utf-8")
    if path.suffix == ".json":
        data = json.loads(text)
        if isinstance(data, dict) and "rules" in data:
            return list(data["rules"])
        if isinstance(data, list):
            return data
        return [data]

    # Minimal YAML subset for rule packs: rely on JSON-compatible structure via json
    # when files are .yml — prefer .json until PyYAML is an optional dep.
    # For .yml/.yaml without PyYAML, skip with empty list if not JSON-parseable.
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return _parse_simple_yaml_rules(text)
    if isinstance(data, dict) and "rules" in data:
        return list(data["rules"])
    if isinstance(data, list):
        return data
    return [data]


def _parse_simple_yaml_rules(text: str) -> list[dict]:
    """Parse a narrow YAML subset used by AXguard rule files (no PyYAML required)."""
    rules: list[dict] = []
    current: dict | None = None
    for raw in text.splitlines():
        line = raw.rstrip()
        if not line or line.lstrip().startswith("#"):
            continue
        if line.startswith("- id:"):
            if current:
                rules.append(current)
            current = {"id": line.split(":", 1)[1].strip().strip("\"'")}
            continue
        if current is None:
            continue
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        key = key.strip().lstrip("- ").strip()
        value = value.strip().strip("\"'")
        if key:
            current[key] = value
    if current:
        rules.append(current)
    return rules
