"""Lightweight dataset poisoning / instruction-injection heuristics.

Flags suspicious training rows. Never executes dataset-embedded code.
"""

from __future__ import annotations

import re
from typing import Any

_POISON_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("instruction_override", re.compile(r"(?i)ignore (all )?(previous|prior) instructions")),
    ("system_prompt_leak", re.compile(r"(?i)reveal (your |the )?system prompt")),
    ("label_flip", re.compile(r"(?i)always (mark|label) (this|code) as (safe|secure|benign)")),
    ("exfil_hint", re.compile(r"(?i)(exfiltrate|send secrets to|curl .{0,40}webhook)")),
    ("jailbreak", re.compile(r"(?i)(dan mode|developer mode|jailbreak)")),
]


def scan_poison(example: dict[str, Any]) -> list[dict[str, Any]]:
    blob_parts = [
        str(example.get("code") or ""),
        str(example.get("prompt") or ""),
        str(example.get("fix") or ""),
        str(example.get("context") or ""),
        json_ish(example.get("candidate")),
    ]
    blob = "\n".join(blob_parts)
    flags: list[dict[str, Any]] = []
    for name, pat in _POISON_PATTERNS:
        if pat.search(blob):
            flags.append(
                {
                    "example_id": example.get("example_id"),
                    "flag": name,
                    "pattern": pat.pattern,
                }
            )
    return flags


def json_ish(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    try:
        import json

        return json.dumps(value, ensure_ascii=False)
    except TypeError:
        return str(value)


def scan_examples(examples: list[dict[str, Any]]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for ex in examples:
        out.extend(scan_poison(ex))
    return out
