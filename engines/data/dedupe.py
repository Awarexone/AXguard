"""Content-hash deduplication for training examples."""

from __future__ import annotations

import hashlib
import json
from typing import Any


def example_fingerprint(example: dict[str, Any]) -> str:
    """Stable hash over the security-relevant payload (not volatile ids)."""
    payload = {
        "kind": example.get("kind"),
        "language": example.get("language"),
        "code": example.get("code"),
        "vulnerability_type": example.get("vulnerability_type"),
        "vulnerable": example.get("vulnerable"),
        "verdict": example.get("verdict"),
        "reason": example.get("reason"),
        "steps": example.get("steps"),
        "prompt": example.get("prompt"),
        "label": example.get("label"),
        "candidate": example.get("candidate"),
    }
    blob = json.dumps(payload, sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


def dedupe_examples(
    examples: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Return (unique_examples, duplicate_records)."""
    seen: dict[str, str] = {}
    unique: list[dict[str, Any]] = []
    duplicates: list[dict[str, Any]] = []
    for ex in examples:
        fp = example_fingerprint(ex)
        enriched = dict(ex)
        enriched["content_hash"] = fp
        if fp in seen:
            duplicates.append(
                {
                    "example_id": enriched.get("example_id"),
                    "duplicate_of": seen[fp],
                    "content_hash": fp,
                }
            )
            continue
        seen[fp] = str(enriched.get("example_id") or fp[:12])
        unique.append(enriched)
    return unique, duplicates
