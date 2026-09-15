"""Poisoning defenses for Security Memory ingest.

Never treat README, comments, or repo-embedded override files as memory
instructions. Strip known injection keys and allow only schema-known fields.
"""

from __future__ import annotations

import re
from copy import deepcopy
from typing import Any

from engines.memory.schema import (
    CHANGE_OUTCOMES,
    CONTROL_STATES,
    FINDING_LIFECYCLES,
    ITEM_TYPES,
    PATH_CHANGE_TYPES,
    VALIDITIES,
)

# Keys that must never influence memory state (instruction injection).
_POISON_KEYS = frozenset(
    {
        "axguard_memory_instruction",
        "axguard_memory_override",
        "memory_instruction",
        "memory_override",
        "system_prompt",
        "ignore_previous_instructions",
        "jailbreak",
    }
)

_POISON_FILENAMES = frozenset(
    {
        "axguard_memory_override.json",
        "axguard_memory_instructions.md",
        ".axguard_memory_override",
        "MEMORY_INSTRUCTIONS.md",
    }
)

_INSTRUCTION_RE = re.compile(
    r"(?i)(ignore (all )?(previous|prior) instructions|"
    r"axguard_memory_instruction|"
    r"treat (this|readme) as (memory|system) instructions)"
)

# Allowlisted top-level / item keys for sanitized ingest payloads.
_ALLOWED_TOP = frozenset(
    {
        "schema_version",
        "tool",
        "kind",
        "snapshot_id",
        "generated_at",
        "source_revision",
        "target",
        "validity",
        "findings",
        "controls",
        "attack_paths",
        "evidence_refs",
        "verifications",
        "decisions",
        "assumptions",
        "unknowns",
        "security_twin",
        "summary",
        "provenance",
        "fingerprint",
        "lifecycle",
        "status",
        "item_type",
        "file",
        "files",
        "symbol",
        "line",
        "rule_id",
        "severity",
        "confidence",
        "hops",
        "entry",
        "target_id",
        "effectiveness",
        "id",
        "name",
        "label",
        "description",
        "content_hash",
        "evidence_ids",
        "related_fingerprints",
        "path_change",
        "control_state",
        "outcome",
        "notes",
        "reason",
        "cited_controls",
        "needs_reevaluation",
        "location",
        "tags",
        "meta",
    }
)


def is_poison_filename(name: str) -> bool:
    base = str(name or "").rsplit("/", 1)[-1]
    return base in _POISON_FILENAMES or base.lower() in {n.lower() for n in _POISON_FILENAMES}


def strip_poison_keys(obj: Any) -> Any:
    """Recursively drop poison keys; return a new structure."""
    if isinstance(obj, dict):
        out: dict[str, Any] = {}
        for k, v in obj.items():
            key = str(k)
            if key.lower() in {p.lower() for p in _POISON_KEYS}:
                continue
            if key.startswith("__memory_"):
                continue
            out[k] = strip_poison_keys(v)
        return out
    if isinstance(obj, list):
        return [strip_poison_keys(x) for x in obj]
    return obj


def _looks_like_instruction_blob(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    return bool(_INSTRUCTION_RE.search(value))


def sanitize_ingest(payload: dict[str, Any]) -> dict[str, Any]:
    """Return a cleaned copy retaining only known schema keys.

    README/comment-style instruction strings are dropped. Unknown enum values
    become ``UNKNOWN`` rather than being invented.
    """
    cleaned = strip_poison_keys(deepcopy(payload if isinstance(payload, dict) else {}))
    return _sanitize_dict(cleaned)


def _sanitize_dict(obj: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for k, v in obj.items():
        key = str(k)
        if key not in _ALLOWED_TOP and key not in {
            "root_cause",
            "sink",
            "prior_status",
            "new_status",
            "controls_encountered",
            "false_positive_reasons",
            "adversary",
            "attack_graph",
            "evidence",
            "verification",
            "findings",
            "paths",
            "graph",
            "status",
            "type",
            "kind",
            "snippet",
            "relationship",
            "quality",
            "provenance",
            "source",
            "line_start",
            "line_end",
            "reuse_count",
            "revision",
            "from_judgment_id",
            "confidence_level",
            "evidence_summary",
            "reasoning",
            "affected_paths",
            "counter_evidence",
            "surviving_evidence",
            "challenges",
        }:
            # Keep nested audit/ag fields that are ingested structurally, but
            # never poison instruction keys (already stripped).
            if key.lower() in {p.lower() for p in _POISON_KEYS}:
                continue
        if _looks_like_instruction_blob(v):
            continue
        if isinstance(v, dict):
            out[k] = _sanitize_dict(v)
        elif isinstance(v, list):
            out[k] = [
                _sanitize_dict(x) if isinstance(x, dict) else x
                for x in v
                if not _looks_like_instruction_blob(x)
            ]
        else:
            out[k] = v

    # Normalize known enums when present
    if "validity" in out and str(out["validity"]) not in VALIDITIES:
        out["validity"] = "UNKNOWN"
    if "lifecycle" in out and str(out["lifecycle"]) not in FINDING_LIFECYCLES:
        out["lifecycle"] = "UNVERIFIED"
    if "item_type" in out and str(out["item_type"]) not in ITEM_TYPES:
        out["item_type"] = "UNKNOWN"
    if "control_state" in out and str(out["control_state"]) not in CONTROL_STATES:
        out["control_state"] = "CONTROL_UNKNOWN"
    if "path_change" in out and str(out["path_change"]) not in PATH_CHANGE_TYPES:
        out["path_change"] = "UNKNOWN"
    if "outcome" in out:
        outcome = str(out["outcome"])
        # Decisions may use finding-lifecycle labels (e.g. FALSE_POSITIVE);
        # change diffs use CHANGE_OUTCOMES. Accept either; else UNKNOWN.
        if outcome not in CHANGE_OUTCOMES and outcome not in FINDING_LIFECYCLES:
            out["outcome"] = "UNKNOWN"
    return out
