"""Schema validation for registry entries and examples."""

from __future__ import annotations

from typing import Any

from engines.data.schema import (
    CATEGORIES,
    FP_REASON_CODES,
    PATH_STATUSES,
    REGISTRY_STATUSES,
    SPLITS,
    VERDICTS,
)


def validate_registry_entry(entry: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    if not entry.get("dataset_id"):
        errors.append("missing dataset_id")
    status = entry.get("status")
    if status and status not in REGISTRY_STATUSES:
        errors.append(f"invalid status: {status}")
    for d in entry.get("domains") or []:
        if d not in CATEGORIES:
            errors.append(f"unknown domain: {d}")
    for u in entry.get("recommended_use") or []:
        if str(u).upper() not in SPLITS and str(u).lower() not in {
            "training",
            "evaluation",
            "research",
        }:
            # allow lowercase legacy from references
            if str(u) not in {"metadata-only", "derived_taxonomy_ok"}:
                errors.append(f"unknown recommended_use: {u}")
    return errors


def validate_example(example: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    if not example.get("example_id"):
        errors.append("missing example_id")
    kind = example.get("kind")
    if kind == "FALSE_POSITIVE":
        if example.get("verdict") and example["verdict"] not in VERDICTS:
            errors.append(f"invalid verdict: {example['verdict']}")
        if example.get("reason") and example["reason"] not in FP_REASON_CODES:
            errors.append(f"invalid FP reason: {example['reason']}")
    if kind == "ATTACK_CHAIN":
        if example.get("status") and example["status"] not in PATH_STATUSES:
            errors.append(f"invalid path status: {example['status']}")
    if kind == "AI_SECURITY":
        label = str(example.get("label") or "").upper()
        if label and label not in {"BENIGN", "MALICIOUS", "UNKNOWN"}:
            errors.append(f"invalid AI label: {label}")
    return errors


def validate_examples(examples: list[dict[str, Any]]) -> dict[str, Any]:
    issues: list[dict[str, Any]] = []
    for ex in examples:
        errs = validate_example(ex)
        if errs:
            issues.append({"example_id": ex.get("example_id"), "errors": errs})
    return {"ok": not issues, "issue_count": len(issues), "issues": issues}
