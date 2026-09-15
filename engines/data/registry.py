"""Dataset registry load/save and status transitions."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from engines.data.license_gate import evaluate_for_public_training, normalize_license
from engines.data.schema import (
    REGISTRY_STATUSES,
    STATUS_APPROVED,
    STATUS_DISCOVERED,
    STATUS_EVALUATION_ONLY,
    STATUS_REJECTED,
    STATUS_RESTRICTED,
    STATUS_UNDER_REVIEW,
    empty_registry,
    registry_entry,
)

_REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_REGISTRY_PATH = _REPO_ROOT / "data" / "registry" / "datasets.json"
REFERENCES_DATASETS = _REPO_ROOT / "references" / "datasets.yaml"


def load_registry(path: Path | str | None = None) -> dict[str, Any]:
    p = Path(path) if path else DEFAULT_REGISTRY_PATH
    if not p.exists():
        return empty_registry()
    data = json.loads(p.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"{p}: expected registry object")
    data.setdefault("datasets", [])
    data["summary"] = summarize(data.get("datasets") or [])
    return data


def save_registry(registry: dict[str, Any], path: Path | str | None = None) -> Path:
    p = Path(path) if path else DEFAULT_REGISTRY_PATH
    p.parent.mkdir(parents=True, exist_ok=True)
    registry = dict(registry)
    registry["summary"] = summarize(registry.get("datasets") or [])
    p.write_text(json.dumps(registry, indent=2, sort_keys=False) + "\n", encoding="utf-8")
    return p


def summarize(datasets: list[dict[str, Any]]) -> dict[str, Any]:
    by_status: dict[str, int] = {}
    for d in datasets:
        s = str(d.get("status") or STATUS_DISCOVERED)
        by_status[s] = by_status.get(s, 0) + 1
    return {
        "dataset_count": len(datasets),
        "by_status": {k: by_status[k] for k in sorted(by_status)},
        "approved_training": by_status.get(STATUS_APPROVED, 0),
        "rejected": by_status.get(STATUS_REJECTED, 0),
        "restricted": by_status.get(STATUS_RESTRICTED, 0),
        "evaluation_only": by_status.get(STATUS_EVALUATION_ONLY, 0),
    }


def get_dataset(registry: dict[str, Any], dataset_id: str) -> dict[str, Any] | None:
    for d in registry.get("datasets") or []:
        if d.get("dataset_id") == dataset_id:
            return d
    return None


def upsert_dataset(registry: dict[str, Any], entry: dict[str, Any]) -> dict[str, Any]:
    datasets = list(registry.get("datasets") or [])
    did = entry.get("dataset_id")
    out: list[dict[str, Any]] = []
    replaced = False
    for d in datasets:
        if d.get("dataset_id") == did:
            out.append(entry)
            replaced = True
        else:
            out.append(d)
    if not replaced:
        out.append(entry)
    registry = dict(registry)
    registry["datasets"] = out
    registry["summary"] = summarize(out)
    return registry


def set_status(
    registry: dict[str, Any],
    dataset_id: str,
    status: str,
    *,
    force_research_only: bool = False,
) -> dict[str, Any]:
    if status not in REGISTRY_STATUSES:
        raise ValueError(f"invalid status: {status}")
    entry = get_dataset(registry, dataset_id)
    if entry is None:
        raise KeyError(dataset_id)

    if status == STATUS_APPROVED:
        ok, reason = True, "ok"
        decision = evaluate_for_public_training(
            entry, force_research_only=force_research_only
        )
        if force_research_only:
            status = STATUS_EVALUATION_ONLY
        elif not decision["allowed_public_training"]:
            raise PermissionError(
                f"cannot approve {dataset_id} for public training: "
                + "; ".join(decision["reasons"])
            )

    updated = dict(entry)
    updated["status"] = status
    updated["license"] = normalize_license(updated.get("license"))
    if status == STATUS_REJECTED:
        updated.setdefault("notes", []).append("Rejected via registry gate")
    return upsert_dataset(registry, updated)


def parse_references_datasets_yaml(text: str) -> list[dict[str, Any]]:
    """Minimal extractor for references/datasets.yaml (no PyYAML dependency)."""
    entries: list[dict[str, Any]] = []
    current: dict[str, Any] | None = None
    for raw in text.splitlines():
        line = raw.rstrip()
        if re.match(r"^\s*-\s+name:", line):
            if current and current.get("dataset_id"):
                entries.append(current)
            current = registry_entry(
                "",
                source="huggingface",
                status=STATUS_DISCOVERED,
                license_verified=False,
            )
            current["name"] = line.split(":", 1)[1].strip()
            continue
        if current is None:
            continue
        m = re.match(r"^\s+(id|url|license|type|recommendation|version):\s*(.+)$", line)
        if not m:
            continue
        key, val = m.group(1), m.group(2).strip().strip('"').strip("'")
        if key == "id":
            current["dataset_id"] = val
        elif key == "url":
            current["url"] = val
        elif key == "license":
            current["license"] = normalize_license(val)
        elif key == "type":
            current.setdefault("notes", []).append(f"type={val}")
        elif key == "recommendation":
            current.setdefault("notes", []).append(f"recommendation={val}")
            if val in {"metadata-only", "derived_taxonomy_ok"}:
                current["recommended_use"] = ["RESEARCH_ONLY"]
                current["status"] = STATUS_UNDER_REVIEW
    if current and current.get("dataset_id"):
        entries.append(current)
    return entries


def merge_references(registry: dict[str, Any]) -> dict[str, Any]:
    if not REFERENCES_DATASETS.exists():
        return registry
    text = REFERENCES_DATASETS.read_text(encoding="utf-8")
    for entry in parse_references_datasets_yaml(text):
        existing = get_dataset(registry, entry["dataset_id"])
        if existing is None:
            registry = upsert_dataset(registry, entry)
    return registry
