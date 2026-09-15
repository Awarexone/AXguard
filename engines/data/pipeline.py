"""Training-data pipeline orchestration (Phase 9)."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from engines.data.classify import classify_example
from engines.data.dedupe import dedupe_examples
from engines.data.discover import discover
from engines.data.normalize import normalize_example
from engines.data.poison import scan_examples
from engines.data.prepare import prepare_splits
from engines.data.registry import DEFAULT_REGISTRY_PATH, get_dataset, load_registry
from engines.data.report import write_data_reports
from engines.data.schema import DATA_VERSION, empty_pipeline_result
from engines.data.scrub import scrub_examples
from engines.data.validate import validate_examples
from engines.dataflow.schema import ensure_no_secret_values


def _load_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        rows.append(json.loads(line))
    return rows


def _collect_examples(root: Path) -> list[dict[str, Any]]:
    examples: list[dict[str, Any]] = []
    # Prefer fixtures/data_pipeline when present under target or repo
    candidates = [
        root / "fixtures" / "data_pipeline",
        root if root.name == "data_pipeline" else None,
        Path(__file__).resolve().parents[2] / "fixtures" / "data_pipeline",
    ]
    seen: set[Path] = set()
    for folder in candidates:
        if folder is None or not folder.exists() or folder in seen:
            continue
        seen.add(folder)
        for path in sorted(folder.glob("*.jsonl")):
            for row in _load_jsonl(path):
                row = dict(row)
                row.setdefault("source_file", path.name)
                examples.append(row)
    return examples


def run_data_pipeline(
    target: Path | str | None = None,
    *,
    registry_path: Path | str | None = None,
    refresh_discover: bool = True,
) -> dict[str, Any]:
    root = Path(target or Path.cwd()).resolve()
    reg_path = Path(registry_path) if registry_path else DEFAULT_REGISTRY_PATH

    if refresh_discover:
        registry = discover(reg_path)
    else:
        registry = load_registry(reg_path)

    result = empty_pipeline_result(root)
    result["schema_version"] = DATA_VERSION
    result["generated_at"] = datetime.now(timezone.utc).isoformat()
    result["registry"] = registry

    raw = _collect_examples(root)
    normalized = [normalize_example(r) for r in raw]
    for ex in normalized:
        ex["domains"] = classify_example(ex)

    scrubbed, scrub_report = scrub_examples(normalized)
    unique, duplicates = dedupe_examples(scrubbed)
    poison_flags = scan_examples(unique)
    validation = validate_examples(unique)

    lookup = {
        d["dataset_id"]: d for d in (registry.get("datasets") or []) if d.get("dataset_id")
    }
    # Also allow fixture source_file → synthetic dataset mapping
    for ex in unique:
        if ex.get("dataset_id"):
            continue
        src = str(ex.get("source") or "")
        if src.startswith("axguard/") and get_dataset(registry, src):
            ex["dataset_id"] = src

    prepare = prepare_splits(unique, dataset_lookup=lookup)

    result["examples"] = unique
    result["duplicates"] = duplicates
    result["scrubbed"] = scrub_report
    result["poison_flags"] = poison_flags
    result["validation"] = validation
    result["prepare"] = {
        "counts": prepare["counts"],
        "blocked_from_training": prepare["blocked_from_training"],
        "dpo_pairs": prepare["dpo_pairs"],
        # Keep split payloads out of default report size — counts + ids only
        "training_ids": [e.get("example_id") for e in prepare["TRAINING"]],
        "validation_ids": [e.get("example_id") for e in prepare["VALIDATION"]],
        "test_ids": [e.get("example_id") for e in prepare["TEST"]],
        "benchmark_ids": [e.get("example_id") for e in prepare["BENCHMARK_ONLY"]],
    }
    result["summary"] = {
        "dataset_count": (registry.get("summary") or {}).get("dataset_count", 0),
        "example_count": len(unique),
        "duplicate_count": len(duplicates),
        "scrub_count": len(scrub_report),
        "poison_count": len(poison_flags),
        "validation_ok": validation.get("ok"),
        **prepare["counts"],
    }
    result["meta"] = {
        "trained": False,
        "downloads": False,
        "registry_path": str(reg_path),
    }
    ensure_no_secret_values(result)
    return result


def write_data_pipeline_report(result: dict[str, Any], out_dir: Path) -> dict[str, str]:
    return write_data_reports(result, out_dir)
