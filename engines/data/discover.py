"""Dataset discovery from local registry seeds (no network downloads)."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from engines.data.license_gate import evaluate_for_public_training, normalize_license
from engines.data.registry import (
    DEFAULT_REGISTRY_PATH,
    load_registry,
    merge_references,
    save_registry,
    upsert_dataset,
)
from engines.data.schema import (
    QUALITY_MEDIUM,
    STATUS_DISCOVERED,
    STATUS_UNDER_REVIEW,
    empty_registry,
    registry_entry,
)

# Metadata-only seed candidates (no row dumps). license_verified=false until reviewed.
_SEED: list[dict[str, Any]] = [
    registry_entry(
        "CyberNative/Code_Vulnerability_Security_DPO",
        source="huggingface",
        url="https://huggingface.co/datasets/CyberNative/Code_Vulnerability_Security_DPO",
        license="Apache-2.0",
        license_verified=False,
        domains=["CODE_VULNERABILITY", "CODE_FIX"],
        quality=QUALITY_MEDIUM,
        recommended_use=["RESEARCH_ONLY"],
        status=STATUS_UNDER_REVIEW,
        notes=["synthetic preference; high label-noise risk; metadata-only"],
    ),
    registry_entry(
        "ismailtasdelen/unified-vulnerability-intelligence-dataset",
        source="huggingface",
        url="https://huggingface.co/datasets/ismailtasdelen/unified-vulnerability-intelligence-dataset",
        license="MIT",
        license_verified=False,
        domains=["CVE_CWE", "SECURITY_REASONING"],
        quality=QUALITY_MEDIUM,
        recommended_use=["RESEARCH_ONLY"],
        status=STATUS_UNDER_REVIEW,
        notes=["taxonomy cross-check only; prefer official CWE/OWASP"],
    ),
    registry_entry(
        "axguard/synthetic-fp-corpus",
        source="axguard",
        url="fixtures/data_pipeline/sample_fp.jsonl",
        license="MIT",
        license_verified=True,
        commercial_use=True,
        redistribution=True,
        domains=["FALSE_POSITIVE", "SECURITY_REASONING"],
        quality="HIGH",
        recommended_use=["TRAINING", "VALIDATION"],
        status="APPROVED",
        notes=["tiny synthetic fixture for pipeline tests"],
    ),
    registry_entry(
        "example/proprietary-blocked",
        source="example",
        url="",
        license="Proprietary",
        license_verified=True,
        domains=["CODE_VULNERABILITY"],
        recommended_use=["RESEARCH_ONLY"],
        status=STATUS_DISCOVERED,
        notes=["seed for license-gate tests"],
    ),
]


def discover(registry_path: Path | str | None = None) -> dict[str, Any]:
    """Merge seed + references/datasets.yaml into the local registry. No downloads."""
    path = Path(registry_path) if registry_path else DEFAULT_REGISTRY_PATH
    registry = load_registry(path) if path.exists() else empty_registry()
    for entry in _SEED:
        e = dict(entry)
        e["license"] = normalize_license(e.get("license"))
        e["gate"] = evaluate_for_public_training(e)
        registry = upsert_dataset(registry, e)
    registry = merge_references(registry)
    # Re-attach gate notes
    datasets = []
    for d in registry.get("datasets") or []:
        dd = dict(d)
        dd["license"] = normalize_license(dd.get("license"))
        dd["gate"] = evaluate_for_public_training(dd)
        datasets.append(dd)
    registry["datasets"] = datasets
    save_registry(registry, path)
    return registry
