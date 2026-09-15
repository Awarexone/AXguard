"""Prepare training / validation / test splits with contamination guards."""

from __future__ import annotations

from typing import Any

from engines.data.schema import (
    SPLIT_BENCHMARK_ONLY,
    SPLIT_RESEARCH_ONLY,
    SPLIT_TEST,
    SPLIT_TRAINING,
    SPLIT_VALIDATION,
    STATUS_APPROVED,
    STATUS_EVALUATION_ONLY,
    STATUS_TRAINING_ONLY,
)


def _split_for_dataset(entry: dict[str, Any] | None) -> str | None:
    if not entry:
        return None
    status = str(entry.get("status") or "")
    uses = {str(u).upper() for u in (entry.get("recommended_use") or [])}
    if status == STATUS_EVALUATION_ONLY or SPLIT_BENCHMARK_ONLY in uses:
        return SPLIT_BENCHMARK_ONLY
    if SPLIT_RESEARCH_ONLY in uses or status != STATUS_APPROVED:
        if status == STATUS_TRAINING_ONLY:
            return SPLIT_TRAINING
        return SPLIT_RESEARCH_ONLY
    return SPLIT_TRAINING


def prepare_splits(
    examples: list[dict[str, Any]],
    *,
    dataset_lookup: dict[str, dict[str, Any]] | None = None,
    train_ratio: float = 0.8,
) -> dict[str, Any]:
    """Partition examples. BENCHMARK_ONLY / unapproved sources never enter TRAINING."""
    lookup = dataset_lookup or {}
    training: list[dict[str, Any]] = []
    validation: list[dict[str, Any]] = []
    test: list[dict[str, Any]] = []
    benchmark_only: list[dict[str, Any]] = []
    research_only: list[dict[str, Any]] = []
    blocked: list[dict[str, Any]] = []

    eligible: list[dict[str, Any]] = []
    for ex in examples:
        src = str(ex.get("dataset_id") or ex.get("source") or "")
        entry = lookup.get(src)
        bucket = _split_for_dataset(entry) if entry else None
        # Synthetic fixtures without registry: allow TRAINING unless marked
        if entry is None:
            use = str(ex.get("split") or SPLIT_TRAINING).upper()
            if use == SPLIT_BENCHMARK_ONLY:
                benchmark_only.append(ex)
            elif use == SPLIT_RESEARCH_ONLY:
                research_only.append(ex)
            else:
                eligible.append(ex)
            continue
        if bucket == SPLIT_BENCHMARK_ONLY:
            benchmark_only.append(ex)
            blocked.append(
                {
                    "example_id": ex.get("example_id"),
                    "reason": "BENCHMARK_ONLY — excluded from training (contamination guard)",
                    "dataset_id": src,
                }
            )
            continue
        if bucket == SPLIT_RESEARCH_ONLY:
            research_only.append(ex)
            blocked.append(
                {
                    "example_id": ex.get("example_id"),
                    "reason": "RESEARCH_ONLY / not APPROVED for public training",
                    "dataset_id": src,
                }
            )
            continue
        eligible.append(ex)

    n = len(eligible)
    cut = int(n * train_ratio)
    val_cut = cut + max(0, (n - cut) // 2)
    training = eligible[:cut]
    validation = eligible[cut:val_cut]
    test = eligible[val_cut:]

    dpo_pairs = build_dpo_pairs(training)

    return {
        "TRAINING": training,
        "VALIDATION": validation,
        "TEST": test,
        "BENCHMARK_ONLY": benchmark_only,
        "RESEARCH_ONLY": research_only,
        "blocked_from_training": blocked,
        "dpo_pairs": dpo_pairs,
        "counts": {
            "TRAINING": len(training),
            "VALIDATION": len(validation),
            "TEST": len(test),
            "BENCHMARK_ONLY": len(benchmark_only),
            "RESEARCH_ONLY": len(research_only),
            "blocked": len(blocked),
            "dpo_pairs": len(dpo_pairs),
        },
    }


def build_dpo_pairs(examples: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Preference pairs from vulnerable vs secure / malicious vs benign when present."""
    by_type: dict[str, dict[str, list[dict[str, Any]]]] = {}
    for ex in examples:
        if ex.get("kind") == "CODE_VULNERABILITY":
            key = str(ex.get("vulnerability_type") or "unknown")
            bucket = by_type.setdefault(key, {"pos": [], "neg": []})
            if ex.get("vulnerable"):
                bucket["pos"].append(ex)
            else:
                bucket["neg"].append(ex)
        if ex.get("kind") == "AI_SECURITY":
            key = str(ex.get("category") or "AI")
            bucket = by_type.setdefault(key, {"pos": [], "neg": []})
            if str(ex.get("label")).upper() == "MALICIOUS":
                bucket["pos"].append(ex)
            elif str(ex.get("label")).upper() == "BENIGN":
                bucket["neg"].append(ex)

    pairs: list[dict[str, Any]] = []
    for key, sides in by_type.items():
        for chosen, rejected in zip(sides["pos"], sides["neg"]):
            pairs.append(
                {
                    "pair_id": f"dpo.{key}.{len(pairs)}",
                    "domain": key,
                    "chosen": chosen.get("example_id"),
                    "rejected": rejected.get("example_id"),
                    "note": "chosen=vulnerable/malicious signal; rejected=secure/benign",
                }
            )
    return pairs
