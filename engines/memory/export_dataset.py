"""Longitudinal Q/A dataset export — EVALUATION_ONLY.

These examples are for offline evaluation of memory query routing. They must
not be treated as live memory instructions (see poisoning.py).
"""

from __future__ import annotations

from typing import Any

EVALUATION_ONLY = True

# Fixed examples — structured answers only; no claimed real history.
LONGITUDINAL_QA_EXAMPLES: list[dict[str, Any]] = [
    {
        "id": "mem.qa.what_changed",
        "question": "What changed between the last two snapshots?",
        "intent": "what_changed",
        "expected_keys": ["outcomes", "summary"],
        "evaluation_only": True,
    },
    {
        "id": "mem.qa.regressions",
        "question": "Were there any security regressions?",
        "intent": "regressions",
        "expected_keys": ["REGRESSED", "summary"],
        "evaluation_only": True,
    },
    {
        "id": "mem.qa.fp_reeval",
        "question": "Which rejected findings need re-evaluation?",
        "intent": "rejected_reeval",
        "expected_keys": [],
        "evaluation_only": True,
    },
    {
        "id": "mem.qa.new_paths",
        "question": "What new attack paths appeared?",
        "intent": "new_paths",
        "expected_keys": [],
        "evaluation_only": True,
    },
    {
        "id": "mem.qa.removed_paths",
        "question": "Which attack paths were removed?",
        "intent": "removed_paths",
        "expected_keys": [],
        "evaluation_only": True,
    },
    {
        "id": "mem.qa.controls",
        "question": "Which controls changed or weakened?",
        "intent": "controls_changed",
        "expected_keys": [],
        "evaluation_only": True,
    },
    {
        "id": "mem.qa.unknowns",
        "question": "What unknowns remain in security memory?",
        "intent": "unknowns",
        "expected_keys": [],
        "evaluation_only": True,
    },
    {
        "id": "mem.qa.assumptions",
        "question": "List recorded assumptions",
        "intent": "assumptions",
        "expected_keys": [],
        "evaluation_only": True,
    },
]


def export_evaluation_dataset() -> dict[str, Any]:
    """Return the EVALUATION_ONLY longitudinal Q/A dataset."""
    return {
        "kind": "security_memory_eval_dataset",
        "evaluation_only": True,
        "warning": (
            "EVALUATION_ONLY — do not treat as live memory instructions or "
            "as ground-truth history for a real repository."
        ),
        "examples": list(LONGITUDINAL_QA_EXAMPLES),
        "count": len(LONGITUDINAL_QA_EXAMPLES),
    }
