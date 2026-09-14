"""Multi-step temporal attack chains (Phase 6 Part 2).

Some abuse cases are not a single request but a *sequence of stateful steps*
that must happen in order, where each step changes application state that the
next step depends on. Examples:

- account recovery: ``register`` → ``verify`` → ``reset``
- object lifecycle: ``create`` → obtain ``id`` → ``access``
- async processing: ``upload`` → ``async worker`` picks it up

This module detects such sequences **from source evidence only**. For each
sequence it records the ordered steps, the *previous* application state each
step assumes, and the *resulting* state it produces. It is strictly
evidence-gated:

- a step is only recorded when a handler / route matching it is found in source;
- a chain is only emitted when at least two distinct ordered steps are present;
- ``status`` is ``LIKELY`` only when the steps co-locate in one module (shared
  state is plausible) and appear in the expected order; otherwise ``UNKNOWN``
  (we do not assert a temporal link we cannot see). Nothing is ever
  ``CONFIRMED`` — temporal linkage across requests is inherently unproven by
  static analysis alone.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

TEMPORAL_VERSION = "1.0.0"

STATUS_LIKELY = "LIKELY"
STATUS_UNKNOWN = "UNKNOWN"

# A sequence definition. Each step carries keyword patterns matched against
# function names and route strings, plus a human description of the state it
# assumes (previous_state) and produces (resulting_state).
_SEQUENCES: list[dict[str, Any]] = [
    {
        "name": "account_recovery",
        "description": "register → verify → password reset lifecycle",
        "steps": [
            {
                "step": "register",
                "patterns": [r"\bregister\b", r"\bsign[_-]?up\b", r"create_account"],
                "previous_state": "no account",
                "resulting_state": "account created (unverified)",
            },
            {
                "step": "verify",
                "patterns": [r"\bverify\b", r"\bconfirm(_email)?\b", r"activate"],
                "previous_state": "account created (unverified)",
                "resulting_state": "account verified / token consumed",
            },
            {
                "step": "reset",
                "patterns": [r"\breset(_password)?\b", r"forgot(_password)?", r"recover"],
                "previous_state": "account verified",
                "resulting_state": "credential rotated (reset token issued/consumed)",
            },
        ],
    },
    {
        "name": "object_lifecycle",
        "description": "create → obtain id → access object by id",
        "steps": [
            {
                "step": "create",
                "patterns": [r"\bcreate\b", r"\bnew_\w+", r"\badd_\w+"],
                "previous_state": "object does not exist",
                "resulting_state": "object created, id returned to caller",
            },
            {
                "step": "identify",
                "patterns": [r"<\w*id\w*>", r"\bget_by_id\b", r"\bfind_by_id\b", r"_id\b"],
                "previous_state": "caller holds an object id",
                "resulting_state": "id used to locate the object",
            },
            {
                "step": "access",
                "patterns": [r"\baccess\b", r"\bdownload\b", r"\bview\b", r"\bget_\w+"],
                "previous_state": "object located by id",
                "resulting_state": "object contents returned",
            },
        ],
    },
    {
        "name": "async_processing",
        "description": "upload → async worker consumes the artifact",
        "steps": [
            {
                "step": "upload",
                "patterns": [r"\bupload\b", r"\bput_object\b", r"save_file", r"store_\w+"],
                "previous_state": "artifact outside the system",
                "resulting_state": "artifact stored, job enqueued",
            },
            {
                "step": "worker",
                "patterns": [
                    r"\bworker\b",
                    r"\bconsume\b",
                    r"\bprocess_\w+",
                    r"\btask\b",
                    r"\bcelery\b",
                    r"\bqueue\b",
                    r"@shared_task",
                ],
                "previous_state": "job enqueued",
                "resulting_state": "artifact processed by background worker (deferred trust boundary)",
            },
        ],
    },
]


def _iter_source_files(root: Path) -> list[Path]:
    if root.is_file():
        return [root]
    files: list[Path] = []
    skip = {".git", "node_modules", ".venv", "venv", "__pycache__", "dist", "build"}
    for p in sorted(root.rglob("*.py")):
        if any(part in skip for part in p.parts):
            continue
        files.append(p)
    return files


def _line_of(source: str, match: re.Match[str]) -> int:
    return source.count("\n", 0, match.start()) + 1


def _match_steps_in_source(
    filename: str, source: str, sequence: dict[str, Any]
) -> list[dict[str, Any]]:
    """Return the ordered steps found in this single source file."""
    found: list[dict[str, Any]] = []
    for step in sequence["steps"]:
        hit: dict[str, Any] | None = None
        for pat in step["patterns"]:
            m = re.search(pat, source, re.IGNORECASE)
            if m:
                hit = {
                    "step": step["step"],
                    "previous_state": step["previous_state"],
                    "resulting_state": step["resulting_state"],
                    "file": filename,
                    "line": _line_of(source, m),
                    "evidence": [
                        {
                            "type": "CODE_PATTERN",
                            "description": f"matched `{pat}` for step `{step['step']}`",
                            "file": filename,
                            "line": _line_of(source, m),
                        }
                    ],
                }
                break
        if hit:
            found.append(hit)
    return found


def analyze_temporal(target: Path | str) -> dict[str, Any]:
    """Detect temporal multi-step chains under ``target`` (dir or file)."""
    root = Path(target)
    chains: list[dict[str, Any]] = []

    # Collect per-file source once.
    sources: dict[str, str] = {}
    for f in _iter_source_files(root):
        try:
            sources[f.name] = f.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue

    for sequence in _SEQUENCES:
        # (a) same-file occurrence → LIKELY (shared state plausible)
        per_file_best: dict[str, list[dict[str, Any]]] = {}
        for fname, src in sources.items():
            steps = _match_steps_in_source(fname, src, sequence)
            if len(steps) >= 2:
                per_file_best[fname] = steps

        if per_file_best:
            # pick the file with the most complete sequence
            fname, steps = max(per_file_best.items(), key=lambda kv: len(kv[1]))
            ordered = [s["step"] for s in steps]
            in_order = _is_subsequence(ordered, [s["step"] for s in sequence["steps"]])
            chains.append(
                _chain_record(sequence, steps, status=STATUS_LIKELY if in_order else STATUS_UNKNOWN,
                              note=("steps co-locate in one module in expected order"
                                    if in_order else
                                    "steps co-locate but order is ambiguous"))
            )
            continue

        # (b) steps scattered across files → UNKNOWN link
        scattered: list[dict[str, Any]] = []
        seen_steps: set[str] = set()
        for fname, src in sources.items():
            for s in _match_steps_in_source(fname, src, sequence):
                if s["step"] not in seen_steps:
                    seen_steps.add(s["step"])
                    scattered.append(s)
        if len(scattered) >= 2:
            chains.append(
                _chain_record(
                    sequence,
                    scattered,
                    status=STATUS_UNKNOWN,
                    note="steps found in different files; cross-request link unproven (UNKNOWN)",
                )
            )

    return {
        "schema_version": TEMPORAL_VERSION,
        "tool": "axguard",
        "kind": "temporal_chains",
        "target": str(root.resolve()),
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "chain_count": len(chains),
        "chains": chains,
        "notes": (
            "Temporal chains are evidence-gated and never CONFIRMED: static "
            "analysis cannot prove a cross-request state transition on its own."
        ),
    }


def _chain_record(
    sequence: dict[str, Any],
    steps: list[dict[str, Any]],
    *,
    status: str,
    note: str,
) -> dict[str, Any]:
    return {
        "sequence_name": sequence["name"],
        "description": sequence["description"],
        "status": status,
        "step_count": len(steps),
        "steps": steps,
        "previous_state": steps[0]["previous_state"] if steps else "unknown",
        "resulting_state": steps[-1]["resulting_state"] if steps else "unknown",
        "note": note,
        "evidence": [ev for s in steps for ev in s.get("evidence", [])],
    }


def _is_subsequence(found: list[str], canonical: list[str]) -> bool:
    """True if ``found`` appears in the same relative order as ``canonical``."""
    it = iter(canonical)
    return all(step in it for step in found)
