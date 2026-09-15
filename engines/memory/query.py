"""Deterministic Security Memory queries (intent routing, no invented history)."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from engines.memory.changes import compare_revisions, compare_snapshots
from engines.memory.schema import (
    LIFE_FALSE_POSITIVE,
    UNKNOWN,
    VALIDITY_INVALIDATED,
)
from engines.memory.store import (
    list_snapshots,
    load_index,
    load_ledger,
    load_snapshot,
    resolve_memory_dir,
)

_INTENT_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("regressions", re.compile(r"(?i)\b(regressions?|regressed|came back|reintroduced)\b")),
    ("what_changed", re.compile(r"(?i)\b(what changed|diff|delta|changes? between)\b")),
    ("rejected_reeval", re.compile(r"(?i)\b(rejected|false.?positive).*(re-?eval|recheck|again)|needs? re-?eval")),
    ("new_paths", re.compile(r"(?i)\b(new (attack )?paths?|paths? added)\b")),
    ("removed_paths", re.compile(r"(?i)\b(removed (attack )?paths?|paths? (gone|fixed|closed))\b")),
    ("controls_changed", re.compile(r"(?i)\b(controls? (changed|weakened|strengthened|removed))\b")),
    ("unknowns", re.compile(r"(?i)\b(unknowns?|what.*(unknown|uncertain))\b")),
    ("assumptions", re.compile(r"(?i)\bassumptions?\b")),
    ("findings", re.compile(r"(?i)\b(findings?|vulnerabilit)\b")),
    ("current", re.compile(r"(?i)\b(current state|latest|now)\b")),
    ("history", re.compile(r"(?i)\b(history|timeline|past snapshots?)\b")),
]


def _latest_two(memory_dir: Path) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
    ids = list_snapshots(memory_dir)
    if not ids:
        return None, None
    after = load_snapshot(ids[-1], memory_dir)
    before = load_snapshot(ids[-2], memory_dir) if len(ids) >= 2 else None
    return before, after


def get_memory(
    memory_dir: Path | str | None = None,
    *,
    state_path: Path | str | None = None,
) -> dict[str, Any]:
    root = resolve_memory_dir(memory_dir, state_path=state_path)
    return {
        "index": load_index(root),
        "ledger": load_ledger(root),
        "snapshot_ids": list_snapshots(root),
    }


def get_history(
    memory_dir: Path | str | None = None,
    *,
    state_path: Path | str | None = None,
) -> dict[str, Any]:
    root = resolve_memory_dir(memory_dir, state_path=state_path)
    ids = list_snapshots(root)
    snapshots = []
    for sid in ids:
        snap = load_snapshot(sid, root)
        if snap:
            snapshots.append(
                {
                    "snapshot_id": snap.get("snapshot_id"),
                    "source_revision": snap.get("source_revision"),
                    "generated_at": snap.get("generated_at"),
                    "summary": snap.get("summary"),
                }
            )
    return {"snapshot_ids": ids, "snapshots": snapshots}


def get_current_state(
    memory_dir: Path | str | None = None,
    *,
    state_path: Path | str | None = None,
) -> dict[str, Any]:
    root = resolve_memory_dir(memory_dir, state_path=state_path)
    index = load_index(root)
    sid = index.get("latest_snapshot_id")
    snap = load_snapshot(str(sid), root) if sid else None
    if snap is None:
        ids = list_snapshots(root)
        snap = load_snapshot(ids[-1], root) if ids else None
    return {
        "index": index,
        "snapshot": snap,
        "ledger_entries": len((load_ledger(root).get("entries") or {})),
    }


def get_findings(
    memory_dir: Path | str | None = None,
    *,
    state_path: Path | str | None = None,
    current_only: bool = True,
) -> list[dict[str, Any]]:
    root = resolve_memory_dir(memory_dir, state_path=state_path)
    if current_only:
        state = get_current_state(root)
        snap = state.get("snapshot") or {}
        return list(snap.get("findings") or [])
    # Ledger view
    led = load_ledger(root)
    return [
        e
        for e in (led.get("entries") or {}).values()
        if e.get("item_type") == "FINDING"
    ]


def get_rejected_findings(
    memory_dir: Path | str | None = None,
    *,
    state_path: Path | str | None = None,
    needs_reevaluation: bool | None = None,
) -> list[dict[str, Any]]:
    root = resolve_memory_dir(memory_dir, state_path=state_path)
    findings = get_findings(root)
    rejected = [
        f
        for f in findings
        if str(f.get("lifecycle")) == LIFE_FALSE_POSITIVE
        or str(f.get("status")) == "FALSE_POSITIVE"
    ]
    led = load_ledger(root)
    entries = led.get("entries") or {}
    out = []
    for f in rejected:
        fp = f.get("fingerprint")
        ent = entries.get(fp) or {}
        row = dict(f)
        row["needs_reevaluation"] = bool(ent.get("needs_reevaluation"))
        if needs_reevaluation is None or row["needs_reevaluation"] is needs_reevaluation:
            out.append(row)
    # Also decisions marked for re-eval
    if needs_reevaluation is True:
        for e in entries.values():
            if e.get("item_type") == "DECISION" and e.get("needs_reevaluation"):
                out.append(e)
    return out


def get_controls(
    memory_dir: Path | str | None = None,
    *,
    state_path: Path | str | None = None,
) -> list[dict[str, Any]]:
    root = resolve_memory_dir(memory_dir, state_path=state_path)
    snap = (get_current_state(root).get("snapshot") or {})
    return list(snap.get("controls") or [])


def get_attack_paths(
    memory_dir: Path | str | None = None,
    *,
    state_path: Path | str | None = None,
) -> list[dict[str, Any]]:
    root = resolve_memory_dir(memory_dir, state_path=state_path)
    snap = (get_current_state(root).get("snapshot") or {})
    return list(snap.get("attack_paths") or [])


def get_changes(
    memory_dir: Path | str | None = None,
    *,
    state_path: Path | str | None = None,
    before_id: str | None = None,
    after_id: str | None = None,
) -> dict[str, Any]:
    root = resolve_memory_dir(memory_dir, state_path=state_path)
    ids = list_snapshots(root)
    if before_id and after_id:
        return compare_revisions(root, before_id, after_id)
    if len(ids) < 2:
        before, after = _latest_two(root)
        if after is None:
            return {
                "kind": "security_memory_diff",
                "error": "insufficient_snapshots",
                "summary": {},
                "outcomes": {
                    "NEW": [],
                    "CHANGED": [],
                    "REGRESSED": [],
                    "RESOLVED": [],
                    "UNCHANGED": [],
                },
            }
        if before is None:
            return compare_snapshots({}, after)
        return compare_snapshots(before, after)
    return compare_revisions(root, ids[-2], ids[-1])


def get_regressions(
    memory_dir: Path | str | None = None,
    *,
    state_path: Path | str | None = None,
) -> dict[str, Any]:
    diff = get_changes(memory_dir, state_path=state_path)
    return {
        "kind": "security_memory_regressions",
        "REGRESSED": (diff.get("outcomes") or {}).get("REGRESSED") or [],
        "summary": {
            "regressed": len((diff.get("outcomes") or {}).get("REGRESSED") or []),
        },
        "diff_summary": diff.get("summary") or {},
    }


def get_invalidated_evidence(
    memory_dir: Path | str | None = None,
    *,
    state_path: Path | str | None = None,
) -> list[dict[str, Any]]:
    root = resolve_memory_dir(memory_dir, state_path=state_path)
    led = load_ledger(root)
    return [
        e
        for e in (led.get("entries") or {}).values()
        if e.get("validity") == VALIDITY_INVALIDATED
        and e.get("item_type") in {"EVIDENCE", "FINDING", "ATTACK_PATH", "CONTROL"}
    ]


def get_unknowns(
    memory_dir: Path | str | None = None,
    *,
    state_path: Path | str | None = None,
) -> list[dict[str, Any]]:
    root = resolve_memory_dir(memory_dir, state_path=state_path)
    snap = (get_current_state(root).get("snapshot") or {})
    return list(snap.get("unknowns") or [])


def get_assumptions(
    memory_dir: Path | str | None = None,
    *,
    state_path: Path | str | None = None,
) -> list[dict[str, Any]]:
    root = resolve_memory_dir(memory_dir, state_path=state_path)
    snap = (get_current_state(root).get("snapshot") or {})
    return list(snap.get("assumptions") or [])


def _detect_intent(question: str) -> str:
    q = str(question or "").strip()
    if not q:
        return "current"
    for name, pat in _INTENT_PATTERNS:
        if pat.search(q):
            return name
    return "current"


def answer_memory_query(
    memory_dir: Path | str | None,
    question: str,
    *,
    state_path: Path | str | None = None,
) -> dict[str, Any]:
    """Route a natural-language question to a deterministic structured answer.

    Never invents history — empty lists / UNKNOWN when data is missing.
    """
    root = resolve_memory_dir(memory_dir, state_path=state_path)
    intent = _detect_intent(question)
    answer: Any
    if intent == "regressions":
        answer = get_regressions(root)
    elif intent == "what_changed":
        answer = get_changes(root)
    elif intent == "rejected_reeval":
        answer = get_rejected_findings(root, needs_reevaluation=True)
    elif intent == "new_paths":
        diff = get_changes(root)
        answer = [
            x
            for x in (diff.get("outcomes") or {}).get("NEW") or []
            if x.get("kind") == "attack_path"
        ]
    elif intent == "removed_paths":
        diff = get_changes(root)
        answer = [
            x
            for x in (diff.get("outcomes") or {}).get("RESOLVED") or []
            if x.get("kind") == "attack_path"
        ]
    elif intent == "controls_changed":
        diff = get_changes(root)
        outcomes = diff.get("outcomes") or {}
        answer = [
            x
            for bucket in ("NEW", "CHANGED", "REGRESSED", "RESOLVED")
            for x in (outcomes.get(bucket) or [])
            if x.get("kind") == "control"
        ]
    elif intent == "unknowns":
        answer = get_unknowns(root)
    elif intent == "assumptions":
        answer = get_assumptions(root)
    elif intent == "findings":
        answer = get_findings(root)
    elif intent == "history":
        answer = get_history(root)
    else:
        answer = get_current_state(root)

    return {
        "kind": "security_memory_query",
        "question": question,
        "intent": intent,
        "answer": answer,
        "confidence": "structured" if answer not in (None, [], {}) else UNKNOWN,
    }
