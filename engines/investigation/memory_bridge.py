"""Soft Security Memory bridge — reuse / invalidate prior conclusions."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from engines.investigation.schema import UNKNOWN


def lookup_memory_for_candidate(
    candidate: dict[str, Any],
    *,
    memory_dir: Path | str | None = None,
) -> dict[str, Any] | None:
    """Return a ledger-ish hit for the candidate, or None.

    Soft-fail: missing memory package / empty store → None.
    """
    try:
        from engines.memory.fingerprints import finding_fingerprint
        from engines.memory.store import load_ledger, resolve_memory_dir
    except Exception:  # noqa: BLE001
        return None

    try:
        root = resolve_memory_dir(memory_dir)
        ledger = load_ledger(root)
    except Exception:  # noqa: BLE001
        return None

    entries = ledger.get("entries") or {}
    if not entries:
        return None

    # Prefer fingerprint match when possible
    try:
        fp = finding_fingerprint(candidate)
    except Exception:  # noqa: BLE001
        fp = None
    if fp and fp in entries:
        hit = dict(entries[fp])
        hit["fingerprint"] = fp
        return hit

    cid = str(candidate.get("id") or "")
    rule = str(candidate.get("rule_id") or candidate.get("vulnerability_type") or "")
    for key, ent in entries.items():
        if cid and (cid == key or cid in str(key) or cid == str(ent.get("finding_id") or "")):
            hit = dict(ent)
            hit["fingerprint"] = key
            return hit
        if rule and rule == str(ent.get("rule_id") or ""):
            hit = dict(ent)
            hit["fingerprint"] = key
            return hit
        loc = candidate.get("location") if isinstance(candidate.get("location"), dict) else {}
        file_hint = str((loc or {}).get("file") or candidate.get("file") or "")
        if file_hint and file_hint == str(ent.get("file") or ""):
            hit = dict(ent)
            hit["fingerprint"] = key
            return hit
    return None


def memory_context_summary(hit: dict[str, Any] | None) -> dict[str, Any]:
    if not hit:
        return {"hit": False, "lifecycle": UNKNOWN, "validity": UNKNOWN}
    return {
        "hit": True,
        "fingerprint": hit.get("fingerprint"),
        "lifecycle": hit.get("lifecycle") or hit.get("status") or UNKNOWN,
        "validity": hit.get("validity") or UNKNOWN,
    }
