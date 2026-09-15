"""Invalidate memory entries when files or controls change."""

from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from engines.memory.schema import (
    ITEM_ATTACK_PATH,
    ITEM_CONTROL,
    ITEM_DECISION,
    ITEM_EVIDENCE,
    ITEM_FINDING,
    VALIDITY_CURRENT,
    VALIDITY_INVALIDATED,
)
from engines.memory.store import load_ledger, resolve_memory_dir, save_ledger


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _norm_file(path: str) -> str:
    return str(path or "").strip().replace("\\", "/").lstrip("./").lower()


def invalidate_for_file_changes(
    memory_dir: Path | str | None,
    changed_files: list[str],
    *,
    state_path: Path | str | None = None,
) -> dict[str, Any]:
    """Mark ledger entries touching ``changed_files`` as INVALIDATED / needs re-eval.

    Uses ledger relationships when available; otherwise conservative file-path
    matching on entry ``files`` lists.
    """
    root = resolve_memory_dir(memory_dir, state_path=state_path)
    led = load_ledger(root)
    changed = {_norm_file(f) for f in (changed_files or []) if f}
    if not changed:
        return {
            "invalidated": [],
            "reevaluation": [],
            "changed_files": [],
            "summary": {"invalidated_count": 0, "reevaluation_count": 0},
        }

    entries = dict(led.get("entries") or {})
    invalidated: list[str] = []
    reevaluation: list[str] = []

    for fp, entry in list(entries.items()):
        files = {_norm_file(f) for f in (entry.get("files") or [])}
        # Conservative: substring / suffix match when exact path unknown
        hit = bool(files & changed)
        if not hit:
            for cf in changed:
                for ef in files:
                    if ef and (ef.endswith(cf) or cf.endswith(ef) or cf in ef or ef in cf):
                        hit = True
                        break
                if hit:
                    break
        if not hit:
            continue
        updated = dict(entry)
        if entry.get("item_type") in {
            ITEM_EVIDENCE,
            ITEM_FINDING,
            ITEM_ATTACK_PATH,
            ITEM_CONTROL,
        }:
            updated["validity"] = VALIDITY_INVALIDATED
            updated["needs_reevaluation"] = True
            updated["invalidated_at"] = _utc_now_iso()
            updated["invalidation_reason"] = "file_change"
            invalidated.append(fp)
            reevaluation.append(fp)
        else:
            updated["needs_reevaluation"] = True
            updated["invalidation_reason"] = "file_change_related"
            reevaluation.append(fp)
        entries[fp] = updated

    # Propagate via relationships
    rels = list(led.get("relationships") or [])
    frontier = set(invalidated)
    changed_fps = set(invalidated)
    while frontier:
        nxt: set[str] = set()
        for rel in rels:
            src, dst = rel.get("from"), rel.get("to")
            if src in frontier and dst and dst not in changed_fps:
                ent = dict(entries.get(dst) or {"fingerprint": dst})
                ent["needs_reevaluation"] = True
                if ent.get("item_type") in {ITEM_FINDING, ITEM_ATTACK_PATH, ITEM_EVIDENCE}:
                    if ent.get("validity") == VALIDITY_CURRENT:
                        ent["validity"] = VALIDITY_INVALIDATED
                        invalidated.append(dst)
                entries[dst] = ent
                reevaluation.append(dst)
                changed_fps.add(dst)
                nxt.add(dst)
            if dst in frontier and src and src not in changed_fps:
                ent = dict(entries.get(src) or {"fingerprint": src})
                ent["needs_reevaluation"] = True
                entries[src] = ent
                reevaluation.append(src)
                changed_fps.add(src)
                nxt.add(src)
        frontier = nxt

    out = deepcopy(led)
    out["entries"] = entries
    save_ledger(out, root)

    inv_u = sorted(set(invalidated))
    re_u = sorted(set(reevaluation))
    return {
        "invalidated": inv_u,
        "reevaluation": re_u,
        "changed_files": sorted(changed),
        "summary": {
            "invalidated_count": len(inv_u),
            "reevaluation_count": len(re_u),
        },
    }


def invalidate_control(
    memory_dir: Path | str | None,
    control_fp: str,
    *,
    state_path: Path | str | None = None,
) -> dict[str, Any]:
    """Mark a control INVALIDATED and dependent paths/findings for re-eval."""
    root = resolve_memory_dir(memory_dir, state_path=state_path)
    led = load_ledger(root)
    entries = dict(led.get("entries") or {})
    cfp = str(control_fp)
    dependents: list[str] = []

    if cfp in entries:
        ent = dict(entries[cfp])
        ent["validity"] = VALIDITY_INVALIDATED
        ent["needs_reevaluation"] = True
        ent["control_state"] = "CONTROL_REMOVED"
        ent["invalidated_at"] = _utc_now_iso()
        ent["invalidation_reason"] = "control_invalidate"
        entries[cfp] = ent

    for rel in led.get("relationships") or []:
        src, dst, kind = rel.get("from"), rel.get("to"), rel.get("rel")
        if src == cfp or dst == cfp:
            other = dst if src == cfp else src
            if not other:
                continue
            dependents.append(other)
            oent = dict(entries.get(other) or {"fingerprint": other})
            oent["needs_reevaluation"] = True
            if oent.get("item_type") in {ITEM_ATTACK_PATH, ITEM_FINDING}:
                oent["validity"] = VALIDITY_INVALIDATED
            oent["invalidation_reason"] = f"dependent_of:{cfp}"
            entries[other] = oent
            _ = kind

    # Also match related_fingerprints lists
    for fp, entry in list(entries.items()):
        related = entry.get("related_fingerprints") or []
        if cfp in related and fp not in dependents:
            dependents.append(fp)
            oent = dict(entry)
            oent["needs_reevaluation"] = True
            entries[fp] = oent

    out = deepcopy(led)
    out["entries"] = entries
    save_ledger(out, root)
    deps = sorted(set(dependents))
    return {
        "control_fingerprint": cfp,
        "invalidated": [cfp],
        "dependents": deps,
        "summary": {"dependent_count": len(deps)},
    }


def mark_fp_for_reevaluation(
    memory_dir: Path | str | None,
    control_fp: str,
    *,
    state_path: Path | str | None = None,
) -> dict[str, Any]:
    """Flag FALSE_POSITIVE / decision entries that cited ``control_fp``."""
    root = resolve_memory_dir(memory_dir, state_path=state_path)
    led = load_ledger(root)
    entries = dict(led.get("entries") or {})
    cfp = str(control_fp)
    marked: list[str] = []

    for rel in led.get("relationships") or []:
        if rel.get("rel") == "cites_control" and rel.get("to") == cfp:
            src = rel.get("from")
            if not src:
                continue
            ent = dict(entries.get(src) or {"fingerprint": src, "item_type": ITEM_DECISION})
            ent["needs_reevaluation"] = True
            ent["reevaluation_reason"] = f"cited_control_changed:{cfp}"
            entries[src] = ent
            marked.append(src)

    for fp, entry in list(entries.items()):
        if entry.get("item_type") != ITEM_DECISION:
            continue
        related = entry.get("related_fingerprints") or []
        if cfp in related:
            ent = dict(entry)
            ent["needs_reevaluation"] = True
            ent["reevaluation_reason"] = f"cited_control_changed:{cfp}"
            entries[fp] = ent
            marked.append(fp)

    out = deepcopy(led)
    out["entries"] = entries
    save_ledger(out, root)
    marked_u = sorted(set(marked))
    return {
        "control_fingerprint": cfp,
        "decisions_marked": marked_u,
        "summary": {"marked_count": len(marked_u)},
    }
