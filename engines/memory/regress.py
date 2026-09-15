"""Regression detection across Security Memory snapshots."""

from __future__ import annotations

from typing import Any

from engines.attack_graph.diff import (
    CHANGE_NEW_ATTACK_PATH,
    CHANGE_PATH_STATUS_CHANGE,
    CHANGE_REMOVED_ATTACK_PATH,
    CHANGE_STRENGTHENED_CONTROL,
    CHANGE_WEAKENED_CONTROL,
    compare_attack_graphs,
)
from engines.attack_graph.predictive import predictive_report
from engines.memory.fingerprints import finding_fingerprint, path_fingerprint
from engines.memory.lifecycle import transition_finding
from engines.memory.schema import (
    CONTROL_REMOVED,
    CONTROL_STRENGTHENED,
    CONTROL_WEAKENED,
    LIFE_REGRESSED,
    LIFE_RESOLVED,
    OUTCOME_CHANGED,
    OUTCOME_NEW,
    OUTCOME_REGRESSED,
    OUTCOME_RESOLVED,
    OUTCOME_UNCHANGED,
    PATH_BLOCKED,
    PATH_NEW,
    PATH_PERSISTING,
    PATH_REGRESSED,
    PATH_REMOVED,
    UNKNOWN,
)


def _finding_map(snapshot: dict[str, Any]) -> dict[str, dict[str, Any]]:
    out: dict[str, dict[str, Any]] = {}
    for f in snapshot.get("findings") or []:
        if not isinstance(f, dict):
            continue
        fp = f.get("fingerprint") or finding_fingerprint(f)
        out[str(fp)] = f
    return out


def _path_map(snapshot: dict[str, Any]) -> dict[str, dict[str, Any]]:
    out: dict[str, dict[str, Any]] = {}
    for p in snapshot.get("attack_paths") or []:
        if not isinstance(p, dict):
            continue
        fp = p.get("fingerprint") or path_fingerprint(p)
        out[str(fp)] = p
    return out


def _control_map(snapshot: dict[str, Any]) -> dict[str, dict[str, Any]]:
    out: dict[str, dict[str, Any]] = {}
    for c in snapshot.get("controls") or []:
        if not isinstance(c, dict):
            continue
        fp = str(c.get("fingerprint") or c.get("id") or UNKNOWN)
        out[fp] = c
    return out


def _as_ag_compat(snapshot: dict[str, Any]) -> dict[str, Any]:
    """Build a minimal attack-graph-shaped dict for compare_attack_graphs."""
    paths = []
    for p in snapshot.get("attack_paths") or []:
        if not isinstance(p, dict):
            continue
        paths.append(
            {
                "hops": p.get("hops") or [],
                "status": p.get("status"),
                "entry": p.get("entry"),
                "target": p.get("target"),
                "tags": p.get("tags") or [],
                "controls_encountered": [
                    {"id": cfp, "effectiveness": "unknown"}
                    for cfp in (p.get("control_fingerprints") or [])
                ],
            }
        )
    return {
        "target": snapshot.get("target"),
        "generated_at": snapshot.get("generated_at"),
        "paths": paths,
        "graph": {"nodes": [], "edges": []},
    }


def detect_regressions(
    before_snapshot: dict[str, Any],
    after_snapshot: dict[str, Any],
) -> dict[str, Any]:
    """Compose attack_graph.diff + finding lifecycle + control deltas.

    Outcomes bucketed into NEW / CHANGED / REGRESSED / RESOLVED / UNCHANGED.
    """
    before = before_snapshot if isinstance(before_snapshot, dict) else {}
    after = after_snapshot if isinstance(after_snapshot, dict) else {}

    new_list: list[dict[str, Any]] = []
    changed_list: list[dict[str, Any]] = []
    regressed_list: list[dict[str, Any]] = []
    resolved_list: list[dict[str, Any]] = []
    unchanged_list: list[dict[str, Any]] = []

    # --- findings lifecycle ---
    bf = _finding_map(before)
    af = _finding_map(after)
    for fp in sorted(set(bf) | set(af)):
        prev = bf.get(fp)
        cur = af.get(fp)
        if prev is None and cur is not None:
            new_list.append(
                {
                    "kind": "finding",
                    "fingerprint": fp,
                    "outcome": OUTCOME_NEW,
                    "lifecycle": cur.get("lifecycle"),
                    "status": cur.get("status"),
                }
            )
            continue
        if prev is not None and cur is None:
            life, validity = transition_finding(prev.get("status"), "ABSENT")
            resolved_list.append(
                {
                    "kind": "finding",
                    "fingerprint": fp,
                    "outcome": OUTCOME_RESOLVED,
                    "lifecycle": life,
                    "validity": validity,
                    "prior_status": prev.get("status"),
                }
            )
            continue
        assert prev is not None and cur is not None
        life, validity = transition_finding(prev.get("status"), cur.get("status"))
        if life == LIFE_REGRESSED or validity == "REGRESSED":
            regressed_list.append(
                {
                    "kind": "finding",
                    "fingerprint": fp,
                    "outcome": OUTCOME_REGRESSED,
                    "lifecycle": life,
                    "validity": validity,
                    "prior_status": prev.get("status"),
                    "status": cur.get("status"),
                }
            )
        elif life == LIFE_RESOLVED:
            resolved_list.append(
                {
                    "kind": "finding",
                    "fingerprint": fp,
                    "outcome": OUTCOME_RESOLVED,
                    "lifecycle": life,
                    "prior_status": prev.get("status"),
                    "status": cur.get("status"),
                }
            )
        elif prev.get("status") != cur.get("status") or prev.get("lifecycle") != cur.get(
            "lifecycle"
        ):
            changed_list.append(
                {
                    "kind": "finding",
                    "fingerprint": fp,
                    "outcome": OUTCOME_CHANGED,
                    "lifecycle": life,
                    "prior_status": prev.get("status"),
                    "status": cur.get("status"),
                }
            )
        else:
            unchanged_list.append(
                {
                    "kind": "finding",
                    "fingerprint": fp,
                    "outcome": OUTCOME_UNCHANGED,
                    "status": cur.get("status"),
                }
            )

    # --- paths via attack_graph.diff ---
    ag_diff = compare_attack_graphs(_as_ag_compat(before), _as_ag_compat(after))
    path_changes: list[dict[str, Any]] = []
    for ch in ag_diff.get("changes") or []:
        ctype = ch.get("change")
        sig = ch.get("signature") or []
        fp = path_fingerprint({"hops": sig})
        if ctype == CHANGE_NEW_ATTACK_PATH:
            rec = {
                "kind": "attack_path",
                "fingerprint": fp,
                "outcome": OUTCOME_NEW,
                "path_change": PATH_NEW,
                "detail": ch,
            }
            new_list.append(rec)
            path_changes.append(rec)
        elif ctype == CHANGE_REMOVED_ATTACK_PATH:
            rec = {
                "kind": "attack_path",
                "fingerprint": fp,
                "outcome": OUTCOME_RESOLVED,
                "path_change": PATH_REMOVED,
                "detail": ch,
            }
            resolved_list.append(rec)
            path_changes.append(rec)
        elif ctype == CHANGE_WEAKENED_CONTROL:
            rec = {
                "kind": "attack_path",
                "fingerprint": fp,
                "outcome": OUTCOME_REGRESSED,
                "path_change": PATH_REGRESSED,
                "control_state": CONTROL_WEAKENED,
                "detail": ch,
            }
            regressed_list.append(rec)
            path_changes.append(rec)
        elif ctype == CHANGE_STRENGTHENED_CONTROL:
            status_after = str(ch.get("status_after") or "")
            path_change = PATH_BLOCKED if status_after == "BLOCKED" else PATH_PERSISTING
            rec = {
                "kind": "attack_path",
                "fingerprint": fp,
                "outcome": OUTCOME_CHANGED,
                "path_change": path_change,
                "control_state": CONTROL_STRENGTHENED,
                "detail": ch,
            }
            changed_list.append(rec)
            path_changes.append(rec)
        elif ctype == CHANGE_PATH_STATUS_CHANGE:
            direction = ch.get("direction")
            if direction == "regressed":
                rec = {
                    "kind": "attack_path",
                    "fingerprint": fp,
                    "outcome": OUTCOME_REGRESSED,
                    "path_change": PATH_REGRESSED,
                    "detail": ch,
                }
                regressed_list.append(rec)
            else:
                rec = {
                    "kind": "attack_path",
                    "fingerprint": fp,
                    "outcome": OUTCOME_CHANGED,
                    "path_change": PATH_PERSISTING,
                    "detail": ch,
                }
                changed_list.append(rec)
            path_changes.append(rec)

    bp = _path_map(before)
    ap = _path_map(after)
    for fp in sorted(set(bp) & set(ap)):
        if any(x.get("fingerprint") == fp for x in path_changes):
            continue
        unchanged_list.append(
            {
                "kind": "attack_path",
                "fingerprint": fp,
                "outcome": OUTCOME_UNCHANGED,
                "path_change": PATH_PERSISTING,
                "status": ap[fp].get("status"),
            }
        )

    # --- controls ---
    bc = _control_map(before)
    ac = _control_map(after)
    for fp in sorted(set(bc) | set(ac)):
        prev = bc.get(fp)
        cur = ac.get(fp)
        if prev is None and cur is not None:
            new_list.append(
                {
                    "kind": "control",
                    "fingerprint": fp,
                    "outcome": OUTCOME_NEW,
                    "control_state": cur.get("control_state"),
                }
            )
        elif prev is not None and cur is None:
            resolved_list.append(
                {
                    "kind": "control",
                    "fingerprint": fp,
                    "outcome": OUTCOME_RESOLVED,
                    "control_state": CONTROL_REMOVED,
                }
            )
        elif prev is not None and cur is not None:
            if prev.get("effectiveness") != cur.get("effectiveness"):
                # Weaker effectiveness → regression signal
                order = {"ineffective": 0, "unknown": 1, "likely": 2, "confirmed": 3}
                ra = order.get(str(prev.get("effectiveness")), 1)
                rb = order.get(str(cur.get("effectiveness")), 1)
                if rb < ra:
                    regressed_list.append(
                        {
                            "kind": "control",
                            "fingerprint": fp,
                            "outcome": OUTCOME_REGRESSED,
                            "control_state": CONTROL_WEAKENED,
                            "prior_effectiveness": prev.get("effectiveness"),
                            "effectiveness": cur.get("effectiveness"),
                        }
                    )
                elif rb > ra:
                    changed_list.append(
                        {
                            "kind": "control",
                            "fingerprint": fp,
                            "outcome": OUTCOME_CHANGED,
                            "control_state": CONTROL_STRENGTHENED,
                            "prior_effectiveness": prev.get("effectiveness"),
                            "effectiveness": cur.get("effectiveness"),
                        }
                    )
                else:
                    changed_list.append(
                        {
                            "kind": "control",
                            "fingerprint": fp,
                            "outcome": OUTCOME_CHANGED,
                            "control_state": "CONTROL_CHANGED",
                        }
                    )
            else:
                unchanged_list.append(
                    {
                        "kind": "control",
                        "fingerprint": fp,
                        "outcome": OUTCOME_UNCHANGED,
                    }
                )

    predictive: dict[str, Any] | None = None
    try:
        predictive = predictive_report(_as_ag_compat(before), _as_ag_compat(after))
    except Exception:  # noqa: BLE001
        predictive = None

    return {
        "kind": "security_memory_regressions",
        "before_snapshot_id": before.get("snapshot_id"),
        "after_snapshot_id": after.get("snapshot_id"),
        "NEW": new_list,
        "CHANGED": changed_list,
        "REGRESSED": regressed_list,
        "RESOLVED": resolved_list,
        "UNCHANGED": unchanged_list,
        "attack_graph_diff": ag_diff,
        "predictive": predictive,
        "summary": {
            "new": len(new_list),
            "changed": len(changed_list),
            "regressed": len(regressed_list),
            "resolved": len(resolved_list),
            "unchanged": len(unchanged_list),
        },
    }
