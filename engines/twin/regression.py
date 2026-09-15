"""Twin regression: compare before/after Security Twins."""

from __future__ import annotations

from typing import Any

from engines.attack_graph import diff, predictive
from engines.twin.schema import LAYER_INFERRED, LAYER_OBSERVED, LAYER_SIMULATED, tagged

# Twin regression change types (extend diff vocabulary)
REG_NEW_PATH = "NEW_PATH"
REG_REMOVED_PATH = "REMOVED_PATH"
REG_WIDENED_PATH = "WIDENED_PATH"
REG_NARROWED_PATH = "NARROWED_PATH"
REG_REMOVED_CONTROL = "REMOVED_CONTROL"
REG_NEW_PRIVILEGE = "NEW_PRIVILEGE"
REG_NEW_EXTERNAL_CONNECTION = "NEW_EXTERNAL_CONNECTION"

REGRESSION_CHANGE_TYPES = frozenset(
    {
        REG_NEW_PATH,
        REG_REMOVED_PATH,
        REG_WIDENED_PATH,
        REG_NARROWED_PATH,
        REG_REMOVED_CONTROL,
        REG_NEW_PRIVILEGE,
        REG_NEW_EXTERNAL_CONNECTION,
    }
)


def twin_regression(before_twin: dict[str, Any], after_twin: dict[str, Any]) -> dict[str, Any]:
    """Compare two twins using attack-graph diff + predictive signals."""
    before_ag = before_twin.get("attack_graph") or {}
    after_ag = after_twin.get("attack_graph") or {}

    diff_result = diff.compare_attack_graphs(before_ag, after_ag)
    changes = diff_result.get("changes") or []
    classified = [_classify_change(c) for c in changes]

    predictive_signals: list[dict[str, Any]] = []
    try:
        pred = predictive.predictive_report(before_ag, after_ag)
        predictive_signals = pred.get("signals") or []
    except Exception:  # noqa: BLE001
        pass

    privilege_changes = _detect_privilege_changes(before_ag, after_ag)
    external_changes = _detect_external_connections(before_twin, after_twin)

    all_changes = classified + privilege_changes + external_changes

    return {
        "before_target": before_twin.get("target"),
        "after_target": after_twin.get("target"),
        "changes": all_changes,
        "diff_summary": diff_result.get("summary") or {},
        "predictive_signals": [
            {**s, "layer": LAYER_SIMULATED} for s in predictive_signals
        ],
        "observed_change_count": sum(
            1 for c in all_changes if c.get("layer") == LAYER_OBSERVED
        ),
        "simulated_signal_count": len(predictive_signals),
        "disclaimer": (
            "Regression compares structural deltas between twin snapshots. "
            "Predictive signals are forward-looking, not confirmed findings."
        ),
    }


def _classify_change(change: dict[str, Any]) -> dict[str, Any]:
    ctype = str(change.get("change") or "")
    mapping = {
        diff.CHANGE_NEW_ATTACK_PATH: REG_NEW_PATH,
        diff.CHANGE_REMOVED_ATTACK_PATH: REG_REMOVED_PATH,
        diff.CHANGE_WEAKENED_CONTROL: REG_NARROWED_PATH,
        diff.CHANGE_STRENGTHENED_CONTROL: REG_WIDENED_PATH,
        diff.CHANGE_REMOVED_ENTRY_POINT: REG_REMOVED_PATH,
        diff.CHANGE_NEW_ENTRY_POINT: REG_NEW_PATH,
        diff.CHANGE_PATH_STATUS_CHANGE: REG_WIDENED_PATH,
    }
    reg_type = mapping.get(ctype, ctype)
    layer = LAYER_OBSERVED

    old_status = change.get("old_status")
    new_status = change.get("status") or change.get("new_status")
    if old_status and new_status:
        from engines.attack_graph.schema import PATH_TIER_RANK

        old_rank = PATH_TIER_RANK.get(str(old_status), 0)
        new_rank = PATH_TIER_RANK.get(str(new_status), 0)
        if new_rank > old_rank:
            reg_type = REG_WIDENED_PATH
        elif new_rank < old_rank:
            reg_type = REG_NARROWED_PATH

    if "control" in ctype.lower() and "removed" in str(change.get("detail", "")).lower():
        reg_type = REG_REMOVED_CONTROL

    return {
        "change_type": tagged(reg_type, layer),
        "original_change": change,
        "layer": layer,
    }


def _detect_privilege_changes(before: dict, after: dict) -> list[dict[str, Any]]:
    from engines.attack_graph import privilege as priv_mod

    before_priv = {
        (t.get("from"), t.get("to"), t.get("pattern"))
        for t in priv_mod.get_privilege_transitions(
            before.get("graph") or {}, before.get("paths") or []
        )
    }
    after_priv = {
        (t.get("from"), t.get("to"), t.get("pattern"))
        for t in priv_mod.get_privilege_transitions(
            after.get("graph") or {}, after.get("paths") or []
        )
    }
    new_transitions = after_priv - before_priv
    return [
        {
            "change_type": tagged(REG_NEW_PRIVILEGE, LAYER_OBSERVED),
            "transition": tagged({"from": t[0], "to": t[1], "pattern": t[2]}, LAYER_OBSERVED),
            "layer": LAYER_OBSERVED,
        }
        for t in sorted(new_transitions)
    ]


def _detect_external_connections(before: dict, after: dict) -> list[dict[str, Any]]:
    def _external_ids(twin: dict) -> set[str]:
        return {
            str(e.get("id"))
            for e in twin.get("entities") or []
            if e.get("type") == "ExternalService"
        }

    new_ext = _external_ids(after) - _external_ids(before)
    return [
        {
            "change_type": tagged(REG_NEW_EXTERNAL_CONNECTION, LAYER_INFERRED),
            "entity_id": eid,
            "layer": LAYER_INFERRED,
        }
        for eid in sorted(new_ext)
    ]
