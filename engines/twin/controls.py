"""Security control effectiveness analysis."""

from __future__ import annotations

from typing import Any

from engines.attack_graph import choke, whatif
from engines.twin.schema import LAYER_OBSERVED, LAYER_SIMULATED, tagged


def control_effectiveness(twin: dict[str, Any]) -> list[dict[str, Any]]:
    """For each security control, report protected paths and exposure if removed."""
    ag = twin.get("attack_graph")
    if not ag:
        return []

    graph = ag.get("graph") or {"nodes": [], "edges": []}
    paths = ag.get("paths") or []
    choke_points = choke.get_choke_points(graph, paths, limit=50)
    choke_by_id = {c["id"]: c for c in choke_points}

    controls = [n for n in graph.get("nodes") or [] if n.get("type") == "control"]
    results: list[dict[str, Any]] = []

    for ctrl in controls:
        cid = str(ctrl.get("id"))
        protected = _paths_with_control(paths, cid)
        blocked = [p for p in protected if str(p.get("status")) == "BLOCKED"]
        exposed_if_removed = len(blocked)

        hypo_count = 0
        try:
            wi = whatif.run_what_if(ag, "remove_authz")
            hypo_count = sum(
                1
                for hp in wi.get("hypothetical_paths") or []
                if any(cid in str(e) for e in (hp.get("evidence_basis") or []))
            )
        except KeyError:
            pass

        choke_info = choke_by_id.get(cid)
        results.append(
            {
                "control_id": cid,
                "label": tagged(ctrl.get("label"), LAYER_OBSERVED),
                "protected_path_count": tagged(len(protected), LAYER_OBSERVED),
                "blocked_path_count": tagged(len(blocked), LAYER_OBSERVED),
                "paths_exposed_if_removed": tagged(
                    exposed_if_removed or hypo_count, LAYER_SIMULATED
                ),
                "choke_score": tagged(
                    choke_info.get("choke_score") if choke_info else 0, LAYER_OBSERVED
                ),
                "path_ids": tagged(sorted({str(p.get("id")) for p in protected}), LAYER_OBSERVED),
                "layer": LAYER_OBSERVED,
            }
        )

    results.sort(key=lambda r: (-(r["paths_exposed_if_removed"].get("value") or 0), r["control_id"]))
    return results


def _paths_with_control(paths: list[dict[str, Any]], control_id: str) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for p in paths:
        ctrl_ids = {str(c.get("id")) for c in (p.get("controls_encountered") or [])}
        hops = {str(h) for h in (p.get("hops") or [])}
        if control_id in ctrl_ids or control_id in hops:
            out.append(p)
    return out
