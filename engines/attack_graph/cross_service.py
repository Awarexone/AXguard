"""Cross-service trust-boundary edges (Phase 6 Part 2).

When an application model describes more than one service — a primary app plus
background workers, or calls out to external services — the interesting attack
surface is often *between* them: a request that crosses from one service into
another crosses a trust boundary that is frequently under-defended because
"it's internal".

This module reads an ``application-model.json`` dict and, **only if** it finds
more than one service-like participant, emits ``service`` nodes,
``trust_boundary`` nodes, and ``crosses_trust_boundary`` edges. Its guiding
principle is the opposite of the usual assumption:

    internal ≠ trusted

Every cross-service edge is annotated with a trust level of ``untrusted``
(unless the model carries explicit evidence of an enforced boundary), because
the absence of a visible control is not evidence of safety.

If the model describes a single service, this returns an empty graph — it never
invents a second service to manufacture a boundary.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any

CROSS_SERVICE_VERSION = "1.0.0"

EDGE_CROSSES_TRUST_BOUNDARY = "crosses_trust_boundary"

TRUST_UNTRUSTED = "untrusted"
TRUST_ENFORCED = "enforced"
TRUST_UNKNOWN = "unknown"


def _slug(text: str) -> str:
    return re.sub(r"[^a-zA-Z0-9]+", "_", str(text or "")).strip("_").lower()


def _service_node(service_id: str, label: str, kind: str, **extra: Any) -> dict[str, Any]:
    node = {
        "id": service_id,
        "type": "service",
        "label": label,
        "kind": kind,
    }
    node.update(extra)
    return node


def _discover_services(app_model: dict[str, Any]) -> list[dict[str, Any]]:
    """Enumerate service-like participants from an application model.

    Sources, in order:
    - an explicit ``services`` list, if the model provides one;
    - the primary application itself (always a service if it has entrypoints);
    - queue/worker consumers (entrypoints with ``kind == 'queue'``);
    - external services the app talks to.
    """
    services: list[dict[str, Any]] = []
    seen: set[str] = set()

    def _add(node: dict[str, Any]) -> None:
        if node["id"] not in seen:
            seen.add(node["id"])
            services.append(node)

    # (1) explicit services, if present
    for svc in app_model.get("services") or []:
        name = svc.get("name") if isinstance(svc, dict) else str(svc)
        if name:
            _add(_service_node(f"service:{_slug(name)}", str(name), "declared",
                               trust="internal", evidence=[{"type": "APP_MODEL", "field": "services"}]))

    entrypoints = app_model.get("entrypoints") or []
    http_entries = [e for e in entrypoints if str(e.get("kind") or "http") != "queue"]
    queue_entries = [e for e in entrypoints if str(e.get("kind")) == "queue"]

    # (2) primary app service (if there are any HTTP entrypoints)
    app_name = (app_model.get("application") or {}).get("name") or "app"
    if http_entries:
        _add(
            _service_node(
                f"service:{_slug(app_name)}",
                str(app_name),
                "primary_app",
                trust="internet_facing",
                evidence=[{"type": "APP_MODEL", "field": "entrypoints", "count": len(http_entries)}],
            )
        )

    # (3) workers / queue consumers
    for qe in queue_entries:
        handler = qe.get("handler") or "worker"
        _add(
            _service_node(
                f"service:worker:{_slug(handler)}",
                f"worker:{handler}",
                "worker",
                trust="internal",
                evidence=[
                    {
                        "type": "APP_MODEL",
                        "field": "entrypoints[kind=queue]",
                        "file": qe.get("file"),
                        "line": qe.get("line"),
                    }
                ],
            )
        )

    # (4) external services
    for ext in app_model.get("external_services") or []:
        name = ext.get("name") if isinstance(ext, dict) else str(ext)
        if not name:
            continue
        _add(
            _service_node(
                f"service:external:{_slug(name)}",
                str(name),
                "external",
                trust="external",
                evidence=[{"type": "APP_MODEL", "field": "external_services"}],
            )
        )

    return services


def build_cross_service_graph(app_model: dict[str, Any] | None) -> dict[str, Any]:
    """Return cross-service nodes/edges for a multi-service application model.

    Empty (no nodes/edges) when fewer than two services are present.
    """
    app_model = app_model or {}
    services = _discover_services(app_model)

    nodes: list[dict[str, Any]] = list(services)
    edges: list[dict[str, Any]] = []
    boundaries: list[dict[str, Any]] = []

    if len(services) >= 2:
        # Connect the primary/internet-facing service (or first) to every other
        # service across an explicit, untrusted-by-default boundary.
        primary = next(
            (s for s in services if s.get("kind") == "primary_app"),
            services[0],
        )
        for other in services:
            if other["id"] == primary["id"]:
                continue
            boundary_id = f"trust_boundary:{_slug(primary['label'])}__{_slug(other['label'])}"
            boundaries.append(
                {
                    "id": boundary_id,
                    "type": "trust_boundary",
                    "label": f"{primary['label']} ↔ {other['label']}",
                    "trust": TRUST_UNTRUSTED,
                    "note": "internal ≠ trusted: no enforced boundary observed in code",
                }
            )
            edges.append(
                {
                    "type": EDGE_CROSSES_TRUST_BOUNDARY,
                    "from": primary["id"],
                    "to": other["id"],
                    "trust": TRUST_UNTRUSTED,
                    "boundary": boundary_id,
                    "evidence": [
                        {
                            "type": "TRUST_BOUNDARY",
                            "description": (
                                "request crosses from one service to another; no "
                                "code-visible mutual-auth / network segmentation "
                                "so the boundary is treated as untrusted"
                            ),
                        }
                    ],
                }
            )
        nodes = list(services) + boundaries

    return {
        "schema_version": CROSS_SERVICE_VERSION,
        "tool": "axguard",
        "kind": "cross_service",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "service_count": len(services),
        "nodes": nodes,
        "edges": edges,
        "trust_boundaries": boundaries,
        "summary": {
            "service_count": len(services),
            "cross_service_edge_count": len(edges),
            "multi_service": len(services) >= 2,
        },
        "notes": (
            "Cross-service edges are emitted only for multi-service models and "
            "default to an UNTRUSTED boundary — internal placement is not "
            "treated as trusted."
        ),
    }
