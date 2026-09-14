"""Application model schema constants and empty factory."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any

APPLICATION_MODEL_VERSION = "1.0.0"
TOOL_NAME = "axguard"

CONFIDENCE_CONFIRMED = "confirmed"
CONFIDENCE_LIKELY = "likely"
CONFIDENCE_UNKNOWN = "unknown"

CONFIDENCES = frozenset(
    {CONFIDENCE_CONFIRMED, CONFIDENCE_LIKELY, CONFIDENCE_UNKNOWN}
)

AUTH_STATUSES = frozenset({"required", "optional", "none", "unknown"})


def evidence(
    file: str | None = None,
    line: int | None = None,
    *,
    symbol: str | None = None,
    reason: str = "",
) -> dict[str, Any]:
    ev: dict[str, Any] = {"reason": reason}
    if file is not None:
        ev["file"] = file
    if line is not None:
        ev["line"] = line
    if symbol is not None:
        ev["symbol"] = symbol
    return ev


def empty_application_model(target: Path) -> dict[str, Any]:
    root = str(target.resolve())
    name = target.resolve().name if target.is_dir() else target.resolve().stem
    return {
        "schema_version": APPLICATION_MODEL_VERSION,
        "tool": TOOL_NAME,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "target": root,
        "application": {
            "name": name or "unknown",
            "root": root,
            "languages": [],
            "frameworks": [],
            "runtimes": [],
            "package_managers": [],
            "databases": [],
            "infrastructure": [],
            "cloud": [],
            "deployment": [],
        },
        "entrypoints": [],
        "identities": [],
        "assets": [],
        "external_services": [],
        "ai_components": [],
        "trust_boundaries": [],
        "security_controls": [],
        "sinks": [],
        "data_flows": [],
        "call_graph": [],
        "graph": {"nodes": [], "edges": []},
        "summary": {
            "endpoint_count": 0,
            "authenticated_count": 0,
            "auth_unknown_count": 0,
            "unauthenticated_count": 0,
            "sink_count": 0,
            "asset_count": 0,
            "external_service_count": 0,
            "ai_component_count": 0,
            "trust_boundary_count": 0,
            "control_count": 0,
            "frameworks": [],
            "databases": [],
        },
    }


def omit_empty(model: dict[str, Any]) -> dict[str, Any]:
    """Return a shallow copy keeping empty lists (schema-stable for consumers)."""
    return model
