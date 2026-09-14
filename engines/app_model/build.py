"""Orchestrate application-model construction and artifact writes."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from engines.app_model.assets import discover_assets
from engines.app_model.controls import discover_controls
from engines.app_model.discover import discover_stack, iter_text_files
from engines.app_model.endpoints import discover_entrypoints
from engines.app_model.graph import (
    build_call_graph,
    build_data_flows,
    build_graph,
    build_trust_boundaries,
)
from engines.app_model.schema import empty_application_model
from engines.app_model.sinks import discover_sinks
from engines.app_model.summarize import render_summary_markdown


def build_application_model(target: Path) -> dict[str, Any]:
    """
    Deterministic Application Understanding + Attack Surface Graph for ``target``.

    No LLM calls. Prefer ``unknown`` over inventing auth/roles/cloud facts.
    Secret values are never included (REDACTED).
    """
    root = target.resolve()
    model = empty_application_model(root)
    files = list(iter_text_files(root))

    stack = discover_stack(root, files)
    app = model["application"]
    app["name"] = stack.get("name") or app["name"]
    app["languages"] = stack.get("languages") or []
    app["frameworks"] = stack.get("frameworks") or []
    app["runtimes"] = stack.get("runtimes") or []
    app["package_managers"] = stack.get("package_managers") or []
    app["databases"] = stack.get("databases") or []
    app["infrastructure"] = stack.get("infrastructure") or []
    app["cloud"] = stack.get("cloud") or []
    app["deployment"] = stack.get("deployment") or []

    ep_partial = discover_entrypoints(root, files, stack)
    model["entrypoints"] = ep_partial.get("entrypoints") or []
    _merge_frameworks(app, ep_partial.get("frameworks") or [])

    model["sinks"] = discover_sinks(root, files)

    controls, identities = discover_controls(root, files)
    model["security_controls"] = controls
    model["identities"] = identities

    asset_partial = discover_assets(root, files, stack)
    model["assets"] = asset_partial.get("assets") or []
    model["external_services"] = asset_partial.get("external_services") or []
    model["ai_components"] = asset_partial.get("ai_components") or []

    model["trust_boundaries"] = build_trust_boundaries(model)
    model["data_flows"] = build_data_flows(model)
    model["call_graph"] = build_call_graph(model)
    model["graph"] = build_graph(model)
    model["summary"] = _build_summary(model)

    _ensure_no_secret_values(model)
    return model


def write_application_model(model: dict[str, Any], out_dir: Path) -> dict[str, Any]:
    """Write ``application-model.json`` and ``application-model.md`` under ``out_dir``."""
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    json_path = out_dir / "application-model.json"
    md_path = out_dir / "application-model.md"

    json_path.write_text(
        json.dumps(model, indent=2, sort_keys=False) + "\n",
        encoding="utf-8",
    )
    md_path.write_text(render_summary_markdown(model), encoding="utf-8")

    return {
        "json": str(json_path),
        "markdown": str(md_path),
        "files": [str(json_path), str(md_path)],
    }


def _merge_frameworks(app: dict[str, Any], extra: list[dict[str, Any]]) -> None:
    existing = {str(x.get("name", "")).lower() for x in app.get("frameworks") or []}
    for fw in extra:
        name = str(fw.get("name", "")).lower()
        if name and name not in existing:
            app.setdefault("frameworks", []).append(fw)
            existing.add(name)


def _build_summary(model: dict[str, Any]) -> dict[str, Any]:
    entrypoints = model.get("entrypoints") or []
    auth_required = 0
    auth_unknown = 0
    unauth = 0
    for ep in entrypoints:
        status = (ep.get("authentication") or {}).get("status", "unknown")
        if status == "required":
            auth_required += 1
        elif status == "none":
            unauth += 1
        else:
            auth_unknown += 1

    app = model.get("application") or {}
    return {
        "endpoint_count": len(entrypoints),
        "authenticated_count": auth_required,
        "auth_unknown_count": auth_unknown,
        "unauthenticated_count": unauth,
        "sink_count": len(model.get("sinks") or []),
        "asset_count": len(model.get("assets") or []),
        "external_service_count": len(model.get("external_services") or []),
        "ai_component_count": len(model.get("ai_components") or []),
        "trust_boundary_count": len(model.get("trust_boundaries") or []),
        "control_count": len(model.get("security_controls") or []),
        "frameworks": [
            x.get("name") if isinstance(x, dict) else x for x in (app.get("frameworks") or [])
        ],
        "databases": [
            x.get("name") if isinstance(x, dict) else x for x in (app.get("databases") or [])
        ],
    }


def _ensure_no_secret_values(obj: Any) -> None:
    """Belt-and-suspenders: replace obvious secret-looking long literals in strings."""
    if isinstance(obj, dict):
        if obj.get("kind") == "secret" or obj.get("type") in {
            "api_key",
            "jwt_secret",
            "password",
            "token",
            "secret",
            "env_secret",
            "aws_access_key_id",
            "private_key",
        }:
            if "value" in obj and obj["value"] != "REDACTED":
                obj["value"] = "REDACTED"
        for v in obj.values():
            _ensure_no_secret_values(v)
    elif isinstance(obj, list):
        for item in obj:
            _ensure_no_secret_values(item)
