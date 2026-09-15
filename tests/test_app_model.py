"""Tests for Application Understanding + Attack Surface Graph."""

from __future__ import annotations

import json
from pathlib import Path

from engines.app_model import (
    APPLICATION_MODEL_VERSION,
    build_application_model,
    query_graph,
    write_application_model,
)
from engines.audit import AuditOptions, run_audit
from engines.report import render_markdown

ROOT = Path(__file__).resolve().parents[1]
SURFACE = ROOT / "fixtures" / "surface_app"
RULES = ROOT / "rules"


def test_build_model_discovers_stack_and_routes():
    model = build_application_model(SURFACE)
    assert model["schema_version"] == APPLICATION_MODEL_VERSION
    langs = {x["name"] for x in model["application"]["languages"]}
    assert "python" in langs
    frameworks = {x["name"] for x in model["application"]["frameworks"]}
    assert "flask" in frameworks
    paths = {ep.get("path") for ep in model["entrypoints"]}
    assert any("/health" in p or "/api" in p for p in paths if p)


def test_require_auth_route_marked_likely_required():
    model = build_application_model(SURFACE)
    user_eps = [
        ep
        for ep in model["entrypoints"]
        if ep.get("path") and "/api/users" in str(ep["path"])
    ]
    assert user_eps
    status = (user_eps[0].get("authentication") or {}).get("status")
    assert status == "required"


def test_health_stays_auth_unknown_without_decorator():
    model = build_application_model(SURFACE)
    health = [ep for ep in model["entrypoints"] if ep.get("path") == "/health"]
    assert health
    assert (health[0].get("authentication") or {}).get("status") == "unknown"


def test_ai_and_external_services_from_evidence():
    model = build_application_model(SURFACE)
    assert model["ai_components"] or model["external_services"]
    names = {s.get("name") for s in model.get("external_services") or []}
    assert "openai" in names or "anthropic" in names


def test_comment_only_stripe_not_confirmed_service():
    model = build_application_model(SURFACE)
    stripe_confirmed = [
        s
        for s in model.get("external_services") or []
        if str(s.get("name", "")).lower() == "stripe"
        and s.get("confidence") == "confirmed"
        and "false_positive" in str((s.get("evidence") or {}).get("file", ""))
    ]
    assert stripe_confirmed == []


def test_confidence_enum_and_secret_redaction():
    model = build_application_model(SURFACE)
    dump = json.dumps(model)
    assert "sk_live" not in dump

    bad: list[str] = []

    def walk(obj):
        if isinstance(obj, dict):
            if "confidence" in obj and obj["confidence"] not in {
                "confirmed",
                "likely",
                "unknown",
            }:
                bad.append(str(obj["confidence"]))
            if obj.get("value") not in (None, "REDACTED", "unknown") and "secret" in str(
                obj.get("type", "")
            ).lower():
                bad.append("secret-value")
            for v in obj.values():
                walk(v)
        elif isinstance(obj, list):
            for v in obj:
                walk(v)

    walk(model)
    assert bad == []


def test_query_graph_auth_unknown():
    model = build_application_model(SURFACE)
    hits = query_graph(model, "endpoints_auth_unknown")
    assert isinstance(hits, list)
    assert hits  # /health at minimum


def test_write_application_model_artifacts(tmp_path: Path):
    model = build_application_model(SURFACE)
    paths = write_application_model(model, tmp_path)
    json_path = Path(paths["json"])
    md_path = Path(paths.get("markdown") or paths.get("md"))
    assert json_path.exists()
    assert md_path.exists()
    assert "Application" in md_path.read_text(encoding="utf-8")


def test_audit_surface_phase_embeds_model(tmp_path: Path):
    result = run_audit(
        AuditOptions(target=SURFACE, rules_dir=RULES, out_dir=tmp_path)
    )
    surface = next(p for p in result["phases"] if p["id"] == "surface")
    assert surface["status"] == "ok"
    assert "application_model_summary" in surface
    assert result.get("application_model_summary", {}).get("endpoint_count", 0) >= 1
    assert (tmp_path / "application-model.json").exists()
    md = render_markdown(result)
    assert "Application understanding" in md
