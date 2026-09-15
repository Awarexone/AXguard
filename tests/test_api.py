"""Tests for AXGuard local-first Security Intelligence API."""

from __future__ import annotations

import time
from pathlib import Path

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")

from fastapi.testclient import TestClient

from engines.api.app import create_app
from engines.api.providers.factory import get_provider, require_provider_for_enrichment
from engines.api.providers.none import NoneProvider
from engines.api.settings import load_settings
from engines.api.errors import ApiError


@pytest.fixture()
def api_env(tmp_path, monkeypatch):
    data_dir = tmp_path / "api-data"
    monkeypatch.setenv("AXGUARD_API_DATA_DIR", str(data_dir))
    monkeypatch.setenv("AXGUARD_API_HOST", "127.0.0.1")
    monkeypatch.setenv("AXGUARD_API_PORT", "8787")
    monkeypatch.delenv("AXGUARD_API_REQUIRE_AUTH", raising=False)
    monkeypatch.setenv("AXGUARD_AI_MODE", "no-llm")
    monkeypatch.setenv("AXGUARD_AI_PROVIDER", "none")
    settings = load_settings(data_dir=data_dir)
    app = create_app(settings)
    worker = app.state.worker
    with TestClient(app) as client:
        yield client, settings, tmp_path
    worker.stop()


def test_none_provider_available_but_rejects_llm_enrichment():
    p = NoneProvider()
    assert p.mode == "none"
    assert p.name == "none"
    assert p.available is True
    with pytest.raises(ApiError) as ei:
        require_provider_for_enrichment("llm", p)
    assert ei.value.status_code == 422


def test_health_and_version(api_env):
    client, settings, _ = api_env
    h = client.get("/v1/health")
    assert h.status_code == 200
    body = h.json()
    assert body["status"] == "ok"
    assert body["provider"]["hosted_llm"] is False
    assert body["provider"]["llm_mode"] == "no-llm"
    v = client.get("/v1/version")
    assert v.status_code == 200
    assert "version" in v.json()


def test_projects_crud_and_scan_idempotency(api_env):
    client, settings, tmp_path = api_env
    target = tmp_path / "proj"
    target.mkdir()
    (target / "app.py").write_text("password = 'secret123'\n", encoding="utf-8")

    created = client.post(
        "/v1/projects",
        json={"name": "demo", "path": str(target)},
    )
    assert created.status_code == 201
    project = created.json()
    pid = project["id"]

    listed = client.get("/v1/projects")
    assert listed.status_code == 200
    assert "data" in listed.json()
    assert listed.json()["has_more"] is False

    s1 = client.post(
        f"/v1/projects/{pid}/scans",
        json={"mode": "lite", "enrichment": "none"},
        headers={"Idempotency-Key": "same-key"},
    )
    assert s1.status_code == 202
    s2 = client.post(
        f"/v1/projects/{pid}/scans",
        json={"mode": "lite", "enrichment": "none"},
        headers={"Idempotency-Key": "same-key"},
    )
    assert s2.status_code == 202
    assert s1.json()["id"] == s2.json()["id"]

    # wait for worker
    scan_id = s1.json()["id"]
    deadline = time.time() + 30
    status = "queued"
    while time.time() < deadline:
        got = client.get(f"/v1/scans/{scan_id}")
        assert got.status_code == 200
        status = got.json()["status"]
        if status in {"completed", "partial", "failed", "cancelled"}:
            break
        time.sleep(0.2)
    assert status in {"completed", "partial", "failed"}

    findings = client.get("/v1/findings", params={"project_id": pid})
    assert findings.status_code == 200
    assert "data" in findings.json()


def test_enrichment_llm_without_provider_422(api_env):
    client, settings, tmp_path = api_env
    target = tmp_path / "proj2"
    target.mkdir()
    (target / "x.py").write_text("x=1\n", encoding="utf-8")
    pid = client.post("/v1/projects", json={"name": "p2", "path": str(target)}).json()["id"]
    resp = client.post(
        f"/v1/projects/{pid}/scans",
        json={"mode": "lite", "enrichment": "llm"},
    )
    assert resp.status_code == 422
    assert resp.json()["error"]["code"] == "LLM_NOT_CONFIGURED"


def test_keys_create_list_revoke(api_env):
    client, _, _ = api_env
    created = client.post("/v1/keys", json={"name": "t", "scopes": ["*"]})
    assert created.status_code == 201
    body = created.json()
    assert body["api_key"].startswith("axg_")
    key_id = body["id"]
    listed = client.get("/v1/keys")
    assert listed.status_code == 200
    assert "data" in listed.json()
    revoked = client.post(f"/v1/keys/{key_id}/revoke")
    assert revoked.status_code == 200
    assert revoked.json().get("revoked_at")


def test_get_provider_default_none():
    p = get_provider(mode="no-llm", provider="none")
    assert isinstance(p, NoneProvider)
    assert p.available is True
