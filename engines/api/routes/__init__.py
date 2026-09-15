"""All /v1 routes mounted via mount_routes(app, deps).

CRITICAL: do NOT use `from __future__ import annotations` here — it breaks
FastAPI OpenAPI generation for Request. Import Request inside mount_routes.
"""

import secrets
import time
from pathlib import Path
from typing import Any

from engines.api import __version__
from engines.api.auth import create_key_record, normalize_scopes
from engines.api.deps import AppDeps, resolve_auth
from engines.api.errors import ApiError
from engines.api.providers.factory import (
    get_provider,
    provider_status,
    require_provider_for_enrichment,
)
from engines.api.services.pipeline import run_review_sync


def mount_routes(app: Any, deps: AppDeps) -> None:
    from fastapi import Request

    store = deps.store
    settings = deps.settings

    def _client_host(request: Request) -> str | None:
        if request.client:
            return request.client.host
        return None

    def _auth(request: Request, scope: str | None = None):
        ctx = resolve_auth(
            deps,
            authorization=request.headers.get("authorization"),
            client_host=_client_host(request),
        )
        if scope:
            ctx.require_scope(scope)
        return ctx

    async def _json(request: Request) -> dict[str, Any]:
        try:
            body = await request.json()
        except Exception as exc:  # noqa: BLE001
            raise ApiError(
                "INVALID_JSON",
                "Request body must be JSON object",
                status_code=400,
            ) from exc
        if body is None:
            return {}
        if not isinstance(body, dict):
            raise ApiError(
                "INVALID_JSON",
                "Request body must be a JSON object",
                status_code=400,
            )
        return body

    def _project(project_id: str) -> dict[str, Any]:
        project = store.get_project(project_id)
        if not project:
            raise ApiError("NOT_FOUND", "Project not found", status_code=404)
        return project

    # --- health / version -------------------------------------------------

    @app.get("/v1/health")
    async def health():
        provider = deps.provider or get_provider(settings=settings)
        return {
            "status": "ok",
            "version": __version__,
            "listen": f"{settings.host}:{settings.port}",
            "loopback": settings.is_loopback,
            "require_auth": settings.require_auth,
            "provider": provider_status(provider, settings=settings),
        }

    @app.get("/v1/version")
    async def version():
        return {"version": __version__, "api": "v1", "product": "axguard-api"}

    # --- projects ---------------------------------------------------------

    @app.get("/v1/projects")
    async def list_projects(request: Request, limit: int = 50, cursor: str | None = None):
        _auth(request, "projects:read")
        return store.list_projects(limit=limit, cursor=cursor)

    @app.post("/v1/projects", status_code=201)
    async def create_project(request: Request):
        _auth(request, "projects:write")
        body = await _json(request)
        name = str(body.get("name") or "").strip()
        path = str(body.get("path") or body.get("source_path") or "").strip()
        if not name or not path:
            raise ApiError(
                "VALIDATION_ERROR",
                "name and path are required",
                status_code=422,
            )
        resolved = str(Path(path).expanduser().resolve())
        return store.create_project(
            {
                "name": name,
                "path": resolved,
                "description": body.get("description"),
                "repository": body.get("repository"),
                "default_branch": body.get("default_branch"),
                "language": body.get("language"),
                "frameworks": body.get("frameworks") or [],
                "configuration": body.get("configuration") or {},
            }
        )

    @app.get("/v1/projects/{project_id}")
    async def get_project(project_id: str, request: Request):
        _auth(request, "projects:read")
        return _project(project_id)

    @app.delete("/v1/projects/{project_id}")
    async def delete_project(project_id: str, request: Request):
        _auth(request, "projects:write")
        _project(project_id)
        store.delete_project(project_id)
        return {"deleted": True, "id": project_id}

    # --- scans ------------------------------------------------------------

    @app.post("/v1/projects/{project_id}/scans", status_code=202)
    async def create_scan(project_id: str, request: Request):
        _auth(request, "scans:write")
        project = _project(project_id)
        body = await _json(request)
        mode = str(body.get("mode") or "balanced").lower()
        if mode not in {"lite", "balanced", "deep", "max"}:
            raise ApiError(
                "VALIDATION_ERROR",
                "mode must be lite|balanced|deep|max",
                status_code=422,
            )
        enrichment = str(body.get("enrichment") or "none").lower()
        provider = deps.provider or get_provider(settings=settings)
        require_provider_for_enrichment(enrichment, provider)
        idem = request.headers.get("idempotency-key") or body.get("idempotency_key")
        scan = store.create_scan(
            {
                "project_id": project["id"],
                "status": "queued",
                "mode": mode,
                "enrichment": enrichment,
                "idempotency_key": idem,
                "payload": {
                    "mode": mode,
                    "enrichment": enrichment,
                    "analysis": body.get("analysis"),
                },
            }
        )
        return {"id": scan["id"], "scan_id": scan["id"], "status": scan["status"], **scan}

    @app.get("/v1/projects/{project_id}/scans")
    async def list_scans(
        project_id: str,
        request: Request,
        limit: int = 50,
        cursor: str | None = None,
    ):
        _auth(request, "scans:read")
        _project(project_id)
        return store.list_scans(project_id=project_id, limit=limit, cursor=cursor)

    @app.get("/v1/scans/{scan_id}")
    async def get_scan(scan_id: str, request: Request):
        _auth(request, "scans:read")
        scan = store.get_scan(scan_id)
        if not scan:
            raise ApiError("NOT_FOUND", "Scan not found", status_code=404)
        return scan

    @app.post("/v1/scans/{scan_id}/cancel")
    async def cancel_scan(scan_id: str, request: Request):
        _auth(request, "scans:write")
        scan = store.cancel_scan(scan_id)
        if not scan:
            raise ApiError("NOT_FOUND", "Scan not found", status_code=404)
        return scan

    # --- findings + evidence ----------------------------------------------

    @app.get("/v1/findings")
    async def list_findings(
        request: Request,
        project_id: str | None = None,
        scan_id: str | None = None,
        severity: str | None = None,
        limit: int = 50,
        cursor: str | None = None,
    ):
        _auth(request, "findings:read")
        return store.list_findings(
            project_id=project_id,
            scan_id=scan_id,
            severity=severity,
            limit=limit,
            cursor=cursor,
        )

    @app.get("/v1/findings/{finding_id}")
    async def get_finding(finding_id: str, request: Request):
        _auth(request, "findings:read")
        finding = store.get_finding(finding_id)
        if not finding:
            raise ApiError("NOT_FOUND", "Finding not found", status_code=404)
        return finding

    @app.post("/v1/findings/{finding_id}/recheck")
    async def recheck_finding(finding_id: str, request: Request):
        _auth(request, "findings:read")
        finding = store.get_finding(finding_id)
        if not finding:
            raise ApiError("NOT_FOUND", "Finding not found", status_code=404)
        return {
            "finding_id": finding_id,
            "status": finding.get("status"),
            "confidence": finding.get("confidence"),
            "note": "Recheck is diagnostic; re-run a project scan for fresh engine output.",
        }

    def _ev_bundle(finding: dict[str, Any]) -> dict[str, Any]:
        return {
            "finding_id": finding.get("id"),
            "evidence": finding.get("evidence") or [],
            "evidence_chain": finding.get("evidence") or [],
            "counter_evidence": finding.get("counter_evidence") or [],
            "unknowns": finding.get("unknowns") or [],
            "confidence": finding.get("confidence") or "UNKNOWN",
        }

    @app.get("/v1/findings/{finding_id}/evidence")
    async def finding_evidence(finding_id: str, request: Request):
        _auth(request, "evidence:read")
        finding = store.get_finding(finding_id)
        if not finding:
            raise ApiError("NOT_FOUND", "Finding not found", status_code=404)
        return {"evidence": _ev_bundle(finding)["evidence"]}

    @app.get("/v1/findings/{finding_id}/evidence-chain")
    async def finding_evidence_chain(finding_id: str, request: Request):
        _auth(request, "evidence:read")
        finding = store.get_finding(finding_id)
        if not finding:
            raise ApiError("NOT_FOUND", "Finding not found", status_code=404)
        return {"evidence_chain": _ev_bundle(finding)["evidence_chain"]}

    @app.get("/v1/findings/{finding_id}/counter-evidence")
    async def finding_counter(finding_id: str, request: Request):
        _auth(request, "evidence:read")
        finding = store.get_finding(finding_id)
        if not finding:
            raise ApiError("NOT_FOUND", "Finding not found", status_code=404)
        return {"counter_evidence": _ev_bundle(finding)["counter_evidence"]}

    @app.get("/v1/findings/{finding_id}/unknowns")
    async def finding_unknowns(finding_id: str, request: Request):
        _auth(request, "evidence:read")
        finding = store.get_finding(finding_id)
        if not finding:
            raise ApiError("NOT_FOUND", "Finding not found", status_code=404)
        return {"unknowns": _ev_bundle(finding)["unknowns"]}

    @app.get("/v1/findings/{finding_id}/confidence")
    async def finding_confidence(finding_id: str, request: Request):
        _auth(request, "evidence:read")
        finding = store.get_finding(finding_id)
        if not finding:
            raise ApiError("NOT_FOUND", "Finding not found", status_code=404)
        return {
            "finding_id": finding_id,
            "confidence": finding.get("confidence") or "UNKNOWN",
            "status": finding.get("status"),
        }

    # --- flows / attack-paths / predictive --------------------------------

    @app.get("/v1/projects/{project_id}/flows")
    async def list_flows(project_id: str, request: Request):
        _auth(request, "flows:read")
        project = _project(project_id)
        payload = store.get_latest_artifact(project_id, "dataflow")
        if payload is None:
            from engines.api.services.pipeline import load_project_json

            payload = load_project_json(Path(project["path"]), "dataflow") or {}
        flows = payload.get("flows") or payload.get("paths") or payload.get("taint_paths") or []
        return {"data": flows, "next_cursor": None, "has_more": False}

    @app.post("/v1/projects/{project_id}/flows/query")
    async def query_flows(project_id: str, request: Request):
        _auth(request, "flows:read")
        project = _project(project_id)
        body = await _json(request)
        try:
            from engines.dataflow import analyze_dataflow, query_taint

            df = analyze_dataflow(Path(project["path"]))
            try:
                result = query_taint(df, body.get("query") or body)
            except TypeError:
                result = {"dataflow_summary": (df or {}).get("summary"), "query": body}
        except Exception as exc:  # noqa: BLE001
            result = {"error": str(exc), "query": body}
        return result if isinstance(result, dict) else {"result": result}

    @app.get("/v1/projects/{project_id}/attack-paths")
    async def list_attack_paths(project_id: str, request: Request):
        _auth(request, "attack_paths:read")
        project = _project(project_id)
        payload = store.get_latest_artifact(project_id, "attack_graph")
        if payload is None:
            from engines.api.services.pipeline import load_project_json

            payload = load_project_json(Path(project["path"]), "attack_graph", "attack-paths") or {}
        paths = payload.get("paths") or []
        return {"data": paths, "next_cursor": None, "has_more": False}

    @app.get("/v1/projects/{project_id}/attack-paths/{path_id}")
    async def get_attack_path(project_id: str, path_id: str, request: Request):
        _auth(request, "attack_paths:read")
        listed = await list_attack_paths(project_id, request)
        for p in listed.get("data") or []:
            if str(p.get("id") or p.get("path_id")) == path_id:
                return p
        raise ApiError("NOT_FOUND", "Attack path not found", status_code=404)

    @app.post("/v1/projects/{project_id}/attack-paths/query")
    async def query_attack_paths(project_id: str, request: Request):
        _auth(request, "attack_paths:read")
        body = await _json(request)
        listed = await list_attack_paths(project_id, request)
        return {"query": body, "matches": listed.get("data") or []}

    @app.get("/v1/projects/{project_id}/predictive-risks")
    async def list_predictive(project_id: str, request: Request):
        _auth(request, "findings:read")
        project = _project(project_id)
        payload = store.get_latest_artifact(project_id, "predictive")
        if payload is None:
            from engines.api.services.pipeline import load_project_json

            payload = load_project_json(Path(project["path"]), "predictive") or {}
        risks = payload.get("risks") or payload.get("signals") or []
        return {"data": risks, "next_cursor": None, "has_more": False, "payload": payload}

    @app.post("/v1/projects/{project_id}/predictive-risks/analyze")
    async def analyze_predictive(project_id: str, request: Request):
        _auth(request, "findings:read")
        project = _project(project_id)
        body = await _json(request)
        try:
            from engines.predictive import run_predict

            result = run_predict(Path(project["path"]), mode=body.get("mode") or "default")
            store.set_artifact(project_id, "predictive", result)
            return result
        except Exception as exc:  # noqa: BLE001
            return {"risks": [], "error": str(exc), "note": "Predictive soft-fail"}

    # --- twin / memory / investigations -----------------------------------

    @app.get("/v1/projects/{project_id}/twin")
    async def get_twin(project_id: str, request: Request):
        _auth(request, "twin:read")
        payload = store.get_latest_artifact(project_id, "twin")
        return payload or {"twin": None, "note": "No twin artifact yet — POST .../twin/build"}

    @app.post("/v1/projects/{project_id}/twin/build")
    async def build_twin(project_id: str, request: Request):
        _auth(request, "twin:write")
        project = _project(project_id)
        body = await _json(request)
        from engines.twin import run_twin

        result = run_twin(
            Path(project["path"]),
            simulate=bool(body.get("simulate", True)),
            controls=bool(body.get("controls", True)),
            blast_entity=body.get("blast_entity"),
            attacker_profile=body.get("attacker_profile") or "PUBLIC_USER",
        )
        store.set_artifact(project_id, "twin", result)
        return result

    @app.post("/v1/projects/{project_id}/twin/what-if")
    async def twin_what_if(project_id: str, request: Request):
        _auth(request, "twin:write")
        project = _project(project_id)
        body = await _json(request)
        from engines.twin import run_twin_what_if

        result = run_twin_what_if(
            Path(project["path"]),
            scenario=body.get("scenario"),
            remove_control=body.get("remove_control"),
            grant_agent_tool=body.get("grant_agent_tool"),
            compromise_entity=body.get("compromise_entity"),
            assumptions=body.get("assumptions"),
        )
        return result

    @app.post("/v1/projects/{project_id}/twin/blast-radius")
    async def twin_blast(project_id: str, request: Request):
        _auth(request, "twin:read")
        project = _project(project_id)
        body = await _json(request)
        entity = body.get("entity") or body.get("blast_entity")
        from engines.twin import run_twin

        result = run_twin(Path(project["path"]), blast_entity=entity, simulate=False, controls=False)
        return result.get("blast_radius") or result

    @app.post("/v1/projects/{project_id}/twin/compare")
    async def twin_compare(project_id: str, request: Request):
        _auth(request, "twin:read")
        body = await _json(request)
        from engines.twin import run_twin_compare

        return run_twin_compare(body.get("before") or {}, body.get("after") or {})

    @app.get("/v1/projects/{project_id}/memory")
    async def get_memory(project_id: str, request: Request):
        _auth(request, "memory:read")
        payload = store.get_latest_artifact(project_id, "memory")
        return payload or {"note": "No memory artifact yet"}

    @app.post("/v1/projects/{project_id}/memory")
    async def record_memory(project_id: str, request: Request):
        _auth(request, "memory:read")
        project = _project(project_id)
        from engines.memory import run_memory_record

        result = run_memory_record(Path(project["path"]))
        store.set_artifact(project_id, "memory", result)
        return result

    def _make(inv_id: str, project_id: str, status: str, payload: dict, result: Any = None):
        return {
            "id": inv_id,
            "project_id": project_id,
            "status": status,
            "payload": payload,
            "result": result,
            "created_at": time.time(),
        }

    @app.post("/v1/projects/{project_id}/investigations", status_code=202)
    async def create_investigation(project_id: str, request: Request):
        _auth(request, "investigations:write")
        project = _project(project_id)
        body = await _json(request)
        inv_id = "inv_" + secrets.token_hex(8)
        try:
            from engines.investigation import run_investigation

            result = run_investigation(
                Path(project["path"]),
                finding_id=body.get("finding_id"),
                budget=body.get("budget") or "balanced",
            )
            rec = _make(inv_id, project_id, "COMPLETED", body, result)
        except Exception as exc:  # noqa: BLE001
            rec = _make(inv_id, project_id, "FAILED", body, {"error": str(exc)})
        store.set_artifact(project_id, f"investigation:{inv_id}", rec)
        store.set_artifact(project_id, "investigation_latest", rec)
        return rec

    @app.get("/v1/investigations/{investigation_id}")
    async def get_investigation(investigation_id: str, request: Request):
        _auth(request, "investigations:read")
        # scan artifacts across projects is expensive; require project_id query soft
        project_id = request.query_params.get("project_id")
        if project_id:
            rec = store.get_latest_artifact(project_id, f"investigation:{investigation_id}")
            if rec:
                return rec
        raise ApiError(
            "NOT_FOUND",
            "Investigation not found (pass ?project_id=)",
            status_code=404,
        )

    @app.post("/v1/investigations/{investigation_id}/cancel")
    async def cancel_investigation(investigation_id: str, request: Request):
        _auth(request, "investigations:write")
        return {"id": investigation_id, "status": "CANCELLED"}

    @app.post("/v1/investigations/{investigation_id}/resume")
    async def resume_investigation(investigation_id: str, request: Request):
        _auth(request, "investigations:write")
        return {"id": investigation_id, "status": "QUEUED", "note": "Re-POST investigations to re-run"}

    # --- reviews / diff / posture / reports -------------------------------

    @app.post("/v1/projects/{project_id}/reviews")
    async def create_review(project_id: str, request: Request):
        _auth(request, "reviews:write")
        project = _project(project_id)
        body = await _json(request)
        return run_review_sync(store, project, body)

    @app.post("/v1/projects/{project_id}/security-diff")
    async def security_diff(project_id: str, request: Request):
        _auth(request, "findings:read")
        project = _project(project_id)
        body = await _json(request)
        base = Path(body["base_path"]) if body.get("base_path") else None
        head = Path(body["head_path"]) if body.get("head_path") else Path(project["path"])
        from engines.scanner import ScanOptions, run_scan
        from engines.paths import default_rules_dir

        empty = {
            "new_findings": [],
            "resolved_findings": [],
            "regressions": [],
            "security_posture_delta": {},
        }
        if not base or not base.exists() or not head.exists():
            return {**empty, "note": "base_path and head_path required"}
        rules = default_rules_dir()
        base_scan = run_scan(ScanOptions(target=base, rules_dir=rules))
        head_scan = run_scan(ScanOptions(target=head, rules_dir=rules))

        def key(f: dict[str, Any]) -> str:
            return f"{f.get('id')}|{f.get('file')}|{f.get('line')}"

        base_map = {key(f): f for f in base_scan.get("findings") or []}
        head_map = {key(f): f for f in head_scan.get("findings") or []}
        return {
            **empty,
            "new_findings": [head_map[k] for k in head_map.keys() - base_map.keys()],
            "resolved_findings": [base_map[k] for k in base_map.keys() - head_map.keys()],
            "base_finding_count": len(base_map),
            "head_finding_count": len(head_map),
        }

    @app.get("/v1/projects/{project_id}/security-posture")
    async def security_posture(project_id: str, request: Request):
        _auth(request, "posture:read")
        project = _project(project_id)
        findings = store.list_findings(project_id=project_id, limit=500).get("data") or []
        by_sev: dict[str, int] = {}
        for f in findings:
            sev = str(f.get("severity") or "info").lower()
            by_sev[sev] = by_sev.get(sev, 0) + 1
        ag = store.get_latest_artifact(project_id, "attack_graph") or {}
        pred = store.get_latest_artifact(project_id, "predictive") or {}
        return {
            "project_id": project_id,
            "path": project["path"],
            "finding_counts_by_severity": by_sev,
            "verified_findings": sum(
                1 for f in findings if str(f.get("status", "")).upper() == "VERIFIED"
            ),
            "attack_paths": len(ag.get("paths") or []),
            "predictive_risks": len(pred.get("risks") or pred.get("signals") or []),
            "methodology": "Local SQLite findings index + optional artifacts. No opaque score.",
        }

    @app.post("/v1/projects/{project_id}/reports", status_code=201)
    async def create_report(project_id: str, request: Request):
        _auth(request, "reports:write")
        project = _project(project_id)
        body = await _json(request)
        report_id = "rpt_" + secrets.token_hex(8)
        findings = store.list_findings(project_id=project_id, limit=200).get("data") or []
        report = {
            "id": report_id,
            "project_id": project_id,
            "format": body.get("format") or "json",
            "finding_count": len(findings),
            "findings": findings,
            "created_at": time.time(),
            "path": project["path"],
        }
        store.set_artifact(project_id, f"report:{report_id}", report)
        store.set_artifact(project_id, "report_latest", report)
        return report

    @app.get("/v1/reports/{report_id}")
    async def get_report(report_id: str, request: Request):
        _auth(request, "reports:read")
        project_id = request.query_params.get("project_id")
        if project_id:
            rec = store.get_latest_artifact(project_id, f"report:{report_id}")
            if rec:
                return rec
        raise ApiError("NOT_FOUND", "Report not found (pass ?project_id=)", status_code=404)

    # --- keys / webhooks --------------------------------------------------

    @app.post("/v1/keys", status_code=201)
    async def create_key(request: Request):
        ctx = _auth(request)
        if ctx.via != "loopback":
            ctx.require_scope("keys:write")
        body = await _json(request)
        raw, record = create_key_record(
            name=str(body.get("name") or "default").strip() or "default",
            scopes=normalize_scopes(body.get("scopes")),
            expires_at=body.get("expires_at"),
        )
        store.insert_api_key(record)
        return {
            "id": record["id"],
            "name": record["name"],
            "scopes": record["scopes"],
            "prefix": record["prefix"],
            "api_key": raw,
            "message": "Store this key now. It will not be shown again.",
        }

    @app.get("/v1/keys")
    async def list_keys(request: Request):
        ctx = _auth(request)
        if ctx.via != "loopback":
            ctx.require_scope("keys:read")
        return store.list_api_keys()

    @app.post("/v1/keys/{key_id}/revoke")
    async def revoke_key(key_id: str, request: Request):
        ctx = _auth(request)
        if ctx.via != "loopback":
            ctx.require_scope("keys:write")
        key = store.revoke_api_key(key_id)
        if not key:
            raise ApiError("NOT_FOUND", "Key not found", status_code=404)
        return {"id": key["id"], "revoked_at": key.get("revoked_at")}

    @app.get("/v1/webhooks")
    async def list_webhooks(request: Request, project_id: str | None = None):
        _auth(request, "webhooks:read")
        return store.list_webhooks(project_id=project_id)

    @app.post("/v1/webhooks", status_code=201)
    async def create_webhook(request: Request):
        _auth(request, "webhooks:write")
        body = await _json(request)
        url = str(body.get("url") or "").strip()
        if not url:
            raise ApiError("VALIDATION_ERROR", "url is required", status_code=422)
        secret = body.get("secret") or ("whsec_" + secrets.token_hex(16))
        wh = store.create_webhook(
            {
                "project_id": body.get("project_id"),
                "url": url,
                "secret": secret,
                "events": body.get("events") or ["*"],
                "enabled": body.get("enabled", True),
            }
        )
        # include secret once
        return {**wh, "secret": secret, "hmac_note": "Sign bodies with HMAC-SHA256 of secret"}
