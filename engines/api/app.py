"""FastAPI application factory for the local Security Intelligence API."""

from __future__ import annotations

from typing import Any

from engines.api import __version__
from engines.api.deps import AppDeps
from engines.api.errors import ApiError, new_request_id
from engines.api.jobs import JobWorker
from engines.api.providers.factory import get_provider
from engines.api.settings import Settings, load_settings
from engines.api.storage import Store


def create_app(settings: Settings | None = None) -> Any:
    """Build FastAPI app; start JobWorker with handler=run_scan_job."""
    try:
        from fastapi import FastAPI, Request
        from fastapi.responses import JSONResponse
    except ImportError as exc:  # pragma: no cover
        raise ImportError(
            "uvicorn/fastapi required. Install with: pip install 'axguard[api]'"
        ) from exc

    from engines.api.services.pipeline import run_scan_job

    settings = settings or load_settings()
    settings.data_dir.mkdir(parents=True, exist_ok=True)
    store = Store(settings.db_path)
    provider = get_provider(settings=settings)
    worker = JobWorker(store, settings, handler=run_scan_job)
    deps = AppDeps(settings=settings, store=store, worker=worker, provider=provider)

    app = FastAPI(
        title="AXGuard Security Intelligence API",
        version=__version__,
        description=(
            "Local-first security intelligence. No AwareXone cloud. "
            "No hosted LLM — use no-llm, Ollama/local, or BYOK."
        ),
    )
    app.state.deps = deps
    app.state.settings = settings
    app.state.store = store
    app.state.worker = worker

    @app.exception_handler(ApiError)
    async def api_error_handler(request: Request, exc: ApiError):
        return JSONResponse(status_code=exc.status_code, content=exc.as_dict())

    @app.middleware("http")
    async def request_id_middleware(request: Request, call_next):
        rid = request.headers.get("x-request-id") or new_request_id()
        request.state.request_id = rid
        response = await call_next(request)
        response.headers["X-Request-Id"] = rid
        return response

    @app.on_event("startup")
    def _startup() -> None:
        worker.start()

    @app.on_event("shutdown")
    def _shutdown() -> None:
        worker.stop()
        store.close()

    from engines.api.routes import mount_routes

    mount_routes(app, deps)
    return app
