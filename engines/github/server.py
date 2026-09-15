"""Minimal stdlib HTTP server for GitHub webhooks."""

from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Callable

from engines.github.app import GitHubApp, GitHubAppCredentials
from engines.github.client import GitHubClient, HttpGitHubClient
from engines.github.config import GitHubBotConfig, load_github_config
from engines.github.installation import InstallationStore
from engines.github.pipeline import run_webhook_pipeline
from engines.github.webhooks import ReplayCache, ReplayError, SignatureError, verify_and_parse


WebhookHandlerFactory = Callable[[], type[BaseHTTPRequestHandler]]


def make_webhook_handler(
    *,
    credentials: GitHubAppCredentials | None = None,
    app: GitHubApp | None = None,
    client: GitHubClient | None = None,
    config: GitHubBotConfig | None = None,
    store: InstallationStore | None = None,
    replay_cache: ReplayCache | None = None,
    workspace_provider: Callable[[Any], Any] | None = None,
    path: str = "/webhooks/github",
) -> type[BaseHTTPRequestHandler]:
    """Build a BaseHTTPRequestHandler class bound to adapter state."""

    cfg = config or load_github_config()
    creds = credentials
    gh_app = app
    if gh_app is None and creds is not None:
        gh_app = GitHubApp(creds, client=client or HttpGitHubClient())
    http_client: GitHubClient = client or (gh_app.client if gh_app else HttpGitHubClient())
    inst_store = store or InstallationStore()
    cache = replay_cache or ReplayCache()
    secret = (creds.webhook_secret if creds else "") or ""

    class WebhookHandler(BaseHTTPRequestHandler):
        def log_message(self, fmt: str, *args: Any) -> None:
            # Avoid logging bodies / tokens
            sys_stderr_write = getattr(self, "_ax_log", None)
            msg = fmt % args
            if "token" in msg.lower() or "secret" in msg.lower():
                return
            BaseHTTPRequestHandler.log_message(self, "%s", msg[:200])

        def do_GET(self) -> None:  # noqa: N802
            if self.path in ("/", "/health", "/healthz"):
                self._json(200, {"ok": True, "service": "axguard-github"})
                return
            self._json(404, {"ok": False, "error": "not_found"})

        def do_POST(self) -> None:  # noqa: N802
            if self.path.rstrip("/") != path.rstrip("/"):
                self._json(404, {"ok": False, "error": "not_found"})
                return
            length = int(self.headers.get("Content-Length") or 0)
            # Cap body size (oversized PR payloads / abuse)
            if length > 5_000_000:
                self._json(413, {"ok": False, "error": "payload_too_large"})
                return
            body = self.rfile.read(length) if length else b""
            event = self.headers.get("X-GitHub-Event") or ""
            delivery_id = self.headers.get("X-GitHub-Delivery") or ""
            signature = self.headers.get("X-Hub-Signature-256")
            try:
                if not secret:
                    raise SignatureError("webhook secret not configured")
                delivery = verify_and_parse(
                    body=body,
                    signature_header=signature,
                    secret=secret,
                    event=event,
                    delivery_id=delivery_id,
                    replay_cache=cache,
                )
            except SignatureError as exc:
                self._json(401, {"ok": False, "error": "invalid_signature", "detail": str(exc)})
                return
            except ReplayError as exc:
                self._json(409, {"ok": False, "error": "replay", "detail": str(exc)})
                return
            except Exception as exc:  # noqa: BLE001
                self._json(400, {"ok": False, "error": "bad_request", "detail": str(exc)[:200]})
                return

            def get_token(installation_id: int) -> str:
                if gh_app is None:
                    raise RuntimeError("GitHub App credentials not configured")
                return gh_app.get_installation_token(installation_id).token

            workspace = None
            if workspace_provider is not None:
                workspace = workspace_provider(delivery)

            try:
                result = run_webhook_pipeline(
                    delivery,
                    client=http_client,
                    get_token=get_token,
                    workspace=workspace,
                    config=cfg,
                    store=inst_store,
                )
            except Exception as exc:  # noqa: BLE001
                self._json(500, {"ok": False, "error": "pipeline_error", "detail": str(exc)[:300]})
                return

            self._json(200, {"ok": True, "event": event, "result": _public_result(result)})

        def _json(self, code: int, payload: dict[str, Any]) -> None:
            raw = json.dumps(payload, default=str).encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

    return WebhookHandler


def _public_result(result: dict[str, Any]) -> dict[str, Any]:
    """Strip non-serializable / sensitive fields from pipeline response."""
    out: dict[str, Any] = {}
    for k, v in result.items():
        if k == "result" and hasattr(v, "verdict"):
            out[k] = {
                "mode": getattr(v.mode, "value", v.mode),
                "verdict": getattr(v.verdict, "value", v.verdict),
                "analysis_failed": v.analysis_failed,
                "finding_count": len(v.findings or []),
            }
        elif k == "published":
            check = (v or {}).get("check")
            out[k] = {
                "check_run_id": getattr(check, "check_run_id", None),
                "conclusion": getattr(check, "conclusion", None),
            }
        else:
            out[k] = v
    return out


def serve_webhooks(
    host: str = "127.0.0.1",
    port: int = 8787,
    **handler_kwargs: Any,
) -> ThreadingHTTPServer:
    """Start webhook server (blocking serve_forever left to caller)."""
    handler = make_webhook_handler(**handler_kwargs)
    server = ThreadingHTTPServer((host, port), handler)
    return server


def run_server_forever(
    host: str | None = None,
    port: int | None = None,
    config: GitHubBotConfig | None = None,
) -> None:
    """CLI-friendly blocking server using env credentials."""
    cfg = config or load_github_config()
    host = host or cfg.github.webhook_host
    port = port if port is not None else cfg.github.webhook_port
    creds = GitHubAppCredentials.from_env(
        app_id_env=cfg.github.app_id_env,
        private_key_env=cfg.github.private_key_env,
        private_key_path_env=cfg.github.private_key_path_env,
        webhook_secret_env=cfg.github.webhook_secret_env,
    )
    server = serve_webhooks(host=host, port=port, credentials=creds, config=cfg)
    print(f"AXGuard GitHub webhook listening on http://{host}:{port}/webhooks/github")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        server.shutdown()
