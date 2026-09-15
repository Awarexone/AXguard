"""In-process job worker — claims queued scans from SQLite."""

from __future__ import annotations

import logging
import threading
import time
from typing import Any, Callable

from engines.api.settings import Settings
from engines.api.storage import Store

log = logging.getLogger("axguard.api.jobs")

# Never log API keys or LLM credentials.
ScanHandler = Callable[[Store, Settings, dict[str, Any]], dict[str, Any]]


class JobWorker:
    def __init__(
        self,
        store: Store,
        settings: Settings,
        *,
        handler: ScanHandler | None = None,
        max_concurrent: int | None = None,
        poll_interval: float = 0.5,
    ) -> None:
        self.store = store
        self.settings = settings
        self.handler = handler
        self.max_concurrent = max(1, max_concurrent or settings.max_concurrent_jobs)
        self.poll_interval = poll_interval
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._active = 0
        self._active_lock = threading.Lock()

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(
            target=self._loop, name="axguard-api-worker", daemon=True
        )
        self._thread.start()

    def stop(self, timeout: float = 2.0) -> None:
        self._stop.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=timeout)

    @property
    def running(self) -> bool:
        return bool(self._thread and self._thread.is_alive())

    def _loop(self) -> None:
        while not self._stop.is_set():
            with self._active_lock:
                can_start = self._active < self.max_concurrent
            if not can_start:
                time.sleep(self.poll_interval)
                continue
            scan = self.store.claim_next_scan()
            if not scan:
                time.sleep(self.poll_interval)
                continue
            fresh = self.store.get_scan(scan["id"])
            if fresh and fresh.get("status") == "cancelled":
                continue
            with self._active_lock:
                self._active += 1
            t = threading.Thread(
                target=self._run_scan,
                args=(scan,),
                name=f"axguard-scan-{scan['id'][:12]}",
                daemon=True,
            )
            t.start()

    def _run_scan(self, scan: dict[str, Any]) -> None:
        scan_id = scan["id"]
        try:
            current = self.store.get_scan(scan_id)
            if current and current.get("status") == "cancelled":
                return
            if self.handler is None:
                self.store.update_scan(
                    scan_id,
                    status="failed",
                    error="No scan handler registered",
                    completed_at=time.time(),
                )
                return
            result = self.handler(self.store, self.settings, scan)
            # Re-check cancel
            current = self.store.get_scan(scan_id)
            if current and current.get("status") == "cancelled":
                return
            status = result.get("job_status") or result.get("status") or "completed"
            if status not in {"completed", "partial", "failed", "cancelled"}:
                status = "completed"
            warnings = result.get("warnings") or []
            self.store.update_scan(
                scan_id,
                status=status,
                result=result,
                warnings=warnings,
                progress=1.0,
                current_phase="done",
                error=result.get("error"),
                completed_at=time.time(),
            )
        except Exception as exc:  # noqa: BLE001
            log.exception("scan %s failed", scan_id)
            self.store.update_scan(
                scan_id,
                status="failed",
                error=str(exc),
                completed_at=time.time(),
            )
        finally:
            with self._active_lock:
                self._active = max(0, self._active - 1)
