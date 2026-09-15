"""SQLite storage — projects, scans, findings, keys, artifacts, webhooks."""

from __future__ import annotations

import base64
import json
import sqlite3
import threading
import time
import uuid
from pathlib import Path
from typing import Any


SCHEMA = """
CREATE TABLE IF NOT EXISTS projects (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    path TEXT NOT NULL,
    description TEXT,
    repository TEXT,
    default_branch TEXT,
    language TEXT,
    frameworks TEXT,
    configuration TEXT,
    created_at REAL NOT NULL,
    updated_at REAL NOT NULL,
    last_analysis REAL,
    security_posture TEXT
);

CREATE TABLE IF NOT EXISTS scans (
    id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL,
    status TEXT NOT NULL,
    mode TEXT,
    enrichment TEXT,
    idempotency_key TEXT,
    payload TEXT,
    result TEXT,
    progress REAL,
    current_phase TEXT,
    error TEXT,
    warnings TEXT,
    created_at REAL NOT NULL,
    started_at REAL,
    completed_at REAL,
    cancelled_at REAL
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_scans_idempotency
    ON scans(project_id, idempotency_key)
    WHERE idempotency_key IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_scans_status ON scans(status);
CREATE INDEX IF NOT EXISTS idx_scans_project ON scans(project_id);

CREATE TABLE IF NOT EXISTS findings (
    id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL,
    scan_id TEXT,
    fingerprint TEXT,
    rule_id TEXT,
    title TEXT,
    severity TEXT,
    status TEXT,
    confidence TEXT,
    file TEXT,
    line INTEGER,
    payload TEXT NOT NULL,
    created_at REAL NOT NULL,
    updated_at REAL NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_findings_project ON findings(project_id);
CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);

CREATE TABLE IF NOT EXISTS api_keys (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    prefix TEXT,
    salt TEXT NOT NULL,
    key_hash TEXT NOT NULL,
    scopes TEXT NOT NULL,
    created_at REAL NOT NULL,
    expires_at REAL,
    revoked_at REAL,
    last_used_at REAL
);

CREATE TABLE IF NOT EXISTS artifacts (
    id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL,
    scan_id TEXT,
    kind TEXT NOT NULL,
    path TEXT,
    payload TEXT,
    created_at REAL NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_artifacts_project ON artifacts(project_id);

CREATE TABLE IF NOT EXISTS webhooks (
    id TEXT PRIMARY KEY,
    project_id TEXT,
    url TEXT NOT NULL,
    secret TEXT NOT NULL,
    events TEXT NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1,
    created_at REAL NOT NULL,
    updated_at REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
"""

SCAN_STATUSES = (
    "queued",
    "running",
    "completed",
    "partial",
    "failed",
    "cancelled",
)


def new_id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex[:16]}"


def _json_dumps(value: Any) -> str:
    return json.dumps(value, default=str, separators=(",", ":"))


def _json_loads(raw: str | None, default: Any = None) -> Any:
    if raw is None or raw == "":
        return default
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return default


def encode_cursor(created_at: float, item_id: str) -> str:
    raw = f"{created_at}|{item_id}".encode("utf-8")
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def decode_cursor(cursor: str | None) -> tuple[float, str] | None:
    if not cursor:
        return None
    pad = "=" * (-len(cursor) % 4)
    try:
        raw = base64.urlsafe_b64decode(cursor + pad).decode("utf-8")
        created_s, item_id = raw.split("|", 1)
        return float(created_s), item_id
    except (ValueError, UnicodeDecodeError, OSError):
        return None


class Store:
    """Thread-safe SQLite store under ~/.axguard/api/api.db by default."""

    def __init__(self, db_path: Path | str) -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(
            str(self.db_path),
            check_same_thread=False,
            isolation_level=None,
        )
        self._conn.row_factory = sqlite3.Row
        with self._lock:
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA foreign_keys=ON")
            self._conn.executescript(SCHEMA)

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    def _execute(self, sql: str, params: tuple[Any, ...] = ()) -> sqlite3.Cursor:
        with self._lock:
            return self._conn.execute(sql, params)

    def _fetchone(self, sql: str, params: tuple[Any, ...] = ()) -> sqlite3.Row | None:
        with self._lock:
            return self._conn.execute(sql, params).fetchone()

    def _fetchall(self, sql: str, params: tuple[Any, ...] = ()) -> list[sqlite3.Row]:
        with self._lock:
            return list(self._conn.execute(sql, params).fetchall())

    # --- projects ---------------------------------------------------------

    def create_project(self, data: dict[str, Any]) -> dict[str, Any]:
        now = time.time()
        project_id = data.get("id") or new_id("prj")
        row = {
            "id": project_id,
            "name": data["name"],
            "path": str(data["path"]),
            "description": data.get("description"),
            "repository": data.get("repository"),
            "default_branch": data.get("default_branch"),
            "language": data.get("language"),
            "frameworks": _json_dumps(data.get("frameworks") or []),
            "configuration": _json_dumps(data.get("configuration") or {}),
            "created_at": now,
            "updated_at": now,
            "last_analysis": data.get("last_analysis"),
            "security_posture": _json_dumps(data.get("security_posture"))
            if data.get("security_posture") is not None
            else None,
        }
        with self._lock:
            self._conn.execute(
                """
                INSERT INTO projects (
                    id, name, path, description, repository, default_branch,
                    language, frameworks, configuration, created_at, updated_at,
                    last_analysis, security_posture
                ) VALUES (
                    :id, :name, :path, :description, :repository, :default_branch,
                    :language, :frameworks, :configuration, :created_at, :updated_at,
                    :last_analysis, :security_posture
                )
                """,
                row,
            )
        return self.get_project(project_id)  # type: ignore[return-value]

    def get_project(self, project_id: str) -> dict[str, Any] | None:
        row = self._fetchone("SELECT * FROM projects WHERE id = ?", (project_id,))
        return self._project_from_row(row) if row else None

    def list_projects(
        self,
        *,
        limit: int = 50,
        cursor: str | None = None,
    ) -> dict[str, Any]:
        limit = max(1, min(int(limit), 200))
        decoded = decode_cursor(cursor)
        params: list[Any] = []
        where = ""
        if decoded:
            where = "WHERE (created_at < ?) OR (created_at = ? AND id < ?)"
            params.extend([decoded[0], decoded[0], decoded[1]])
        params.append(limit + 1)
        rows = self._fetchall(
            f"SELECT * FROM projects {where} ORDER BY created_at DESC, id DESC LIMIT ?",
            tuple(params),
        )
        items = [self._project_from_row(r) for r in rows[:limit]]
        has_more = len(rows) > limit
        next_cursor = None
        if has_more and items:
            last = items[-1]
            next_cursor = encode_cursor(float(last["created_at"]), last["id"])
        return {"data": items, "next_cursor": next_cursor, "has_more": has_more}

    def update_project(self, project_id: str, **fields: Any) -> dict[str, Any] | None:
        allowed = {
            "name",
            "path",
            "description",
            "repository",
            "default_branch",
            "language",
            "frameworks",
            "configuration",
            "last_analysis",
            "security_posture",
        }
        updates: dict[str, Any] = {}
        for k, v in fields.items():
            if k not in allowed:
                continue
            if k in {"frameworks", "configuration", "security_posture"} and v is not None:
                updates[k] = _json_dumps(v)
            elif k == "path" and v is not None:
                updates[k] = str(v)
            else:
                updates[k] = v
        if not updates:
            return self.get_project(project_id)
        updates["updated_at"] = time.time()
        # Column names are allowlisted above; values stay bound parameters.
        sets = ", ".join(f"{k} = ?" for k in updates)
        sql = "UPDATE projects SET " + sets + " WHERE id = ?"
        self._execute(sql, tuple(updates.values()) + (project_id,))
        return self.get_project(project_id)

    def delete_project(self, project_id: str) -> bool:
        cur = self._execute("DELETE FROM projects WHERE id = ?", (project_id,))
        return cur.rowcount > 0

    def _project_from_row(self, row: sqlite3.Row) -> dict[str, Any]:
        d = dict(row)
        d["frameworks"] = _json_loads(d.get("frameworks"), [])
        d["configuration"] = _json_loads(d.get("configuration"), {})
        if d.get("security_posture"):
            d["security_posture"] = _json_loads(d["security_posture"], None)
        return d

    # --- scans ------------------------------------------------------------

    def create_scan(self, data: dict[str, Any]) -> dict[str, Any]:
        now = time.time()
        scan_id = data.get("id") or new_id("scn")
        idem = data.get("idempotency_key")
        if idem:
            existing = self._fetchone(
                "SELECT * FROM scans WHERE project_id = ? AND idempotency_key = ?",
                (data["project_id"], idem),
            )
            if existing:
                return self._scan_from_row(existing)
        row = {
            "id": scan_id,
            "project_id": data["project_id"],
            "status": data.get("status") or "queued",
            "mode": data.get("mode") or "balanced",
            "enrichment": data.get("enrichment") or "none",
            "idempotency_key": idem,
            "payload": _json_dumps(data.get("payload") or {}),
            "result": None,
            "progress": 0.0,
            "current_phase": None,
            "error": None,
            "warnings": _json_dumps([]),
            "created_at": now,
            "started_at": None,
            "completed_at": None,
            "cancelled_at": None,
        }
        with self._lock:
            self._conn.execute(
                """
                INSERT INTO scans (
                    id, project_id, status, mode, enrichment, idempotency_key,
                    payload, result, progress, current_phase, error, warnings,
                    created_at, started_at, completed_at, cancelled_at
                ) VALUES (
                    :id, :project_id, :status, :mode, :enrichment, :idempotency_key,
                    :payload, :result, :progress, :current_phase, :error, :warnings,
                    :created_at, :started_at, :completed_at, :cancelled_at
                )
                """,
                row,
            )
        return self.get_scan(scan_id)  # type: ignore[return-value]

    def get_scan(self, scan_id: str) -> dict[str, Any] | None:
        row = self._fetchone("SELECT * FROM scans WHERE id = ?", (scan_id,))
        return self._scan_from_row(row) if row else None

    def list_scans(
        self,
        *,
        project_id: str | None = None,
        limit: int = 50,
        cursor: str | None = None,
    ) -> dict[str, Any]:
        limit = max(1, min(int(limit), 200))
        clauses: list[str] = []
        params: list[Any] = []
        if project_id:
            clauses.append("project_id = ?")
            params.append(project_id)
        decoded = decode_cursor(cursor)
        if decoded:
            clauses.append("((created_at < ?) OR (created_at = ? AND id < ?))")
            params.extend([decoded[0], decoded[0], decoded[1]])
        where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
        params.append(limit + 1)
        rows = self._fetchall(
            f"SELECT * FROM scans {where} ORDER BY created_at DESC, id DESC LIMIT ?",
            tuple(params),
        )
        items = [self._scan_from_row(r) for r in rows[:limit]]
        has_more = len(rows) > limit
        next_cursor = None
        if has_more and items:
            last = items[-1]
            next_cursor = encode_cursor(float(last["created_at"]), last["id"])
        return {"data": items, "next_cursor": next_cursor, "has_more": has_more}

    def update_scan(self, scan_id: str, **fields: Any) -> dict[str, Any] | None:
        allowed = {
            "status",
            "mode",
            "enrichment",
            "payload",
            "result",
            "progress",
            "current_phase",
            "error",
            "warnings",
            "started_at",
            "completed_at",
            "cancelled_at",
        }
        updates: dict[str, Any] = {}
        for k, v in fields.items():
            if k not in allowed:
                continue
            if k in {"payload", "result", "warnings"} and v is not None and not isinstance(v, str):
                updates[k] = _json_dumps(v)
            else:
                updates[k] = v
        if not updates:
            return self.get_scan(scan_id)
        # Column names are allowlisted above; values stay bound parameters.
        sets = ", ".join(f"{k} = ?" for k in updates)
        sql = "UPDATE scans SET " + sets + " WHERE id = ?"
        self._execute(sql, tuple(updates.values()) + (scan_id,))
        return self.get_scan(scan_id)

    def cancel_scan(self, scan_id: str) -> dict[str, Any] | None:
        scan = self.get_scan(scan_id)
        if not scan:
            return None
        if scan["status"] in {"completed", "failed", "cancelled", "partial"}:
            return scan
        return self.update_scan(
            scan_id,
            status="cancelled",
            cancelled_at=time.time(),
            completed_at=time.time(),
        )

    def claim_next_scan(self) -> dict[str, Any] | None:
        """Atomically claim the oldest queued scan and mark it running."""
        with self._lock:
            row = self._conn.execute(
                """
                SELECT * FROM scans
                WHERE status = 'queued'
                ORDER BY created_at ASC, id ASC
                LIMIT 1
                """
            ).fetchone()
            if not row:
                return None
            scan_id = row["id"]
            now = time.time()
            self._conn.execute(
                """
                UPDATE scans
                SET status = 'running', started_at = ?, progress = 0.05
                WHERE id = ? AND status = 'queued'
                """,
                (now, scan_id),
            )
            claimed = self._conn.execute(
                "SELECT * FROM scans WHERE id = ? AND status = 'running'",
                (scan_id,),
            ).fetchone()
            return self._scan_from_row(claimed) if claimed else None

    def _scan_from_row(self, row: sqlite3.Row) -> dict[str, Any]:
        d = dict(row)
        d["payload"] = _json_loads(d.get("payload"), {})
        d["result"] = _json_loads(d.get("result"), None)
        d["warnings"] = _json_loads(d.get("warnings"), [])
        return d

    # --- findings ---------------------------------------------------------

    def upsert_finding(self, item: dict[str, Any]) -> dict[str, Any]:
        now = time.time()
        finding_id = item.get("id") or new_id("fnd")
        existing = self.get_finding(finding_id)
        payload = dict(item)
        payload["id"] = finding_id
        row = {
            "id": finding_id,
            "project_id": item["project_id"],
            "scan_id": item.get("scan_id"),
            "fingerprint": item.get("fingerprint"),
            "rule_id": item.get("rule_id") or item.get("type"),
            "title": item.get("title"),
            "severity": item.get("severity"),
            "status": item.get("status"),
            "confidence": item.get("confidence"),
            "file": item.get("file")
            or ((item.get("location") or {}).get("file") if isinstance(item.get("location"), dict) else None),
            "line": item.get("line")
            or ((item.get("location") or {}).get("line") if isinstance(item.get("location"), dict) else None),
            "payload": _json_dumps(payload),
            "created_at": existing["created_at"] if existing else item.get("created_at", now),
            "updated_at": now,
        }
        with self._lock:
            self._conn.execute(
                """
                INSERT INTO findings (
                    id, project_id, scan_id, fingerprint, rule_id, title,
                    severity, status, confidence, file, line, payload,
                    created_at, updated_at
                ) VALUES (
                    :id, :project_id, :scan_id, :fingerprint, :rule_id, :title,
                    :severity, :status, :confidence, :file, :line, :payload,
                    :created_at, :updated_at
                )
                ON CONFLICT(id) DO UPDATE SET
                    project_id=excluded.project_id,
                    scan_id=excluded.scan_id,
                    fingerprint=excluded.fingerprint,
                    rule_id=excluded.rule_id,
                    title=excluded.title,
                    severity=excluded.severity,
                    status=excluded.status,
                    confidence=excluded.confidence,
                    file=excluded.file,
                    line=excluded.line,
                    payload=excluded.payload,
                    updated_at=excluded.updated_at
                """,
                row,
            )
        return self.get_finding(finding_id)  # type: ignore[return-value]

    def get_finding(self, finding_id: str) -> dict[str, Any] | None:
        row = self._fetchone("SELECT * FROM findings WHERE id = ?", (finding_id,))
        return self._finding_from_row(row) if row else None

    def list_findings(
        self,
        *,
        project_id: str | None = None,
        scan_id: str | None = None,
        severity: str | None = None,
        limit: int = 50,
        cursor: str | None = None,
    ) -> dict[str, Any]:
        limit = max(1, min(int(limit), 500))
        clauses: list[str] = []
        params: list[Any] = []
        if project_id:
            clauses.append("project_id = ?")
            params.append(project_id)
        if scan_id:
            clauses.append("scan_id = ?")
            params.append(scan_id)
        if severity:
            clauses.append("severity = ?")
            params.append(severity.lower())
        decoded = decode_cursor(cursor)
        if decoded:
            clauses.append("((created_at < ?) OR (created_at = ? AND id < ?))")
            params.extend([decoded[0], decoded[0], decoded[1]])
        where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
        params.append(limit + 1)
        rows = self._fetchall(
            f"SELECT * FROM findings {where} ORDER BY created_at DESC, id DESC LIMIT ?",
            tuple(params),
        )
        items = [self._finding_from_row(r) for r in rows[:limit]]
        has_more = len(rows) > limit
        next_cursor = None
        if has_more and items:
            last = items[-1]
            next_cursor = encode_cursor(float(last["created_at"]), last["id"])
        return {"data": items, "next_cursor": next_cursor, "has_more": has_more}

    def _finding_from_row(self, row: sqlite3.Row) -> dict[str, Any]:
        d = dict(row)
        payload = _json_loads(d.pop("payload", None), {}) or {}
        # Prefer stored payload shape; keep index columns as fallbacks.
        out = dict(payload)
        for k in (
            "id",
            "project_id",
            "scan_id",
            "fingerprint",
            "rule_id",
            "title",
            "severity",
            "status",
            "confidence",
            "file",
            "line",
            "created_at",
            "updated_at",
        ):
            if d.get(k) is not None:
                out.setdefault(k, d[k])
                out[k] = d[k] if k in d else out.get(k)
                out[k] = d[k]
        return out

    # --- api keys ---------------------------------------------------------

    def insert_api_key(self, record: dict[str, Any]) -> dict[str, Any]:
        with self._lock:
            self._conn.execute(
                """
                INSERT INTO api_keys (
                    id, name, prefix, salt, key_hash, scopes,
                    created_at, expires_at, revoked_at, last_used_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    record["id"],
                    record["name"],
                    record.get("prefix"),
                    record["salt"],
                    record["key_hash"],
                    _json_dumps(record.get("scopes") or ["*"]),
                    record.get("created_at", time.time()),
                    record.get("expires_at"),
                    record.get("revoked_at"),
                    record.get("last_used_at"),
                ),
            )
        return self.get_api_key(record["id"])  # type: ignore[return-value]

    def get_api_key(self, key_id: str) -> dict[str, Any] | None:
        row = self._fetchone("SELECT * FROM api_keys WHERE id = ?", (key_id,))
        return self._key_from_row(row) if row else None

    def list_api_keys(
        self,
        *,
        limit: int = 50,
        cursor: str | None = None,
    ) -> dict[str, Any]:
        limit = max(1, min(int(limit), 200))
        rows = self._fetchall("SELECT * FROM api_keys ORDER BY created_at DESC")
        items = [self._key_public(self._key_from_row(r)) for r in rows]
        # simple slice pagination (keys are few)
        decoded = decode_cursor(cursor)
        if decoded:
            items = [i for i in items if (float(i.get("created_at") or 0), i["id"]) < (decoded[0], decoded[1])]
        page = items[:limit]
        has_more = len(items) > limit
        next_cursor = None
        if has_more and page:
            last = page[-1]
            next_cursor = encode_cursor(float(last.get("created_at") or 0), last["id"])
        return {"data": page, "next_cursor": next_cursor, "has_more": has_more}

    def find_api_key_by_raw(self, raw_key: str) -> dict[str, Any] | None:
        from engines.api.auth import key_is_usable, verify_api_key

        rows = self._fetchall("SELECT * FROM api_keys WHERE revoked_at IS NULL")
        for row in rows:
            rec = self._key_from_row(row)
            if not key_is_usable(rec):
                continue
            if verify_api_key(raw_key, rec["salt"], rec["key_hash"]):
                return rec
        return None

    def touch_api_key(self, key_id: str) -> None:
        self._execute(
            "UPDATE api_keys SET last_used_at = ? WHERE id = ?",
            (time.time(), key_id),
        )

    def revoke_api_key(self, key_id: str) -> dict[str, Any] | None:
        key = self.get_api_key(key_id)
        if not key:
            return None
        self._execute(
            "UPDATE api_keys SET revoked_at = ? WHERE id = ?",
            (time.time(), key_id),
        )
        return self.get_api_key(key_id)

    def _key_from_row(self, row: sqlite3.Row) -> dict[str, Any]:
        d = dict(row)
        d["scopes"] = _json_loads(d.get("scopes"), ["*"])
        return d

    def _key_public(self, key: dict[str, Any]) -> dict[str, Any]:
        return {
            "id": key["id"],
            "name": key["name"],
            "prefix": key.get("prefix"),
            "scopes": key.get("scopes") or [],
            "created_at": key.get("created_at"),
            "expires_at": key.get("expires_at"),
            "revoked_at": key.get("revoked_at"),
            "last_used_at": key.get("last_used_at"),
        }

    # --- artifacts --------------------------------------------------------

    def put_artifact(self, data: dict[str, Any]) -> dict[str, Any]:
        art_id = data.get("id") or new_id("art")
        row = {
            "id": art_id,
            "project_id": data["project_id"],
            "scan_id": data.get("scan_id"),
            "kind": data["kind"],
            "path": data.get("path"),
            "payload": _json_dumps(data.get("payload"))
            if data.get("payload") is not None
            else None,
            "created_at": time.time(),
        }
        with self._lock:
            self._conn.execute(
                """
                INSERT INTO artifacts (id, project_id, scan_id, kind, path, payload, created_at)
                VALUES (:id, :project_id, :scan_id, :kind, :path, :payload, :created_at)
                """,
                row,
            )
        return self.get_artifact(art_id)  # type: ignore[return-value]

    def get_artifact(self, artifact_id: str) -> dict[str, Any] | None:
        row = self._fetchone("SELECT * FROM artifacts WHERE id = ?", (artifact_id,))
        if not row:
            return None
        d = dict(row)
        d["payload"] = _json_loads(d.get("payload"), None)
        return d

    def list_artifacts(
        self,
        *,
        project_id: str,
        kind: str | None = None,
        limit: int = 50,
        cursor: str | None = None,
    ) -> dict[str, Any]:
        limit = max(1, min(int(limit), 200))
        clauses = ["project_id = ?"]
        params: list[Any] = [project_id]
        if kind:
            clauses.append("kind = ?")
            params.append(kind)
        decoded = decode_cursor(cursor)
        if decoded:
            clauses.append("((created_at < ?) OR (created_at = ? AND id < ?))")
            params.extend([decoded[0], decoded[0], decoded[1]])
        where = " AND ".join(clauses)
        params.append(limit + 1)
        rows = self._fetchall(
            f"SELECT * FROM artifacts WHERE {where} ORDER BY created_at DESC, id DESC LIMIT ?",
            tuple(params),
        )
        out = []
        for row in rows[:limit]:
            d = dict(row)
            d["payload"] = _json_loads(d.get("payload"), None)
            out.append(d)
        has_more = len(rows) > limit
        next_cursor = None
        if has_more and out:
            last = out[-1]
            next_cursor = encode_cursor(float(last["created_at"]), last["id"])
        return {"data": out, "next_cursor": next_cursor, "has_more": has_more}


    def set_artifact(
        self,
        project_id: str,
        kind: str,
        payload: Any,
        *,
        scan_id: str | None = None,
        path: str | None = None,
    ) -> dict[str, Any]:
        """Store a JSON artifact payload keyed by project + kind (latest wins via list order)."""
        return self.put_artifact(
            {
                "project_id": project_id,
                "kind": kind,
                "payload": payload,
                "scan_id": scan_id,
                "path": path,
            }
        )

    def get_latest_artifact(self, project_id: str, kind: str) -> Any | None:
        arts = self.list_artifacts(project_id=project_id, kind=kind, limit=1)
        data = arts.get("data") if isinstance(arts, dict) else arts
        if not data:
            return None
        return data[0].get("payload")

    # --- webhooks ---------------------------------------------------------

    def create_webhook(self, data: dict[str, Any]) -> dict[str, Any]:
        wh_id = data.get("id") or new_id("wh")
        now = time.time()
        row = {
            "id": wh_id,
            "project_id": data.get("project_id"),
            "url": data["url"],
            "secret": data.get("secret") or new_id("whsec"),
            "events": _json_dumps(data.get("events") or ["*"]),
            "enabled": 1 if data.get("enabled", True) else 0,
            "created_at": now,
            "updated_at": now,
        }
        with self._lock:
            self._conn.execute(
                """
                INSERT INTO webhooks (
                    id, project_id, url, secret, events, enabled, created_at, updated_at
                ) VALUES (
                    :id, :project_id, :url, :secret, :events, :enabled, :created_at, :updated_at
                )
                """,
                row,
            )
        return self.get_webhook(wh_id)  # type: ignore[return-value]

    def get_webhook(self, webhook_id: str) -> dict[str, Any] | None:
        row = self._fetchone("SELECT * FROM webhooks WHERE id = ?", (webhook_id,))
        return self._webhook_from_row(row) if row else None

    def list_webhooks(
        self,
        *,
        project_id: str | None = None,
        limit: int = 50,
        cursor: str | None = None,
    ) -> dict[str, Any]:
        limit = max(1, min(int(limit), 200))
        if project_id:
            rows = self._fetchall(
                "SELECT * FROM webhooks WHERE project_id = ? ORDER BY created_at DESC",
                (project_id,),
            )
        else:
            rows = self._fetchall("SELECT * FROM webhooks ORDER BY created_at DESC")
        items = [self._webhook_from_row(r) for r in rows]
        decoded = decode_cursor(cursor)
        if decoded:
            items = [
                i
                for i in items
                if (float(i.get("created_at") or 0), i["id"]) < (decoded[0], decoded[1])
            ]
        page = items[:limit]
        has_more = len(items) > limit
        next_cursor = None
        if has_more and page:
            last = page[-1]
            next_cursor = encode_cursor(float(last.get("created_at") or 0), last["id"])
        return {"data": page, "next_cursor": next_cursor, "has_more": has_more}

    def _webhook_from_row(self, row: sqlite3.Row) -> dict[str, Any]:
        d = dict(row)
        d["events"] = _json_loads(d.get("events"), ["*"])
        d["enabled"] = bool(d.get("enabled"))
        return d
