"""Installation / installation_repositories event handling."""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any

from engines.github.models import RepoRef, WebhookDelivery
from engines.github.permissions import validate_granted


@dataclass
class InstallationRecord:
    installation_id: int
    account_login: str = ""
    account_type: str = ""
    repository_selection: str = ""
    repos: list[str] = field(default_factory=list)
    suspended: bool = False
    updated_at: float = 0.0


class InstallationStore:
    """In-memory installation registry (no source code, no tokens)."""

    def __init__(self) -> None:
        self._by_id: dict[int, InstallationRecord] = {}

    def get(self, installation_id: int) -> InstallationRecord | None:
        return self._by_id.get(installation_id)

    def list_installations(self) -> list[InstallationRecord]:
        return list(self._by_id.values())

    def authorize_repo(self, installation_id: int, full_name: str) -> bool:
        rec = self._by_id.get(installation_id)
        if rec is None or rec.suspended:
            return False
        if rec.repository_selection == "all":
            return True
        return full_name in rec.repos

    def upsert(self, record: InstallationRecord) -> None:
        self._by_id[record.installation_id] = record

    def remove(self, installation_id: int) -> None:
        self._by_id.pop(installation_id, None)


def handle_installation_event(
    delivery: WebhookDelivery,
    store: InstallationStore,
) -> dict[str, Any]:
    """Process ``installation`` / ``installation_repositories`` events."""
    event = delivery.event
    action = delivery.action or ""
    payload = delivery.payload
    installation = payload.get("installation") or {}
    installation_id = int(installation.get("id") or delivery.installation_id or 0)
    if not installation_id:
        return {"ok": False, "error": "missing_installation_id"}

    account = installation.get("account") or {}
    now = time.time()

    if event == "installation":
        if action == "deleted":
            store.remove(installation_id)
            return {"ok": True, "action": action, "installation_id": installation_id}
        if action == "suspend":
            existing = store.get(installation_id)
            if existing:
                existing.suspended = True
                existing.updated_at = now
            else:
                store.upsert(
                    InstallationRecord(
                        installation_id=installation_id,
                        account_login=str(account.get("login") or ""),
                        account_type=str(account.get("type") or ""),
                        repository_selection=str(
                            installation.get("repository_selection") or ""
                        ),
                        suspended=True,
                        updated_at=now,
                    )
                )
            return {"ok": True, "action": action, "installation_id": installation_id}
        if action == "unsuspend":
            existing = store.get(installation_id)
            if existing:
                existing.suspended = False
                existing.updated_at = now
            return {"ok": True, "action": action, "installation_id": installation_id}

        repos = []
        for r in payload.get("repositories") or []:
            full = r.get("full_name") or f"{r.get('name')}"
            repos.append(str(full))
        rec = InstallationRecord(
            installation_id=installation_id,
            account_login=str(account.get("login") or ""),
            account_type=str(account.get("type") or ""),
            repository_selection=str(installation.get("repository_selection") or ""),
            repos=repos,
            suspended=False,
            updated_at=now,
        )
        store.upsert(rec)
        granted = {
            str(k): str(v) for k, v in (installation.get("permissions") or {}).items()
        }
        # Missing permissions payload is a problem — do not silently assume minimum
        problems = (
            validate_granted(granted) if granted else ["permissions_omitted"]
        )
        return {
            "ok": True,
            "action": action,
            "installation_id": installation_id,
            "repos": repos,
            "permission_problems": problems,
        }

    if event == "installation_repositories":
        rec = store.get(installation_id) or InstallationRecord(
            installation_id=installation_id,
            account_login=str(account.get("login") or ""),
            repository_selection=str(installation.get("repository_selection") or ""),
            updated_at=now,
        )
        added = [
            str(r.get("full_name") or r.get("name"))
            for r in (payload.get("repositories_added") or [])
        ]
        removed = [
            str(r.get("full_name") or r.get("name"))
            for r in (payload.get("repositories_removed") or [])
        ]
        repo_set = set(rec.repos)
        repo_set.update(added)
        repo_set.difference_update(removed)
        rec.repos = sorted(repo_set)
        rec.repository_selection = str(
            installation.get("repository_selection") or rec.repository_selection
        )
        rec.updated_at = now
        store.upsert(rec)
        return {
            "ok": True,
            "action": action,
            "installation_id": installation_id,
            "added": added,
            "removed": removed,
        }

    return {"ok": False, "error": "unsupported_event", "event": event}


def repo_ref_authorized(
    store: InstallationStore,
    repo: RepoRef | None,
    *,
    require_known: bool = False,
) -> bool:
    """Return True if the installation may analyze this repository.

    Warm-up (unknown installation id) is allowed only when the store has never
    seen any installation and ``require_known`` is False. After any install
    event is recorded, unknown ids are rejected so suspend/delete cannot be
    bypassed by a forged installation id.
    """
    if repo is None or repo.installation_id is None:
        return False
    rec = store.get(repo.installation_id)
    if rec is None:
        if require_known:
            return False
        if not store.list_installations():
            return True
        return False
    return store.authorize_repo(repo.installation_id, repo.slug)
