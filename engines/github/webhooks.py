"""Webhook signature verification, replay protection, and event parsing."""

from __future__ import annotations

import hashlib
import hmac
import json
import time
from collections import OrderedDict
from typing import Any

from engines.github.models import PullRequestRef, RepoRef, WebhookDelivery
from engines.github.untrusted import sanitize_untrusted_text


class SignatureError(ValueError):
    """Invalid or missing webhook signature."""


class ReplayError(ValueError):
    """Duplicate or stale webhook delivery."""


def verify_signature(
    body: bytes,
    signature_header: str | None,
    secret: str,
) -> None:
    """Verify ``X-Hub-Signature-256`` (HMAC-SHA256).

    Raises SignatureError on mismatch / missing header.
    """
    if not secret:
        raise SignatureError("webhook secret not configured")
    if not signature_header:
        raise SignatureError("missing X-Hub-Signature-256")
    try:
        algo, dig = signature_header.split("=", 1)
    except ValueError as exc:
        raise SignatureError("malformed X-Hub-Signature-256") from exc
    if algo != "sha256":
        raise SignatureError(f"unsupported signature algorithm: {algo}")
    expected = hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, dig.strip()):
        raise SignatureError("webhook signature mismatch")


class ReplayCache:
    """In-memory delivery-id cache with TTL (default 10 minutes)."""

    def __init__(self, *, ttl_seconds: float = 600, max_entries: int = 10_000) -> None:
        self.ttl = ttl_seconds
        self.max_entries = max_entries
        self._seen: OrderedDict[str, float] = OrderedDict()

    def _purge(self, now: float) -> None:
        while self._seen:
            key, ts = next(iter(self._seen.items()))
            if now - ts <= self.ttl and len(self._seen) <= self.max_entries:
                break
            if now - ts > self.ttl:
                self._seen.popitem(last=False)
                continue
            # over capacity — drop oldest
            self._seen.popitem(last=False)

    def check_and_record(self, delivery_id: str, *, now: float | None = None) -> None:
        if not delivery_id:
            raise ReplayError("missing X-GitHub-Delivery")
        t = now if now is not None else time.time()
        self._purge(t)
        if delivery_id in self._seen:
            raise ReplayError(f"replayed delivery: {delivery_id}")
        self._seen[delivery_id] = t
        self._seen.move_to_end(delivery_id)


def _repo_from_payload(payload: dict[str, Any], installation_id: int | None) -> RepoRef | None:
    repo = payload.get("repository") or {}
    if not repo:
        return None
    full = str(repo.get("full_name") or "")
    owner = ""
    name = ""
    if "/" in full:
        owner, name = full.split("/", 1)
    else:
        owner = str((repo.get("owner") or {}).get("login") or "")
        name = str(repo.get("name") or "")
    return RepoRef(
        owner=owner,
        name=name,
        full_name=full or f"{owner}/{name}",
        installation_id=installation_id,
        private=bool(repo.get("private")),
        default_branch=str(repo.get("default_branch") or "") or None,
    )


def _pr_from_payload(payload: dict[str, Any]) -> PullRequestRef | None:
    pr = payload.get("pull_request") or {}
    if not pr:
        return None
    base = pr.get("base") or {}
    head = pr.get("head") or {}
    return PullRequestRef(
        number=int(pr.get("number") or 0),
        base_sha=str(base.get("sha") or ""),
        head_sha=str(head.get("sha") or ""),
        base_ref=str(base.get("ref") or ""),
        head_ref=str(head.get("ref") or ""),
        title=sanitize_untrusted_text(str(pr.get("title") or ""), max_len=500),
        html_url=str(pr.get("html_url") or ""),
        draft=bool(pr.get("draft")),
    )


def parse_delivery(
    *,
    event: str,
    delivery_id: str,
    body: bytes | str,
    received_at: float | None = None,
) -> WebhookDelivery:
    if isinstance(body, bytes):
        payload = json.loads(body.decode("utf-8") or "{}")
    else:
        payload = json.loads(body or "{}")
    if not isinstance(payload, dict):
        raise ValueError("webhook payload must be a JSON object")
    installation = payload.get("installation") or {}
    installation_id = installation.get("id")
    if installation_id is not None:
        installation_id = int(installation_id)
    action = payload.get("action")
    return WebhookDelivery(
        event=str(event or ""),
        action=str(action) if action is not None else None,
        delivery_id=str(delivery_id or ""),
        installation_id=installation_id,
        repository=_repo_from_payload(payload, installation_id),
        pull_request=_pr_from_payload(payload),
        payload=payload,
        received_at=received_at if received_at is not None else time.time(),
    )


def verify_and_parse(
    *,
    body: bytes,
    signature_header: str | None,
    secret: str,
    event: str,
    delivery_id: str,
    replay_cache: ReplayCache | None = None,
    received_at: float | None = None,
) -> WebhookDelivery:
    """Verify signature, enforce replay protection, parse delivery."""
    verify_signature(body, signature_header, secret)
    cache = replay_cache or ReplayCache()
    cache.check_and_record(delivery_id, now=received_at)
    return parse_delivery(
        event=event,
        delivery_id=delivery_id,
        body=body,
        received_at=received_at,
    )


# Events the bot cares about
SUPPORTED_EVENTS = frozenset(
    {
        "pull_request",
        "check_run",
        "installation",
        "installation_repositories",
        "push",
        "release",
        "ping",
    }
)

PR_REVIEW_ACTIONS = frozenset({"opened", "synchronize", "reopened"})
PR_OPTIONAL_ACTIONS = frozenset({"closed", "ready_for_review", "edited"})
