"""EvidenceStore — dedupe, reuse across findings, and freshness tracking.

Evidence is deduplicated by ``(type, file, line, symbol, description)``. When the
same logical evidence is added again with a *different* ``content_hash`` (for
example a snippet changed because the source moved), the stored item is treated
as **stale** and refreshed in place while keeping its stable id; callers can see
that a stale replacement happened via :meth:`is_stale` / the item ``revision``.
"""

from __future__ import annotations

import hashlib
from typing import Any, Iterable

from engines.evidence.schema import (
    QUALITY_RANK,
    UNKNOWN_LOCATION,
    compute_content_hash,
    dedupe_key,
)


def _stable_id(key: tuple[str, str, int, str, str]) -> str:
    raw = "|".join(str(part) for part in key)
    digest = hashlib.sha1(raw.encode("utf-8")).hexdigest()[:10]
    return f"ev.{digest}"


class EvidenceStore:
    """Content-addressed store of evidence items shared across findings."""

    def __init__(self) -> None:
        self._items: dict[str, dict[str, Any]] = {}
        self._key_to_id: dict[tuple[str, str, int, str, str], str] = {}
        self._reuse: dict[str, int] = {}
        self._stale_ids: set[str] = set()

    # -- mutation --------------------------------------------------------
    def add(self, item: dict[str, Any]) -> str:
        """Add or reuse an evidence item; returns its stable id.

        * New key → stored, ``reuse_count`` starts at 1.
        * Same key + same ``content_hash`` → reused (``reuse_count`` bumped).
        * Same key + different ``content_hash`` → **stale**; content refreshed in
          place, ``revision`` bumped, and the id recorded in the stale set.
        """
        key = dedupe_key(item)
        content_hash = item.get("content_hash") or self._recompute_hash(item)

        existing_id = self._key_to_id.get(key)
        if existing_id is None:
            new_id = _stable_id(key)
            stored = dict(item)
            stored["id"] = new_id
            stored["content_hash"] = content_hash
            stored["revision"] = 1
            stored["reuse_count"] = 1
            self._items[new_id] = stored
            self._key_to_id[key] = new_id
            self._reuse[new_id] = 1
            return new_id

        stored = self._items[existing_id]
        if stored.get("content_hash") == content_hash:
            self._reuse[existing_id] = self._reuse.get(existing_id, 1) + 1
            stored["reuse_count"] = self._reuse[existing_id]
            # keep the strongest quality/confidence seen for a shared item
            self._merge_strength(stored, item)
            return existing_id

        # content changed for the same logical location → stale refresh
        prev_hash = stored.get("content_hash")
        stored.update(
            {
                k: v
                for k, v in item.items()
                if k not in {"id", "reuse_count", "revision"}
            }
        )
        stored["id"] = existing_id
        stored["content_hash"] = content_hash
        stored["revision"] = int(stored.get("revision", 1)) + 1
        stored["stale_replaced"] = True
        stored["previous_content_hash"] = prev_hash
        self._reuse[existing_id] = self._reuse.get(existing_id, 1) + 1
        stored["reuse_count"] = self._reuse[existing_id]
        self._stale_ids.add(existing_id)
        return existing_id

    def add_many(self, items: Iterable[dict[str, Any]]) -> list[str]:
        return [self.add(item) for item in items]

    # -- queries ---------------------------------------------------------
    def get(self, evidence_id: str) -> dict[str, Any] | None:
        return self._items.get(evidence_id)

    def all(self) -> list[dict[str, Any]]:
        return list(self._items.values())

    def ids(self) -> list[str]:
        return list(self._items.keys())

    def reuse_count(self, evidence_id: str) -> int:
        return self._reuse.get(evidence_id, 0)

    def is_stale(self, evidence_id: str) -> bool:
        return evidence_id in self._stale_ids

    def stale_ids(self) -> list[str]:
        return sorted(self._stale_ids)

    def is_fresh(self, item: dict[str, Any]) -> bool:
        """True when ``item`` matches the stored content hash for its key."""
        key = dedupe_key(item)
        existing_id = self._key_to_id.get(key)
        if existing_id is None:
            return False
        stored = self._items[existing_id]
        return stored.get("content_hash") == (
            item.get("content_hash") or self._recompute_hash(item)
        )

    def reused_count(self) -> int:
        """Total number of items that were shared by more than one finding."""
        return sum(1 for c in self._reuse.values() if c > 1)

    def to_dict(self) -> dict[str, dict[str, Any]]:
        return {eid: dict(item) for eid, item in self._items.items()}

    # -- internals -------------------------------------------------------
    @staticmethod
    def _recompute_hash(item: dict[str, Any]) -> str:
        file = item.get("file")
        return compute_content_hash(
            type=str(item.get("type") or ""),
            file=None if file in {None, UNKNOWN_LOCATION} else str(file),
            line_start=item.get("line_start"),
            line_end=item.get("line_end"),
            symbol=item.get("symbol"),
            description=str(item.get("description") or ""),
            snippet=item.get("snippet"),
        )

    @staticmethod
    def _merge_strength(stored: dict[str, Any], incoming: dict[str, Any]) -> None:
        """Keep the strongest quality when the same evidence is re-added."""
        s_q = QUALITY_RANK.get(str(stored.get("quality")), 0)
        i_q = QUALITY_RANK.get(str(incoming.get("quality")), 0)
        if i_q > s_q:
            stored["quality"] = incoming.get("quality")
