"""Search modes — status filters over live attack paths (Phase 6 Part 2).

A *mode* is an explicit, opt-in view of the enumerated paths:

* ``CONFIRMED_ONLY``       — only ``CONFIRMED`` paths (highest signal).
* ``CONFIRMED_AND_LIKELY`` — ``CONFIRMED`` + ``LIKELY`` (the credible set).
* ``INCLUDE_UNKNOWN``      — also ``UNVERIFIED`` (surface-for-review set).

Modes never change the underlying ``paths[]`` artifact — they filter a copy for
display / querying. ``BLOCKED`` and ``INVALID`` paths are *never* live in any
mode: a blocked chain has an effective barrier and an invalid chain does not
exist, so both are treated as rejected regardless of mode.
"""

from __future__ import annotations

from typing import Any

from engines.attack_graph.schema import (
    DEFAULT_SEARCH_MODE,
    MODE_ALLOWED_STATUSES,
    MODE_INCLUDE_UNKNOWN,
    REJECTED_STATUSES,
    SEARCH_MODES,
)


def normalize_mode(mode: str | None) -> str:
    """Return a valid mode, defaulting rather than raising on bad input."""
    if mode and str(mode) in SEARCH_MODES:
        return str(mode)
    return DEFAULT_SEARCH_MODE


def allowed_statuses(mode: str | None) -> frozenset[str]:
    return MODE_ALLOWED_STATUSES.get(normalize_mode(mode), MODE_ALLOWED_STATUSES[MODE_INCLUDE_UNKNOWN])


def path_in_mode(path: dict[str, Any], mode: str | None) -> bool:
    """True if a path is *live* under ``mode`` (and not a rejected status)."""
    status = str(path.get("status"))
    if status in REJECTED_STATUSES:
        return False
    return status in allowed_statuses(mode)


def filter_paths(paths: list[dict[str, Any]], mode: str | None) -> list[dict[str, Any]]:
    """Return the subset of ``paths`` that are live under ``mode`` (order kept)."""
    return [p for p in paths if path_in_mode(p, mode)]


def partition_paths(
    paths: list[dict[str, Any]], mode: str | None
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Split into ``(live, filtered_out)`` for a mode (order preserved)."""
    live: list[dict[str, Any]] = []
    out: list[dict[str, Any]] = []
    for p in paths:
        (live if path_in_mode(p, mode) else out).append(p)
    return live, out
