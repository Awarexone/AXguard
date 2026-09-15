"""Documented minimum GitHub App permissions for AXGuard."""

from __future__ import annotations

from typing import Any

# Permission → access level. Keep minimal; every key must appear in REASONS.
MINIMUM_PERMISSIONS: dict[str, str] = {
    "contents": "read",
    "metadata": "read",
    "pull_requests": "write",
    "checks": "write",
}

REASONS: dict[str, str] = {
    "contents": (
        "Read repository trees, blobs, and compare API to fetch changed files "
        "and SHAs for diff-first analysis. Never write to contents."
    ),
    "metadata": (
        "Required by GitHub Apps for repository identity and installation "
        "context (always granted; read-only)."
    ),
    "pull_requests": (
        "Read PR metadata and diffs; write a single updatable summary comment "
        "marked <!-- AXGUARD-SECURITY-REVIEW -->. No issue spam."
    ),
    "checks": (
        "Create/update the AXGuard Security Review check run and annotations "
        "for verified findings and meaningful regressions."
    ),
}

# Explicitly not requested (document why)
REJECTED_PERMISSIONS: dict[str, str] = {
    "actions": "Not required; AXGuard does not manage workflows.",
    "administration": "Too broad; never needed for review.",
    "commit_statuses": "Prefer Checks API over legacy commit statuses.",
    "deployments": "No deploy integration in this adapter.",
    "issues": "PR comments use pull_requests; avoid separate issues scope.",
    "secrets": "Never read repository Actions secrets.",
    "workflows": "Never modify workflow files.",
    "members": "Org membership not required.",
}


def permission_reasons() -> dict[str, str]:
    """Return documented reasons for each minimum permission."""
    return dict(REASONS)


def as_manifest_permissions() -> dict[str, Any]:
    """Shape suitable for GitHub App manifest / setup docs."""
    return {
        "permissions": dict(MINIMUM_PERMISSIONS),
        "reasons": dict(REASONS),
        "rejected": dict(REJECTED_PERMISSIONS),
    }


def validate_granted(granted: dict[str, str]) -> list[str]:
    """Return list of problems if granted permissions are insufficient or over-broad.

    ``granted`` maps permission name → access (read/write/none).
    """
    problems: list[str] = []
    for name, need in MINIMUM_PERMISSIONS.items():
        have = (granted.get(name) or "none").lower()
        if have == "none":
            problems.append(f"missing:{name}")
            continue
        if need == "write" and have not in ("write", "admin"):
            problems.append(f"insufficient:{name} (need write, have {have})")
        if need == "read" and have not in ("read", "write", "admin"):
            problems.append(f"insufficient:{name} (need read, have {have})")
    for name in granted:
        if name in REJECTED_PERMISSIONS and (granted.get(name) or "none") != "none":
            problems.append(f"overbroad:{name}")
    return problems
