"""PR / compare diff helpers — base/head SHAs and changed files."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from engines.github.client import GitHubClient
from engines.github.models import PullRequestRef, RepoRef


@dataclass
class DiffContext:
    base_sha: str
    head_sha: str
    changed_files: list[str] = field(default_factory=list)
    file_details: list[dict[str, Any]] = field(default_factory=list)
    truncated: bool = False


def extract_pr_diff(
    client: GitHubClient,
    repo: RepoRef,
    pr: PullRequestRef,
    *,
    token: str,
    max_files: int = 200,
) -> DiffContext:
    """Fetch changed files for a pull request (diff-first)."""
    files: list[dict[str, Any]] = []
    page = 1
    while True:
        chunk = client.get_json(
            f"/repos/{repo.slug}/pulls/{pr.number}/files?per_page=100&page={page}",
            token=token,
        )
        if not chunk:
            break
        if not isinstance(chunk, list):
            break
        files.extend(chunk)
        if len(chunk) < 100 or len(files) >= max_files:
            break
        page += 1

    truncated = len(files) > max_files
    files = files[:max_files]
    names = [str(f.get("filename") or "") for f in files if f.get("filename")]
    return DiffContext(
        base_sha=pr.base_sha,
        head_sha=pr.head_sha,
        changed_files=names,
        file_details=files,
        truncated=truncated,
    )


def changed_files_from_compare(
    client: GitHubClient,
    repo: RepoRef,
    base_sha: str,
    head_sha: str,
    *,
    token: str,
    max_files: int = 200,
) -> DiffContext:
    """Compare two commits/refs via the GitHub compare API."""
    path = f"/repos/{repo.slug}/compare/{base_sha}...{head_sha}"
    data = client.get_json(path, token=token) or {}
    if not isinstance(data, dict):
        data = {}
    files = list(data.get("files") or [])
    truncated = bool(data.get("truncated")) or len(files) > max_files
    files = files[:max_files]
    names = [str(f.get("filename") or "") for f in files if f.get("filename")]
    head_out = head_sha
    commits = data.get("commits") or []
    if commits and isinstance(commits, list):
        head_out = str((commits[-1] or {}).get("sha") or head_sha)
    return DiffContext(
        base_sha=str((data.get("base_commit") or {}).get("sha") or base_sha),
        head_sha=head_out,
        changed_files=names,
        file_details=files,
        truncated=truncated,
    )


def filter_analysis_targets(
    changed_files: list[str],
    *,
    max_files: int = 200,
) -> list[str]:
    """Prefer source-like paths; skip obvious binaries and lockfile noise."""
    skip_suffix = (
        ".png",
        ".jpg",
        ".jpeg",
        ".gif",
        ".webp",
        ".ico",
        ".pdf",
        ".zip",
        ".gz",
        ".tar",
        ".woff",
        ".woff2",
        ".lock",
    )
    skip_names = {"package-lock.json", "yarn.lock", "pnpm-lock.yaml", "poetry.lock"}
    out: list[str] = []
    for name in changed_files:
        base = name.rsplit("/", 1)[-1]
        if base in skip_names:
            continue
        if any(name.lower().endswith(s) for s in skip_suffix):
            continue
        out.append(name)
        if len(out) >= max_files:
            break
    return out
