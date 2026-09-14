"""Lightweight dependency / SBOM graph (Phase 6 Part 2).

Builds dependency nodes and ``DEPENDS_ON`` / ``SUPPLIES`` edges from **manifest
files only** — ``requirements.txt``, ``pyproject.toml``, and ``package.json``.

**Hard constraints (honesty):**

- No network calls, no CVE database, no vulnerability scanning. This module
  never invents a CVE, advisory, or "known vulnerable" label.
- Reachability of a dependency into an attack path is ``unknown`` unless the
  caller supplies evidence — a manifest entry proves the dependency is declared,
  not that it is reached at runtime.
- Version constraints are recorded verbatim from the manifest (or ``unknown``).

The output is a small self-contained graph the foundation engine (or a report)
can merge as supply-chain context. It is redacted with the shared
``ensure_no_secret_values`` before return.
"""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from engines.dataflow.schema import ensure_no_secret_values

SBOM_VERSION = "1.0.0"

EDGE_DEPENDS_ON = "DEPENDS_ON"
EDGE_SUPPLIES = "SUPPLIES"

ECOSYSTEM_PYPI = "pypi"
ECOSYSTEM_NPM = "npm"


def _slug(text: str) -> str:
    return re.sub(r"[^a-zA-Z0-9]+", "_", str(text or "")).strip("_").lower()


def dependency_id(ecosystem: str, name: str) -> str:
    return f"dependency:{_slug(ecosystem)}:{_slug(name)}"


# ---------------------------------------------------------------------------
# manifest parsers (declared dependencies only; no resolution, no lockfiles)
# ---------------------------------------------------------------------------
_REQ_LINE = re.compile(
    r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*(\[[^\]]*\])?\s*"
    r"(==|>=|<=|~=|!=|<|>|===)?\s*([A-Za-z0-9._*+!-]+)?"
)


def parse_requirements_txt(text: str) -> list[dict[str, Any]]:
    deps: list[dict[str, Any]] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue  # skip blanks, comments, pip flags (-r, -e, --hash)
        # strip inline comments and environment markers
        line = line.split(";", 1)[0].split("#", 1)[0].strip()
        if not line:
            continue
        m = _REQ_LINE.match(line)
        if not m:
            continue
        name = m.group(1)
        op = m.group(3) or ""
        ver = m.group(4) or ""
        version = f"{op}{ver}" if ver else "unknown"
        deps.append({"name": name, "version": version, "ecosystem": ECOSYSTEM_PYPI})
    return deps


def _parse_pyproject_deps_regex(text: str) -> list[dict[str, Any]]:
    """Fallback pyproject parser (used when tomllib is unavailable)."""
    deps: list[dict[str, Any]] = []
    # [project] dependencies = ["a==1", "b>=2", ...]
    m = re.search(r"dependencies\s*=\s*\[(.*?)\]", text, re.DOTALL)
    blocks = [m.group(1)] if m else []
    # Also scan any array assignment that looks like a dependency list
    # (covers optional-dependencies groups without a full TOML parse).
    for arr in re.finditer(r"=\s*\[([^\]]*?)\]", text):
        chunk = arr.group(1)
        if "==" in chunk or ">=" in chunk or '"' in chunk or "'" in chunk:
            blocks.append(chunk)
    seen = set()
    for block in blocks:
        for item in re.findall(r"['\"]([^'\"]+)['\"]", block):
            for d in parse_requirements_txt(item):
                key = (d["ecosystem"], d["name"])
                if key not in seen:
                    seen.add(key)
                    deps.append(d)
    return deps


def parse_pyproject_toml(text: str) -> list[dict[str, Any]]:
    try:
        import tomllib  # Python 3.11+

        data = tomllib.loads(text)
    except Exception:
        return _parse_pyproject_deps_regex(text)

    deps: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()

    def _add(specifiers: list[Any]) -> None:
        for spec in specifiers or []:
            if not isinstance(spec, str):
                continue
            for d in parse_requirements_txt(spec):
                key = (d["ecosystem"], d["name"])
                if key not in seen:
                    seen.add(key)
                    deps.append(d)

    project = data.get("project") or {}
    _add(project.get("dependencies") or [])
    for group in (project.get("optional-dependencies") or {}).values():
        _add(group if isinstance(group, list) else [])
    # PEP 621 build-system requires + poetry-style are intentionally skipped to
    # avoid over-claiming; declared runtime deps are the honest signal.
    return deps


def parse_package_json(text: str) -> list[dict[str, Any]]:
    try:
        data = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        return []
    deps: list[dict[str, Any]] = []
    for field in ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies"):
        block = data.get(field)
        if isinstance(block, dict):
            for name, ver in block.items():
                deps.append(
                    {
                        "name": str(name),
                        "version": str(ver) if ver else "unknown",
                        "ecosystem": ECOSYSTEM_NPM,
                        "manifest_field": field,
                    }
                )
    return deps


_MANIFEST_PARSERS = {
    "requirements.txt": parse_requirements_txt,
    "pyproject.toml": parse_pyproject_toml,
    "package.json": parse_package_json,
}


# ---------------------------------------------------------------------------
# graph builder
# ---------------------------------------------------------------------------
def build_sbom(target: Path | str) -> dict[str, Any]:
    """Scan ``target`` for supported manifests and build a dependency graph.

    Only files named exactly ``requirements.txt`` / ``pyproject.toml`` /
    ``package.json`` at the target root (and one level down) are read. No
    network access, no CVE lookup.
    """
    root = Path(target)
    project_name = root.resolve().name or "project"
    project_node_id = f"project:{_slug(project_name)}"

    nodes: list[dict[str, Any]] = [
        {
            "id": project_node_id,
            "type": "project",
            "label": project_name,
            "root": str(root.resolve()),
        }
    ]
    edges: list[dict[str, Any]] = []
    dependencies: list[dict[str, Any]] = []
    manifests_seen: list[str] = []
    seen_dep_ids: set[str] = set()

    for manifest_name, parser in _MANIFEST_PARSERS.items():
        for manifest_path in _find_manifests(root, manifest_name):
            try:
                text = manifest_path.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            rel = _rel(manifest_path, root)
            manifests_seen.append(rel)
            for dep in parser(text):
                eco = dep.get("ecosystem", ECOSYSTEM_PYPI)
                name = dep.get("name")
                if not name:
                    continue
                dep_id = dependency_id(eco, name)
                dep_record = {
                    "id": dep_id,
                    "name": name,
                    "version": dep.get("version", "unknown"),
                    "ecosystem": eco,
                    "manifest": rel,
                    # A declared dependency is NOT proven reachable at runtime.
                    "reachability": "unknown",
                }
                if dep.get("manifest_field"):
                    dep_record["manifest_field"] = dep["manifest_field"]
                if dep_id not in seen_dep_ids:
                    seen_dep_ids.add(dep_id)
                    dependencies.append(dep_record)
                    nodes.append(
                        {
                            "id": dep_id,
                            "type": "dependency",
                            "label": f"{name} {dep_record['version']}",
                            "ecosystem": eco,
                            "version": dep_record["version"],
                            "reachability": "unknown",
                            "evidence": [
                                {
                                    "type": "MANIFEST",
                                    "description": f"declared in {rel}",
                                    "file": rel,
                                }
                            ],
                        }
                    )
                    edges.append(
                        {
                            "type": EDGE_DEPENDS_ON,
                            "from": project_node_id,
                            "to": dep_id,
                            "evidence": [{"type": "MANIFEST", "file": rel}],
                            "reachability": "unknown",
                        }
                    )
                    edges.append(
                        {
                            "type": EDGE_SUPPLIES,
                            "from": dep_id,
                            "to": project_node_id,
                            "evidence": [{"type": "MANIFEST", "file": rel}],
                            "reachability": "unknown",
                        }
                    )

    result = {
        "schema_version": SBOM_VERSION,
        "tool": "axguard",
        "kind": "sbom",
        "target": str(root.resolve()),
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "manifests": sorted(set(manifests_seen)),
        "nodes": nodes,
        "edges": edges,
        "dependencies": dependencies,
        "summary": {
            "manifest_count": len(set(manifests_seen)),
            "dependency_count": len(dependencies),
            "by_ecosystem": _by_ecosystem(dependencies),
        },
        "notes": (
            "Declared dependencies only. No CVE lookup, no network access, no "
            "reachability claim — a manifest entry proves declaration, not use."
        ),
    }
    ensure_no_secret_values(result)
    return result


def _find_manifests(root: Path, name: str) -> list[Path]:
    found: list[Path] = []
    top = root / name
    if top.is_file():
        found.append(top)
    # one level down (monorepo packages), skip virtualenvs / node_modules / vcs
    if root.is_dir():
        for child in sorted(root.iterdir()):
            if not child.is_dir():
                continue
            if child.name in {".git", "node_modules", ".venv", "venv", "__pycache__", "dist", "build"}:
                continue
            candidate = child / name
            if candidate.is_file():
                found.append(candidate)
    return found


def _rel(path: Path, root: Path) -> str:
    try:
        return str(path.resolve().relative_to(root.resolve()))
    except ValueError:
        return path.name


def _by_ecosystem(deps: list[dict[str, Any]]) -> dict[str, int]:
    out: dict[str, int] = {}
    for d in deps:
        eco = str(d.get("ecosystem") or "unknown")
        out[eco] = out.get(eco, 0) + 1
    return out
