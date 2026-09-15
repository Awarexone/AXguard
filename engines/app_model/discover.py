"""Deterministic stack / ecosystem discovery from manifests and file patterns."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Iterator

from engines.source_scan import SKIP_DIRS, TEXT_NAMES, TEXT_SUFFIXES

from engines.app_model.schema import (
    CONFIDENCE_CONFIRMED,
    CONFIDENCE_LIKELY,
    evidence,
)

# Manifest filenames → package manager / ecosystem hints
_MANIFESTS: dict[str, dict[str, Any]] = {
    "package.json": {
        "package_manager": "npm",
        "runtime": "node",
        "language": "javascript",
    },
    "package-lock.json": {"package_manager": "npm"},
    "yarn.lock": {"package_manager": "yarn"},
    "pnpm-lock.yaml": {"package_manager": "pnpm"},
    "requirements.txt": {
        "package_manager": "pip",
        "runtime": "python",
        "language": "python",
    },
    "pyproject.toml": {
        "package_manager": "pip",
        "runtime": "python",
        "language": "python",
    },
    "Pipfile": {
        "package_manager": "pipenv",
        "runtime": "python",
        "language": "python",
    },
    "poetry.lock": {"package_manager": "poetry"},
    "go.mod": {"package_manager": "go", "runtime": "go", "language": "go"},
    "Gemfile": {
        "package_manager": "bundler",
        "runtime": "ruby",
        "language": "ruby",
    },
    "composer.json": {
        "package_manager": "composer",
        "runtime": "php",
        "language": "php",
    },
    "pom.xml": {
        "package_manager": "maven",
        "runtime": "jvm",
        "language": "java",
    },
    "build.gradle": {
        "package_manager": "gradle",
        "runtime": "jvm",
        "language": "java",
    },
    "build.gradle.kts": {
        "package_manager": "gradle",
        "runtime": "jvm",
        "language": "java",
    },
    "Cargo.toml": {
        "package_manager": "cargo",
        "runtime": "rust",
        "language": "rust",
    },
}

_FRAMEWORK_DEPS: dict[str, list[str]] = {
    "flask": ["flask"],
    "fastapi": ["fastapi"],
    "django": ["django"],
    "express": ["express"],
    "next": ["next"],
    "nuxt": ["nuxt"],
    "fastify": ["fastify"],
    "nestjs": ["@nestjs/core", "@nestjs/common"],
    "react": ["react"],
    "vue": ["vue"],
    "spring": ["spring-boot", "springframework"],
    "laravel": ["laravel/framework"],
    "symfony": ["symfony/"],
    "gin": ["github.com/gin-gonic/gin"],
    "echo": ["github.com/labstack/echo"],
    "fiber": ["github.com/gofiber/fiber"],
    "rails": ["rails"],
    "langchain": ["langchain", "@langchain/"],
}

_IMPORT_HINTS: list[tuple[str, re.Pattern[str], str]] = [
    ("flask", re.compile(r"^\s*(from\s+flask\s+import|import\s+flask)\b", re.M), "python"),
    ("fastapi", re.compile(r"^\s*(from\s+fastapi\s+import|import\s+fastapi)\b", re.M), "python"),
    ("django", re.compile(r"^\s*(from\s+django|import\s+django)\b", re.M), "python"),
    ("express", re.compile(r"""require\(['\"]express['\"]\)|from\s+['\"]express['\"]""", re.M), "javascript"),
    ("next", re.compile(r"""from\s+['\"]next(/|['\"])|require\(['\"]next['\"]\)""", re.M), "javascript"),
]


def iter_text_files(root: Path) -> Iterator[Path]:
    """Walk target using the same skip/suffix rules as source_scan."""
    if root.is_file():
        yield root
        return
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        suffix = path.suffix.lower()
        name = path.name.lower()
        if suffix not in TEXT_SUFFIXES and name not in TEXT_NAMES:
            continue
        yield path


def rel_path(path: Path, root: Path) -> str:
    try:
        return str(path.relative_to(root))
    except ValueError:
        return str(path)


def read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def discover_stack(root: Path, files: list[Path] | None = None) -> dict[str, Any]:
    """Detect languages, frameworks, runtimes, package managers from manifests + imports."""
    files = files if files is not None else list(iter_text_files(root))
    languages: dict[str, dict[str, Any]] = {}
    frameworks: dict[str, dict[str, Any]] = {}
    runtimes: dict[str, dict[str, Any]] = {}
    package_managers: dict[str, dict[str, Any]] = {}
    databases: dict[str, dict[str, Any]] = {}
    infrastructure: dict[str, dict[str, Any]] = {}
    cloud: dict[str, dict[str, Any]] = {}
    deployment: dict[str, dict[str, Any]] = {}
    app_name = root.name if root.is_dir() else root.stem

    by_name = {p.name.lower(): p for p in files}

    for fname, meta in _MANIFESTS.items():
        path = by_name.get(fname.lower())
        if path is None:
            # also accept nested (first match)
            matches = [p for p in files if p.name.lower() == fname.lower()]
            path = matches[0] if matches else None
        if path is None:
            continue
        rel = rel_path(path, root)
        conf = CONFIDENCE_CONFIRMED
        if "language" in meta:
            _add(
                languages,
                meta["language"],
                evidence(rel, 1, reason=f"manifest {fname}"),
                conf,
            )
        if "runtime" in meta:
            _add(
                runtimes,
                meta["runtime"],
                evidence(rel, 1, reason=f"manifest {fname}"),
                conf,
            )
        if "package_manager" in meta:
            _add(
                package_managers,
                meta["package_manager"],
                evidence(rel, 1, reason=f"manifest {fname}"),
                conf,
            )

        content = read_text(path)
        if fname == "package.json":
            app_name, fw = _parse_package_json(content, rel)
            for name, item in fw.items():
                frameworks[name] = item
            for db in _deps_databases(content):
                databases[db["name"]] = db
            for c in _deps_cloud(content):
                cloud[c["name"]] = c
        elif fname in {"requirements.txt", "Pipfile"}:
            for name, item in _parse_python_reqs(content, rel).items():
                frameworks.setdefault(name, item)
            for db in _python_db_hints(content, rel):
                databases[db["name"]] = db
        elif fname == "pyproject.toml":
            for name, item in _parse_pyproject(content, rel).items():
                frameworks.setdefault(name, item)
            parsed_name = _pyproject_name(content)
            if parsed_name:
                app_name = parsed_name
            for db in _python_db_hints(content, rel):
                databases[db["name"]] = db
        elif fname == "go.mod":
            for name, item in _parse_go_mod(content, rel).items():
                frameworks.setdefault(name, item)
        elif fname == "Gemfile":
            if re.search(r"\bgem\s+['\"]rails['\"]", content, re.I):
                frameworks["rails"] = {
                    "name": "rails",
                    "confidence": CONFIDENCE_CONFIRMED,
                    "evidence": evidence(rel, 1, reason="Gemfile rails"),
                }
        elif fname == "composer.json":
            for name, item in _parse_composer(content, rel).items():
                frameworks.setdefault(name, item)
        elif fname in {"pom.xml", "build.gradle", "build.gradle.kts"}:
            if re.search(r"spring", content, re.I):
                frameworks["spring"] = {
                    "name": "spring",
                    "confidence": CONFIDENCE_LIKELY,
                    "evidence": evidence(rel, 1, reason="spring reference in build file"),
                }

    # File-suffix language hints
    suffix_lang = {
        ".py": "python",
        ".js": "javascript",
        ".jsx": "javascript",
        ".ts": "typescript",
        ".tsx": "typescript",
        ".go": "go",
        ".rb": "ruby",
        ".php": "php",
        ".java": "java",
        ".rs": "rust",
    }
    for path in files:
        lang = suffix_lang.get(path.suffix.lower())
        if lang and lang not in languages:
            _add(
                languages,
                lang,
                evidence(rel_path(path, root), 1, reason="file extension"),
                CONFIDENCE_LIKELY,
            )

    # Import-based framework hints (only fill gaps)
    for path in files:
        if path.suffix.lower() not in {".py", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"}:
            continue
        content = read_text(path)
        if not content:
            continue
        rel = rel_path(path, root)
        for fw, pattern, _lang in _IMPORT_HINTS:
            if fw in frameworks:
                continue
            m = pattern.search(content)
            if m:
                line = content.count("\n", 0, m.start()) + 1
                frameworks[fw] = {
                    "name": fw,
                    "confidence": CONFIDENCE_LIKELY,
                    "evidence": evidence(rel, line, reason=f"import/require of {fw}"),
                }

    # Infra / deployment files
    for path in files:
        name = path.name.lower()
        rel = rel_path(path, root)
        if name == "dockerfile" or name.startswith("dockerfile."):
            _add(
                infrastructure,
                "docker",
                evidence(rel, 1, reason="Dockerfile present"),
                CONFIDENCE_CONFIRMED,
            )
            _add(
                deployment,
                "container",
                evidence(rel, 1, reason="Dockerfile present"),
                CONFIDENCE_LIKELY,
            )
        if name in {"docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml"}:
            _add(
                infrastructure,
                "docker-compose",
                evidence(rel, 1, reason="compose file"),
                CONFIDENCE_CONFIRMED,
            )
        if path.suffix.lower() in {".tf", ".hcl"}:
            _add(
                infrastructure,
                "terraform",
                evidence(rel, 1, reason="terraform file"),
                CONFIDENCE_CONFIRMED,
            )
        if ".github/workflows" in rel.replace("\\", "/"):
            _add(
                deployment,
                "github-actions",
                evidence(rel, 1, reason="GitHub Actions workflow"),
                CONFIDENCE_CONFIRMED,
            )

    return {
        "name": app_name or "unknown",
        "languages": list(languages.values()),
        "frameworks": list(frameworks.values()),
        "runtimes": list(runtimes.values()),
        "package_managers": list(package_managers.values()),
        "databases": list(databases.values()),
        "infrastructure": list(infrastructure.values()),
        "cloud": list(cloud.values()),
        "deployment": list(deployment.values()),
        "framework_names": sorted(frameworks.keys()),
    }


def _add(
    bucket: dict[str, dict[str, Any]],
    name: str,
    ev: dict[str, Any],
    confidence: str,
) -> None:
    if name in bucket:
        return
    bucket[name] = {"name": name, "confidence": confidence, "evidence": ev}


def _parse_package_json(content: str, rel: str) -> tuple[str, dict[str, dict[str, Any]]]:
    frameworks: dict[str, dict[str, Any]] = {}
    name = "unknown"
    try:
        data = json.loads(content)
    except json.JSONDecodeError:
        return name, frameworks
    if isinstance(data.get("name"), str) and data["name"]:
        name = data["name"]
    deps: dict[str, Any] = {}
    for key in ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies"):
        block = data.get(key) or {}
        if isinstance(block, dict):
            deps.update(block)
    dep_names = {str(k).lower(): str(k) for k in deps}
    for fw, needles in _FRAMEWORK_DEPS.items():
        for needle in needles:
            needle_l = needle.lower()
            hit = None
            for dk in dep_names:
                if dk == needle_l or dk.startswith(needle_l.rstrip("/")):
                    hit = dep_names[dk]
                    break
            if hit:
                frameworks[fw] = {
                    "name": fw,
                    "confidence": CONFIDENCE_CONFIRMED,
                    "evidence": evidence(rel, 1, symbol=hit, reason=f"package.json dependency {hit}"),
                }
                break
    return name, frameworks


def _deps_databases(package_json: str) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    mapping = {
        "pg": "postgresql",
        "postgres": "postgresql",
        "mysql": "mysql",
        "mysql2": "mysql",
        "mongodb": "mongodb",
        "mongoose": "mongodb",
        "redis": "redis",
        "ioredis": "redis",
        "sqlite3": "sqlite",
        "better-sqlite3": "sqlite",
    }
    try:
        data = json.loads(package_json)
    except json.JSONDecodeError:
        return out
    deps: dict[str, Any] = {}
    for key in ("dependencies", "devDependencies"):
        block = data.get(key) or {}
        if isinstance(block, dict):
            deps.update({str(k).lower(): k for k in block})
    for dep, db in mapping.items():
        if dep in deps:
            out.append(
                {
                    "name": db,
                    "confidence": CONFIDENCE_CONFIRMED,
                    "evidence": evidence(
                        "package.json",
                        1,
                        symbol=str(deps[dep]),
                        reason=f"dependency {deps[dep]}",
                    ),
                }
            )
    return out


def _deps_cloud(package_json: str) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    mapping = {
        "aws-sdk": "aws",
        "@aws-sdk/": "aws",
        "@google-cloud/": "gcp",
        "@azure/": "azure",
        "boto3": "aws",
    }
    try:
        data = json.loads(package_json)
    except json.JSONDecodeError:
        return out
    deps: dict[str, Any] = {}
    for key in ("dependencies", "devDependencies"):
        block = data.get(key) or {}
        if isinstance(block, dict):
            deps.update({str(k).lower(): k for k in block})
    seen: set[str] = set()
    for dep_l, orig in deps.items():
        for prefix, cloud_name in mapping.items():
            if dep_l == prefix.rstrip("/") or dep_l.startswith(prefix):
                if cloud_name not in seen:
                    seen.add(cloud_name)
                    out.append(
                        {
                            "name": cloud_name,
                            "confidence": CONFIDENCE_CONFIRMED,
                            "evidence": evidence(
                                "package.json",
                                1,
                                symbol=str(orig),
                                reason=f"dependency {orig}",
                            ),
                        }
                    )
    return out


def _parse_python_reqs(content: str, rel: str) -> dict[str, dict[str, Any]]:
    frameworks: dict[str, dict[str, Any]] = {}
    for i, line in enumerate(content.splitlines(), 1):
        raw = line.strip()
        if not raw or raw.startswith("#") or raw.startswith("-"):
            continue
        pkg = re.split(r"[<>=!~;\[]", raw, maxsplit=1)[0].strip().lower()
        for fw, needles in _FRAMEWORK_DEPS.items():
            if any(pkg == n.lower() or pkg.startswith(n.lower()) for n in needles if "/" not in n):
                frameworks[fw] = {
                    "name": fw,
                    "confidence": CONFIDENCE_CONFIRMED,
                    "evidence": evidence(rel, i, symbol=pkg, reason=f"requirement {pkg}"),
                }
    return frameworks


def _python_db_hints(content: str, rel: str) -> list[dict[str, Any]]:
    mapping = {
        "psycopg2": "postgresql",
        "psycopg": "postgresql",
        "asyncpg": "postgresql",
        "pymongo": "mongodb",
        "motor": "mongodb",
        "redis": "redis",
        "aioredis": "redis",
        "mysqlclient": "mysql",
        "pymysql": "mysql",
        "sqlite3": "sqlite",
        "sqlalchemy": "sqlalchemy",
    }
    out: list[dict[str, Any]] = []
    lower = content.lower()
    for pkg, db in mapping.items():
        if re.search(rf"(?m)^\s*{re.escape(pkg)}\b|{re.escape(pkg)}\s*[=<>]|[\"']{re.escape(pkg)}[\"']", lower):
            out.append(
                {
                    "name": db,
                    "confidence": CONFIDENCE_CONFIRMED,
                    "evidence": evidence(rel, 1, symbol=pkg, reason=f"dependency hint {pkg}"),
                }
            )
    return out


def _parse_pyproject(content: str, rel: str) -> dict[str, dict[str, Any]]:
    frameworks: dict[str, dict[str, Any]] = {}
    # crude dependency name extraction
    for fw, needles in _FRAMEWORK_DEPS.items():
        for needle in needles:
            if "/" in needle:
                continue
            if re.search(rf"[\"']{re.escape(needle)}[\"']|{re.escape(needle)}\s*[>=<]", content, re.I):
                frameworks[fw] = {
                    "name": fw,
                    "confidence": CONFIDENCE_CONFIRMED,
                    "evidence": evidence(rel, 1, symbol=needle, reason=f"pyproject dependency {needle}"),
                }
                break
    return frameworks


def _pyproject_name(content: str) -> str | None:
    m = re.search(r"(?m)^\s*name\s*=\s*[\"']([^\"']+)[\"']", content)
    return m.group(1) if m else None


def _parse_go_mod(content: str, rel: str) -> dict[str, dict[str, Any]]:
    frameworks: dict[str, dict[str, Any]] = {}
    for fw, needles in _FRAMEWORK_DEPS.items():
        for needle in needles:
            if "github.com" not in needle:
                continue
            if needle in content:
                frameworks[fw] = {
                    "name": fw,
                    "confidence": CONFIDENCE_CONFIRMED,
                    "evidence": evidence(rel, 1, symbol=needle, reason=f"go.mod require {needle}"),
                }
                break
    return frameworks


def _parse_composer(content: str, rel: str) -> dict[str, dict[str, Any]]:
    frameworks: dict[str, dict[str, Any]] = {}
    try:
        data = json.loads(content)
    except json.JSONDecodeError:
        return frameworks
    require = {}
    for key in ("require", "require-dev"):
        block = data.get(key) or {}
        if isinstance(block, dict):
            require.update(block)
    for fw, needles in _FRAMEWORK_DEPS.items():
        for needle in needles:
            for pkg in require:
                if needle.lower() in str(pkg).lower():
                    frameworks[fw] = {
                        "name": fw,
                        "confidence": CONFIDENCE_CONFIRMED,
                        "evidence": evidence(rel, 1, symbol=str(pkg), reason=f"composer {pkg}"),
                    }
                    break
    return frameworks
