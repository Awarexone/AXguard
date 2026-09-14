"""Sensitive assets, external services, and AI component inventory (values REDACTED)."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from engines.app_model.discover import read_text, rel_path
from engines.app_model.schema import CONFIDENCE_CONFIRMED, CONFIDENCE_LIKELY, evidence

REDACTED = "REDACTED"

_SECRET_ASSIGN = re.compile(
    r"(?i)(api[_-]?key|secret[_-]?key|access[_-]?token|auth[_-]?token|password|passwd|"
    r"private[_-]?key|jwt[_-]?secret|client[_-]?secret)\s*[=:]\s*['\"][^'\"]{8,}['\"]"
)
_ENV_SECRET = re.compile(
    r"(?i)^(export\s+)?([A-Z0-9_]*(?:SECRET|TOKEN|PASSWORD|API_KEY|ACCESS_KEY|PRIVATE_KEY)[A-Z0-9_]*)\s*="
)
_AWS_KEY = re.compile(r"AKIA[0-9A-Z]{16}")
_PEM = re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")

_EXTERNAL_PKG: dict[str, tuple[str, str]] = {
    # name -> (category, display)
    "stripe": ("payments", "stripe"),
    "openai": ("ai", "openai"),
    "anthropic": ("ai", "anthropic"),
    "@anthropic-ai/sdk": ("ai", "anthropic"),
    "aws-sdk": ("cloud", "aws"),
    "@aws-sdk/client-s3": ("cloud", "aws"),
    "boto3": ("cloud", "aws"),
    "redis": ("datastore", "redis"),
    "ioredis": ("datastore", "redis"),
    "pg": ("datastore", "postgresql"),
    "postgres": ("datastore", "postgresql"),
    "psycopg2": ("datastore", "postgresql"),
    "psycopg2-binary": ("datastore", "postgresql"),
    "pymongo": ("datastore", "mongodb"),
    "mongodb": ("datastore", "mongodb"),
    "mongoose": ("datastore", "mongodb"),
    "langchain": ("ai", "langchain"),
    "@langchain/core": ("ai", "langchain"),
    "langgraph": ("ai", "langgraph"),
    "@modelcontextprotocol/sdk": ("ai", "mcp"),
    "mcp": ("ai", "mcp"),
    "slack": ("messaging", "slack"),
    "@slack/web-api": ("messaging", "slack"),
    "sendgrid": ("email", "sendgrid"),
    "nodemailer": ("email", "nodemailer"),
    "twilio": ("messaging", "twilio"),
    "firebase": ("cloud", "firebase"),
    "google-cloud": ("cloud", "gcp"),
    "@google-cloud/storage": ("cloud", "gcp"),
    "azure": ("cloud", "azure"),
}

_IMPORT_EXTERNAL = [
    (re.compile(r"^\s*(?:import|from)\s+(openai|anthropic|stripe|boto3|redis|pymongo|langchain|mcp)\b", re.M), "confirmed"),
    (re.compile(r"""require\(['\"](stripe|openai|anthropic|aws-sdk|redis|mongoose|@modelcontextprotocol/sdk)['\"]\)"""), "confirmed"),
    (re.compile(r"""from\s+['\"](openai|anthropic|stripe|@aws-sdk/[^'\"]+|langchain[^'\"]*|@modelcontextprotocol/sdk)['\"]"""), "confirmed"),
]

_AI_HINTS = [
    (re.compile(r"(?i)\bChatOpenAI\b|\bOpenAI\(|openai\.chat"), "openai_client"),
    (re.compile(r"(?i)\bAnthropic\(|anthropic\.messages"), "anthropic_client"),
    (re.compile(r"(?i)\btool(_|-)?calls?\b|\bfunction_call\b|\btools\s*=\s*\["), "tool_calling"),
    (re.compile(r"(?i)MCPServer|mcp\.client|StdioServerTransport|modelcontextprotocol"), "mcp"),
    (re.compile(r"(?i)\bvectorstore\b|\bembeddings?\b|\bPinecone\b|\bChroma\b"), "retrieval"),
    (re.compile(r"(?i)\bAgentExecutor\b|\bcreate_react_agent\b|\blanggraph\b"), "agent_framework"),
]


def discover_assets(
    root: Path,
    files: list[Path],
    stack: dict[str, Any] | None = None,
) -> dict[str, Any]:
    assets: list[dict[str, Any]] = []
    external: list[dict[str, Any]] = []
    ai_components: list[dict[str, Any]] = []
    seen_ext: set[str] = set()
    seen_ai: set[str] = set()

    # Manifests
    for fpath in files:
        name = fpath.name.lower()
        rel = rel_path(fpath, root)
        if name == "package.json":
            _from_package_json(read_text(fpath), rel, external, ai_components, seen_ext, seen_ai)
        elif name in {"requirements.txt", "pyproject.toml", "pipfile"}:
            _from_python_manifest(read_text(fpath), rel, external, ai_components, seen_ext, seen_ai)

    for fpath in files:
        content = read_text(fpath)
        if not content:
            continue
        rel = rel_path(fpath, root)

        # Secret locations — never store values
        for m in _SECRET_ASSIGN.finditer(content):
            line = content.count("\n", 0, m.start()) + 1
            key_name = m.group(1)
            assets.append(
                {
                    "kind": "secret",
                    "type": _secret_type(key_name),
                    "name": key_name,
                    "location": rel,
                    "line": line,
                    "value": REDACTED,
                    "confidence": CONFIDENCE_LIKELY,
                    "evidence": evidence(
                        rel, line, symbol=key_name, reason="Secret-like assignment (value redacted)"
                    ),
                }
            )
        for m in _ENV_SECRET.finditer(content):
            line = content.count("\n", 0, m.start()) + 1
            var = m.group(2)
            assets.append(
                {
                    "kind": "secret",
                    "type": "env_secret",
                    "name": var,
                    "location": rel,
                    "line": line,
                    "value": REDACTED,
                    "confidence": CONFIDENCE_CONFIRMED
                    if fpath.name.lower().startswith(".env") or fpath.suffix == ".env"
                    else CONFIDENCE_LIKELY,
                    "evidence": evidence(rel, line, symbol=var, reason="Env secret variable (value redacted)"),
                }
            )
        if _AWS_KEY.search(content):
            line = content.count("\n", 0, _AWS_KEY.search(content).start()) + 1  # type: ignore[union-attr]
            assets.append(
                {
                    "kind": "secret",
                    "type": "aws_access_key_id",
                    "name": "AKIA****************",
                    "location": rel,
                    "line": line,
                    "value": REDACTED,
                    "confidence": CONFIDENCE_CONFIRMED,
                    "evidence": evidence(rel, line, reason="AWS access key ID pattern (value redacted)"),
                }
            )
        if _PEM.search(content):
            line = content.count("\n", 0, _PEM.search(content).start()) + 1  # type: ignore[union-attr]
            assets.append(
                {
                    "kind": "secret",
                    "type": "private_key",
                    "name": "PRIVATE_KEY",
                    "location": rel,
                    "line": line,
                    "value": REDACTED,
                    "confidence": CONFIDENCE_CONFIRMED,
                    "evidence": evidence(rel, line, reason="PEM private key block (value redacted)"),
                }
            )

        for pattern, _ in _IMPORT_EXTERNAL:
            for m in pattern.finditer(content):
                pkg = m.group(1)
                _add_external(pkg, rel, content.count("\n", 0, m.start()) + 1, external, seen_ext, CONFIDENCE_CONFIRMED)

        for pattern, kind in _AI_HINTS:
            m = pattern.search(content)
            if not m:
                continue
            key = f"{kind}:{rel}"
            if key in seen_ai:
                continue
            seen_ai.add(key)
            line = content.count("\n", 0, m.start()) + 1
            ai_components.append(
                {
                    "kind": kind,
                    "name": kind,
                    "file": rel,
                    "line": line,
                    "confidence": CONFIDENCE_LIKELY,
                    "evidence": evidence(rel, line, reason=f"AI-related pattern ({kind})"),
                }
            )

    # DB hints from stack
    if stack:
        for db in stack.get("databases") or []:
            name = db.get("name") if isinstance(db, dict) else str(db)
            assets.append(
                {
                    "kind": "database",
                    "type": "database",
                    "name": name,
                    "location": (db.get("evidence") or {}).get("file") if isinstance(db, dict) else None,
                    "value": REDACTED,
                    "confidence": db.get("confidence", CONFIDENCE_LIKELY) if isinstance(db, dict) else CONFIDENCE_LIKELY,
                    "evidence": db.get("evidence") if isinstance(db, dict) else evidence(reason="stack database hint"),
                }
            )

    return {
        "assets": assets,
        "external_services": external,
        "ai_components": ai_components,
    }


def _secret_type(name: str) -> str:
    n = name.lower()
    if "jwt" in n:
        return "jwt_secret"
    if "password" in n or "passwd" in n:
        return "password"
    if "token" in n:
        return "token"
    if "api" in n:
        return "api_key"
    return "secret"


def _from_package_json(
    content: str,
    rel: str,
    external: list[dict[str, Any]],
    ai: list[dict[str, Any]],
    seen_ext: set[str],
    seen_ai: set[str],
) -> None:
    try:
        data = json.loads(content)
    except json.JSONDecodeError:
        return
    deps: dict[str, Any] = {}
    for key in ("dependencies", "devDependencies"):
        block = data.get(key) or {}
        if isinstance(block, dict):
            deps.update(block)
    for pkg in deps:
        meta = _EXTERNAL_PKG.get(pkg) or _EXTERNAL_PKG.get(pkg.lower())
        if not meta:
            # prefix match for @aws-sdk/*
            for key, val in _EXTERNAL_PKG.items():
                if pkg.startswith(key) or pkg.lower().startswith(key.lower()):
                    meta = val
                    break
        if not meta:
            continue
        category, display = meta
        _add_external(display, rel, 1, external, seen_ext, CONFIDENCE_CONFIRMED, category=category, symbol=pkg)
        if category == "ai" and display not in seen_ai:
            seen_ai.add(display)
            ai.append(
                {
                    "kind": "provider" if display in {"openai", "anthropic"} else "framework",
                    "name": display,
                    "file": rel,
                    "line": 1,
                    "confidence": CONFIDENCE_CONFIRMED,
                    "evidence": evidence(rel, 1, symbol=pkg, reason=f"package.json dependency {pkg}"),
                }
            )


def _from_python_manifest(
    content: str,
    rel: str,
    external: list[dict[str, Any]],
    ai: list[dict[str, Any]],
    seen_ext: set[str],
    seen_ai: set[str],
) -> None:
    lower = content.lower()
    for pkg, (category, display) in _EXTERNAL_PKG.items():
        if "/" in pkg or pkg.startswith("@"):
            continue
        if re.search(rf"(?m)^\s*{re.escape(pkg)}\b|{re.escape(pkg)}\s*[<=>]|[\"']{re.escape(pkg)}[\"']", lower):
            _add_external(display, rel, 1, external, seen_ext, CONFIDENCE_CONFIRMED, category=category, symbol=pkg)
            if category == "ai" and display not in seen_ai:
                seen_ai.add(display)
                ai.append(
                    {
                        "kind": "provider" if display in {"openai", "anthropic"} else "framework",
                        "name": display,
                        "file": rel,
                        "line": 1,
                        "confidence": CONFIDENCE_CONFIRMED,
                        "evidence": evidence(rel, 1, symbol=pkg, reason=f"manifest dependency {pkg}"),
                    }
                )


def _add_external(
    name: str,
    file: str,
    line: int,
    external: list[dict[str, Any]],
    seen: set[str],
    confidence: str,
    *,
    category: str | None = None,
    symbol: str | None = None,
) -> None:
    key = name.lower()
    if key in seen:
        return
    seen.add(key)
    if category is None:
        meta = _EXTERNAL_PKG.get(name) or _EXTERNAL_PKG.get(key)
        category = meta[0] if meta else "external"
    external.append(
        {
            "name": name,
            "category": category,
            "confidence": confidence,
            "evidence": evidence(file, line, symbol=symbol or name, reason=f"External service {name}"),
        }
    )
