"""Dataflow / taint analysis schema constants and empty factory."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any

DATAFLOW_VERSION = "1.0.0"
TOOL_NAME = "axguard"

# Confidence (same vocabulary as app_model)
CONFIDENCE_CONFIRMED = "confirmed"
CONFIDENCE_LIKELY = "likely"
CONFIDENCE_UNKNOWN = "unknown"
CONFIDENCES = frozenset(
    {CONFIDENCE_CONFIRMED, CONFIDENCE_LIKELY, CONFIDENCE_UNKNOWN}
)

# Taint states along a path
TAINTED = "TAINTED"
PARTIALLY_SANITIZED = "PARTIALLY_SANITIZED"
VALIDATED = "VALIDATED"
SANITIZED = "SANITIZED"
TRUSTED = "TRUSTED"
UNKNOWN = "UNKNOWN"
TAINT_STATES = frozenset(
    {
        TAINTED,
        PARTIALLY_SANITIZED,
        VALIDATED,
        SANITIZED,
        TRUSTED,
        UNKNOWN,
    }
)

# Source trust levels
TRUST_UNTRUSTED = "untrusted"
TRUST_SEMI = "semi_trusted"
TRUST_TRUSTED = "trusted"
TRUST_UNKNOWN = "unknown"
TRUST_LEVELS = frozenset(
    {TRUST_UNTRUSTED, TRUST_SEMI, TRUST_TRUSTED, TRUST_UNKNOWN}
)

# Sink taxonomy (extends app_model sink types)
SINK_SQL = "sql"
SINK_CMD = "cmd"
SINK_NET = "net"
SINK_FS = "fs"
SINK_HTML = "html"
SINK_EVAL = "eval"
SINK_DESER = "deser"
SINK_REDIRECT = "redirect"
SINK_AI_TOOL = "ai_tool"
SINK_TEMPLATE = "template"
SINK_TYPES = frozenset(
    {
        SINK_SQL,
        SINK_CMD,
        SINK_NET,
        SINK_FS,
        SINK_HTML,
        SINK_EVAL,
        SINK_DESER,
        SINK_REDIRECT,
        SINK_AI_TOOL,
        SINK_TEMPLATE,
    }
)

# Map app_model sink.type → dataflow taxonomy
APP_MODEL_SINK_MAP: dict[str, str] = {
    "sql": SINK_SQL,
    "exec": SINK_EVAL,
    "http": SINK_NET,
    "fs": SINK_FS,
    "html": SINK_HTML,
    "template": SINK_TEMPLATE,
    "deserialize": SINK_DESER,
}

# Control effectiveness
EFFECT_CONFIRMED = "confirmed"
EFFECT_LIKELY = "likely"
EFFECT_UNKNOWN = "unknown"
EFFECT_INEFFECTIVE = "ineffective"
EFFECTIVENESS = frozenset(
    {EFFECT_CONFIRMED, EFFECT_LIKELY, EFFECT_UNKNOWN, EFFECT_INEFFECTIVE}
)

# Secret-looking keys — never emit values
_SECRET_KEY_HINTS = frozenset(
    {
        "api_key",
        "apikey",
        "password",
        "passwd",
        "secret",
        "token",
        "credential",
        "private_key",
        "access_key",
        "aws_secret",
        "jwt_secret",
    }
)


def evidence(
    file: str | None = None,
    line: int | None = None,
    *,
    symbol: str | None = None,
    reason: str = "",
    snippet: str | None = None,
) -> dict[str, Any]:
    ev: dict[str, Any] = {"reason": reason}
    if file is not None:
        ev["file"] = file
    if line is not None:
        ev["line"] = line
    if symbol is not None:
        ev["symbol"] = symbol
    if snippet is not None:
        ev["snippet"] = _redact_snippet(snippet)
    return ev


def _redact_snippet(text: str, max_len: int = 160) -> str:
    """Truncate and scrub obvious secret literals from evidence snippets."""
    import re

    out = text.strip()
    # Quoted long hex/base64-ish tokens
    out = re.sub(
        r"(?i)(['\"])(sk[_-][a-z0-9]{8,}|AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{20,}|[A-Za-z0-9+/]{32,}={0,2})\1",
        r"\1REDACTED\1",
        out,
    )
    out = re.sub(
        r"(?i)(password|secret|token|api[_-]?key)\s*[=:]\s*['\"][^'\"]{4,}['\"]",
        r"\1=REDACTED",
        out,
    )
    if len(out) > max_len:
        out = out[: max_len - 3] + "..."
    return out


def looks_like_secret_key(name: str) -> bool:
    lower = name.lower().replace("-", "_")
    return any(h in lower for h in _SECRET_KEY_HINTS)


def empty_dataflow(target: Path) -> dict[str, Any]:
    root = str(target.resolve())
    return {
        "schema_version": DATAFLOW_VERSION,
        "tool": TOOL_NAME,
        "target": root,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "sources": [],
        "sinks": [],
        "flows": [],
        "taint_paths": [],
        "controls": [],
        "summary": {
            "source_count": 0,
            "sink_count": 0,
            "path_count": 0,
            "unsanitized_path_count": 0,
        },
    }


def ensure_no_secret_values(obj: Any) -> None:
    """Replace secret-looking values in nested structures (never emit secrets)."""
    if isinstance(obj, dict):
        for k, v in list(obj.items()):
            if looks_like_secret_key(str(k)) and isinstance(v, str) and v not in {
                "REDACTED",
                "unknown",
                "",
            }:
                if len(v) > 4 and not v.startswith(("request.", "os.", "$", "{")):
                    obj[k] = "REDACTED"
            elif k == "value" and isinstance(v, str) and v != "REDACTED":
                # Belt-and-suspenders for asset-style nodes
                if looks_like_secret_key(str(obj.get("type", "") + obj.get("kind", ""))):
                    obj[k] = "REDACTED"
            else:
                ensure_no_secret_values(v)
    elif isinstance(obj, list):
        for item in obj:
            ensure_no_secret_values(item)
