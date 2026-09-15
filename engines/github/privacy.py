"""Secret redaction and ephemeral source handling for the GitHub adapter."""

from __future__ import annotations

import shutil
import tempfile
from pathlib import Path
from typing import Any

from engines.data.scrub import scrub_text
from engines.dataflow.schema import ensure_no_secret_values


def redact_text(text: str) -> str:
    """Redact secrets / credential-like strings from free text."""
    if not text:
        return text
    cleaned, _hits = scrub_text(text)
    return cleaned


def redact_secrets(obj: Any) -> Any:
    """Deep-redact strings in dict/list structures; never log raw secrets."""
    if isinstance(obj, str):
        return redact_text(obj)
    if isinstance(obj, dict):
        out = {k: redact_secrets(v) for k, v in obj.items()}
        ensure_no_secret_values(out)
        return out
    if isinstance(obj, list):
        return [redact_secrets(v) for v in obj]
    return obj


def should_retain_source(config: Any) -> bool:
    """Default: do not retain repository source after analysis."""
    privacy = getattr(config, "privacy", None)
    if privacy is None and isinstance(config, dict):
        privacy = config.get("privacy") or {}
    if isinstance(privacy, dict):
        return bool(privacy.get("retain_source", False))
    return bool(getattr(privacy, "retain_source", False))


class EphemeralWorkspace:
    """Temporary directory deleted after analysis unless retain_source is enabled."""

    def __init__(self, *, retain: bool = False, prefix: str = "axguard-gh-") -> None:
        self.retain = retain
        self.path: Path | None = None
        self._prefix = prefix

    def __enter__(self) -> Path:
        self.path = Path(tempfile.mkdtemp(prefix=self._prefix))
        return self.path

    def __exit__(self, *exc: object) -> None:
        if self.retain:
            return
        if self.path and self.path.exists():
            shutil.rmtree(self.path, ignore_errors=True)
        self.path = None
