"""Framework adapter contracts."""

from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any


class FrameworkAdapter(ABC):
    """Detect a framework and contribute partial discovery facts."""

    name: str = "base"

    @abstractmethod
    def detect(self, path: Path, stack: dict[str, Any]) -> bool:
        """Return True when this adapter should run for the target."""

    @abstractmethod
    def discover(self, path: Path, files: list[Path]) -> dict[str, Any]:
        """
        Return partial facts. Supported keys:
          entrypoints, frameworks, security_controls, identities
        """
