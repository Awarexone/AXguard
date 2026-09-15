"""Path traversal hunter (filesystem sinks)."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from engines.verify.hunters.base import hunt_paths_then_weak_sinks
from engines.verify.schema import VULN_PATH


class PathTraversalHunter:
    name = "path_traversal"
    vulnerability_type = VULN_PATH

    def hunt(
        self,
        target: Path,
        *,
        application_model: dict[str, Any],
        dataflow: dict[str, Any],
    ) -> list[dict[str, Any]]:
        return hunt_paths_then_weak_sinks(
            vulnerability_type=VULN_PATH,
            title_for_path="Candidate path traversal via tainted filesystem sink",
            title_for_sink="Candidate filesystem sink without confirmed taint path",
            hunter_name=self.name,
            application_model=application_model,
            dataflow=dataflow,
            target=target,
        )
