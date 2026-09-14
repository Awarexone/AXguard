"""Command injection hunter (cmd / exec / eval sinks)."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from engines.verify.hunters.base import hunt_paths_then_weak_sinks
from engines.verify.schema import VULN_CMD


class CommandInjectionHunter:
    name = "command_injection"
    vulnerability_type = VULN_CMD

    def hunt(
        self,
        target: Path,
        *,
        application_model: dict[str, Any],
        dataflow: dict[str, Any],
    ) -> list[dict[str, Any]]:
        return hunt_paths_then_weak_sinks(
            vulnerability_type=VULN_CMD,
            title_for_path="Candidate command injection via tainted exec sink",
            title_for_sink="Candidate exec/cmd sink without confirmed taint path",
            hunter_name=self.name,
            application_model=application_model,
            dataflow=dataflow,
            target=target,
        )
