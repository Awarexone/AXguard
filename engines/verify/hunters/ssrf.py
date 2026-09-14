"""SSRF hunter (network / HTTP sinks)."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from engines.verify.hunters.base import hunt_paths_then_weak_sinks
from engines.verify.schema import VULN_SSRF


class SsrfHunter:
    name = "ssrf"
    vulnerability_type = VULN_SSRF

    def hunt(
        self,
        target: Path,
        *,
        application_model: dict[str, Any],
        dataflow: dict[str, Any],
    ) -> list[dict[str, Any]]:
        return hunt_paths_then_weak_sinks(
            vulnerability_type=VULN_SSRF,
            title_for_path="Candidate SSRF via tainted network sink",
            title_for_sink="Candidate network sink without confirmed taint path",
            hunter_name=self.name,
            application_model=application_model,
            dataflow=dataflow,
            target=target,
        )
