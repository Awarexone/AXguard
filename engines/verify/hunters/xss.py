"""XSS hunter (HTML / template sinks)."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from engines.verify.hunters.base import hunt_paths_then_weak_sinks
from engines.verify.schema import VULN_XSS


class XssHunter:
    name = "xss"
    vulnerability_type = VULN_XSS

    def hunt(
        self,
        target: Path,
        *,
        application_model: dict[str, Any],
        dataflow: dict[str, Any],
    ) -> list[dict[str, Any]]:
        return hunt_paths_then_weak_sinks(
            vulnerability_type=VULN_XSS,
            title_for_path="Candidate XSS via tainted HTML/template sink",
            title_for_sink="Candidate HTML/template sink without confirmed taint path",
            hunter_name=self.name,
            application_model=application_model,
            dataflow=dataflow,
            target=target,
        )
