"""Write evidence.json + evidence.md and attach compact summaries to findings."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from engines.dataflow.schema import ensure_no_secret_values
from engines.evidence.summarize import render_evidence_markdown


def attach_finding_summaries(result: dict[str, Any]) -> dict[str, Any]:
    """Attach compact evidence summaries onto the adversary findings in place.

    Adds ``confidence_level``, ``evidence_confidence`` (level only), and
    ``evidence_summary`` to each adversary finding without touching the existing
    ``confidence``/``status`` fields. Returns the adversary payload.
    """
    adversary = result.get("_adversary") or {}
    by_id = {
        e.get("finding_id"): e for e in result.get("findings_evidence") or []
    }
    for finding in adversary.get("findings") or []:
        entry = by_id.get(finding.get("id"))
        if not entry:
            continue
        finding["confidence_level"] = entry.get("confidence_level")
        finding["evidence_confidence"] = entry.get("confidence_level")
        finding["evidence_summary"] = entry.get("summary")
        finding["evidence_ids"] = list(entry.get("supporting_evidence_ids") or [])
        finding["counter_evidence_ids"] = list(entry.get("counter_evidence_ids") or [])
        if entry.get("conflict_handling"):
            finding["evidence_conflict_handling"] = entry["conflict_handling"]
    return adversary


def write_evidence_artifacts(result: dict[str, Any], out_dir: Path) -> dict[str, Any]:
    """Write ``evidence.json`` and ``evidence.md``."""
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    json_path = out_dir / "evidence.json"
    md_path = out_dir / "evidence.md"

    serializable = {
        k: v for k, v in result.items() if not str(k).startswith("_")
    }
    ensure_no_secret_values(serializable)

    json_path.write_text(
        json.dumps(serializable, indent=2, sort_keys=False) + "\n",
        encoding="utf-8",
    )
    md_path.write_text(render_evidence_markdown(serializable), encoding="utf-8")

    return {
        "json": str(json_path),
        "markdown": str(md_path),
        "files": [str(json_path), str(md_path)],
    }
