"""Write adversary.json, adversary.md, and final-findings.json artifacts."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from engines.adversary.summarize import render_adversary_markdown
from engines.dataflow.schema import ensure_no_secret_values


def write_adversary_artifacts(result: dict[str, Any], out_dir: Path) -> dict[str, Any]:
    """Write ``adversary.json``, ``adversary.md``, and ``final-findings.json``."""
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    json_path = out_dir / "adversary.json"
    md_path = out_dir / "adversary.md"
    final_path = out_dir / "final-findings.json"

    serializable = {
        k: v
        for k, v in result.items()
        if not str(k).startswith("_")
    }
    ensure_no_secret_values(serializable)

    json_path.write_text(
        json.dumps(serializable, indent=2, sort_keys=False) + "\n",
        encoding="utf-8",
    )
    md_path.write_text(render_adversary_markdown(serializable), encoding="utf-8")

    final_payload = {
        "schema_version": serializable.get("schema_version"),
        "tool": serializable.get("tool"),
        "target": serializable.get("target"),
        "generated_at": serializable.get("generated_at"),
        "findings": serializable.get("findings") or [],
        "summary": serializable.get("summary") or {},
    }
    ensure_no_secret_values(final_payload)
    final_path.write_text(
        json.dumps(final_payload, indent=2, sort_keys=False) + "\n",
        encoding="utf-8",
    )

    return {
        "json": str(json_path),
        "markdown": str(md_path),
        "final_findings": str(final_path),
        "files": [str(json_path), str(md_path), str(final_path)],
    }


# Alias matching public API naming in pipeline
write_adversary_report = write_adversary_artifacts
