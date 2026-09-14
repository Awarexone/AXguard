"""Write verification.json and verification.md artifacts."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from engines.dataflow.schema import ensure_no_secret_values
from engines.verify.summarize import render_verification_markdown


def write_verification_artifacts(result: dict[str, Any], out_dir: Path) -> dict[str, Any]:
    """Write ``verification.json`` and ``verification.md`` under ``out_dir``."""
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    json_path = out_dir / "verification.json"
    md_path = out_dir / "verification.md"

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
    md_path.write_text(render_verification_markdown(serializable), encoding="utf-8")

    return {
        "json": str(json_path),
        "markdown": str(md_path),
        "files": [str(json_path), str(md_path)],
    }


# Alias matching public API naming in pipeline
write_verification_report = write_verification_artifacts
