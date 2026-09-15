"""Core scan orchestration."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from engines.rules_loader import load_rules
from engines.source_scan import scan_source


@dataclass
class ScanOptions:
    target: Path
    rules_dir: Path


def run_scan(options: ScanOptions) -> dict:
    rules = load_rules(options.rules_dir)
    findings = scan_source(options.target, rules)
    return {
        "tool": "axguard",
        "version": "0.2.0",
        "target": str(options.target),
        "finding_count": len(findings),
        "findings": findings,
    }
