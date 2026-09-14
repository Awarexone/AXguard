"""Repo path helpers."""

from __future__ import annotations

from pathlib import Path


def package_root() -> Path:
    return Path(__file__).resolve().parents[1]


def default_rules_dir() -> Path:
    return package_root() / "rules"
