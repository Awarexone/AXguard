"""Source-tree pattern scanner."""

from __future__ import annotations

from pathlib import Path

SKIP_DIRS = {
    ".git",
    ".hg",
    ".svn",
    ".venv",
    "venv",
    "node_modules",
    "dist",
    "build",
    "__pycache__",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".findings",
}

TEXT_SUFFIXES = {
    ".py",
    ".js",
    ".jsx",
    ".ts",
    ".tsx",
    ".mjs",
    ".cjs",
    ".go",
    ".rb",
    ".php",
    ".java",
    ".kt",
    ".rs",
    ".c",
    ".cpp",
    ".h",
    ".hpp",
    ".cs",
    ".swift",
    ".sh",
    ".bash",
    ".zsh",
    ".yml",
    ".yaml",
    ".json",
    ".toml",
    ".env",
    ".sql",
    ".html",
    ".htm",
    ".vue",
    ".svelte",
    ".md",
    ".tf",
    ".hcl",
    ".cshtml",
    ".aspx",
    ".jsp",
    ".xml",
    ".ini",
    ".cfg",
    ".gradle",
    ".properties",
}

# Exact filenames (any path) scanned even without a matching suffix.
TEXT_NAMES = {
    ".env",
    "dockerfile",
    "pipfile",
    "requirements.txt",
}


def scan_source(target: Path, rules: list[dict]) -> list[dict]:
    findings: list[dict] = []
    files = list(_iter_files(target))
    for path in files:
        try:
            content = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        rel = str(path.relative_to(target)) if path.is_relative_to(target) else str(path)
        for rule in rules:
            pattern = rule.get("pattern_re")
            if pattern is None:
                continue
            if not _rule_applies(rule, path):
                continue
            for match in pattern.finditer(content):
                line = content.count("\n", 0, match.start()) + 1
                findings.append(
                    {
                        "id": rule.get("id", "unknown"),
                        "title": rule.get("title", rule.get("id", "finding")),
                        "severity": rule.get("severity", "medium").lower(),
                        "file": rel,
                        "line": line,
                        "snippet": _snippet(content, match.start()),
                        "message": rule.get("message", ""),
                        "cwe": rule.get("cwe"),
                        "fix": rule.get("fix"),
                        "rule_source": rule.get("_source"),
                    }
                )
    findings.sort(key=lambda f: (-_sev(f["severity"]), f["file"], f["line"]))
    return findings


def _sev(severity: str) -> int:
    return {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}.get(severity, 0)


def _iter_files(root: Path):
    if root.is_file():
        yield root
        return
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        suffix = path.suffix.lower()
        name = path.name.lower()
        if suffix not in TEXT_SUFFIXES and name not in TEXT_NAMES:
            continue
        yield path


def _rule_applies(rule: dict, path: Path) -> bool:
    languages = rule.get("languages")
    if not languages:
        return True
    if isinstance(languages, str):
        languages = [languages]
    suffix = path.suffix.lower().lstrip(".")
    name = path.name.lower()
    for lang in languages:
        lang = str(lang).lower()
        if lang in {suffix, name}:
            return True
        if lang == "python" and suffix == "py":
            return True
        if lang in {"javascript", "js"} and suffix in {"js", "jsx", "mjs", "cjs"}:
            return True
        if lang in {"typescript", "ts"} and suffix in {"ts", "tsx"}:
            return True
        if lang == "shell" and suffix in {"sh", "bash", "zsh"}:
            return True
        if lang in {"yaml", "yml"} and suffix in {"yml", "yaml"}:
            return True
        if lang == "php" and suffix == "php":
            return True
        if lang == "java" and suffix in {"java", "kt"}:
            return True
        if lang == "go" and suffix == "go":
            return True
        if lang in {"ruby", "rb"} and suffix == "rb":
            return True
        if lang in {"terraform", "hcl", "tf"} and suffix in {"tf", "hcl"}:
            return True
        if lang == "dockerfile" and name == "dockerfile":
            return True
    return False


def _snippet(content: str, start: int, radius: int = 80) -> str:
    line_start = content.rfind("\n", 0, start) + 1
    line_end = content.find("\n", start)
    if line_end == -1:
        line_end = len(content)
    line = content[line_start:line_end].strip()
    if len(line) > radius:
        return line[: radius - 3] + "..."
    return line
