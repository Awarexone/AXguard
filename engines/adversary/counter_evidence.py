"""Search related files / middleware / validation / config for counter-evidence."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from engines.app_model.discover import read_text, rel_path
from engines.dataflow.schema import ensure_no_secret_values, evidence as _evidence

# Comments that look like prompt-injection / "ignore this finding" — never trust
_ADVERSARIAL_COMMENT = re.compile(
    r"(?i)(?:AI\s*(?:reviewer|judge|assistant)?|LLM|Copilot|Cursor)"
    r".{0,40}(?:ignore|fixed|false\s*positive|not\s*a\s*(?:bug|vuln)|safe\s*to\s*ignore)"
    r"|(?:ignore\s+this\s+finding|this\s+vulnerability\s+is\s+fixed)"
)

# Import / require lines → related modules (same package preferred)
_IMPORT_PY = re.compile(
    r"(?m)^\s*(?:from\s+([\w.]+)\s+import|import\s+([\w.]+))"
)
_REQUIRE_JS = re.compile(
    r"""require\(\s*['"](\.[^'"]+)['"]\s*\)|from\s+['"](\.[^'"]+)['"]"""
)

# Counter-evidence pattern catalog: (kind, strength, pattern, reason)
# strength: confirmed | likely | weak
_COUNTER_PATTERNS: list[tuple[str, str, re.Pattern[str], str]] = [
    (
        "parameterization",
        "confirmed",
        re.compile(
            r"\.(?:execute|executemany)\s*\(\s*['\"][^'\"]*(?:\?|%s|:\w+)[^'\"]*['\"]\s*,",
            re.I,
        ),
        "Parameterized / bound SQL arguments",
    ),
    (
        "parameterization",
        "likely",
        re.compile(
            r"text\s*\(\s*['\"][^'\"]*:\w+|\.filter\s*\([^)]*==|preparedStatement|"
            r"cursor\.execute\s*\(\s*['\"][^f'\"][^'\"]*\?",
            re.I,
        ),
        "Likely bound / ORM-filtered query",
    ),
    (
        "allowlist",
        "confirmed",
        re.compile(
            r"(?i)if\s+.*(?:hostname|host)\s+not\s+in\s+\w+",
        ),
        "Hostname allowlist reject branch",
    ),
    (
        "allowlist",
        "likely",
        re.compile(
            r"(?i)(ALLOWED_HOSTS|ALLOWLIST|allowed_hosts|SAFE_HOSTS|"
            r"urlparse\s*\(|hostname\s*(?:in|==|not\s+in))",
        ),
        "Host / URL allowlist evidence",
    ),
    (
        "path_jail",
        "confirmed",
        re.compile(
            r"(?i)(?:os\.path\.commonpath|Path\([^)]*\)\.resolve\(\).*relative_to|"
            r"startswith\s*\(\s*(?:base|root|SAFE_|ALLOWED_))",
        ),
        "Path jail / base-directory enforcement",
    ),
    (
        "path_jail",
        "likely",
        re.compile(
            r"(?i)(?:os\.path\.(?:normpath|realpath|abspath)|"
            r"pathlib\.Path|secure_filename|werkzeug\.utils\.secure_filename)",
        ),
        "Path normalization / secure_filename",
    ),
    (
        "sanitization",
        "confirmed",
        re.compile(
            r"(?i)(?:html\.escape|markupsafe\.escape|bleach\.clean|DOMPurify|"
            r"escapeHtml|cgi\.escape|sax\.utils\.escape)\s*\(",
        ),
        "Context escaping / sanitizer call",
    ),
    (
        "sanitization",
        "likely",
        re.compile(
            r"(?i)(?:html\.escape|markupsafe\.escape|bleach\.clean|DOMPurify|"
            r"escapeHtml|encodeURIComponent)",
        ),
        "Escaping / sanitizer reference",
    ),
    (
        "validation",
        "likely",
        re.compile(
            r"(?i)(?:validators?\.\w+|pydantic|marshmallow|joi\.|zod\.|"
            r"re\.fullmatch|re\.match\s*\()",
        ),
        "Validation library / regex match",
    ),
    (
        "authorization",
        "likely",
        re.compile(
            r"(?i)(?:@require_auth|@login_required|@permission_required|"
            r"check_permission|authorize\(|has_permission|"
            r"Depends\s*\(\s*get_current)",
        ),
        "Authorization decorator / check",
    ),
    (
        "tenant_isolation",
        "likely",
        re.compile(
            r"(?i)(?:tenant_id|org_id|workspace_id|account_id)\s*(?:==|=)\s*|"
            r"filter_by\s*\([^)]*tenant|WHERE\s+.*tenant",
        ),
        "Tenant / org boundary filter",
    ),
    (
        "framework",
        "likely",
        re.compile(
            r"(?i)(?:autoescape\s*=\s*True|Jinja2.*autoescape|"
            r"\{\{\s*\w+\s*\}\}|django\.utils\.html\.escape|"
            r"HttpResponse\(|render_template\s*\()",
        ),
        "Framework template / autoescape hint",
    ),
    (
        "configuration",
        "likely",
        re.compile(
            r"(?i)(?:ALLOWED_HOSTS\s*=|DEBUG\s*=\s*False|SECURE_|"
            r"Content-Security-Policy|X-Frame-Options)",
        ),
        "Security-relevant configuration",
    ),
    (
        "dead_code",
        "likely",
        re.compile(
            r"(?i)(?:if\s+False\s*:|if\s+0\s*:|raise\s+NotImplementedError|"
            r"^\s*#\s*(?:TODO:\s*)?dead\b)",
            re.M,
        ),
        "Likely unreachable / dead branch",
    ),
]

# Function names that look like controls but prove nothing alone
_NAME_ONLY_CONTROL = re.compile(
    r"(?i)\b(?:sanitize|validate|clean|escape|check|secure|safe)_?\w*\s*\("
)

_CONFIG_NAMES = frozenset(
    {
        "settings.py",
        "config.py",
        "config.js",
        "config.ts",
        "config.json",
        "config.yaml",
        "config.yml",
        "application.yml",
        "application.yaml",
        "appsettings.json",
        ".env.example",
        "nginx.conf",
        "docker-compose.yml",
        "docker-compose.yaml",
    }
)

_MIDDLEWARE_HINT = re.compile(r"(?i)middleware|auth|security|guard|permission")


def search_counter_evidence(
    *,
    target: Path,
    candidate: dict[str, Any],
    judgment: dict[str, Any] | None = None,
    application_model: dict[str, Any] | None = None,
    dataflow: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    """
    Collect counter-evidence near the finding without rebuilding graphs.

    Uses Phase 1–2 inventories when present, then scans same file + nearby
    imports / middleware / config. Never treats adversarial comments as evidence.
    """
    _ = judgment
    root = Path(target).resolve()
    cand = candidate or {}
    loc = cand.get("location") or {}
    sink = cand.get("sink") or {}
    file_rel = str(loc.get("file") or sink.get("file") or "")
    line = int(loc.get("line") or sink.get("line") or 0)

    hits: list[dict[str, Any]] = []
    seen: set[tuple[str, str, int]] = set()

    def add_hit(
        kind: str,
        strength: str,
        *,
        file: str | None,
        line_no: int | None,
        reason: str,
        snippet: str | None = None,
        source: str = "scan",
    ) -> None:
        key = (kind, str(file or ""), int(line_no or 0))
        if key in seen:
            return
        seen.add(key)
        # Strip adversarial-comment bait from snippets — never use as instruction
        if snippet and _ADVERSARIAL_COMMENT.search(snippet):
            snippet = "[adversarial comment ignored]"
        ev = _evidence(
            file,
            line_no,
            symbol=kind,
            reason=reason,
            snippet=snippet,
        )
        hit = {
            "kind": kind,
            "strength": strength,
            "source": source,
            "evidence": ev,
        }
        ensure_no_secret_values(hit)
        hits.append(hit)

    # Reuse Phase 2 path controls
    df = cand.get("data_flow") or {}
    for ctrl in list(df.get("controls_seen") or []) + list(cand.get("controls") or []):
        if isinstance(ctrl, dict):
            kind = str(ctrl.get("kind") or "control")
            eff = str(ctrl.get("effectiveness") or "unknown")
            strength = "confirmed" if eff == "confirmed" else "likely" if eff == "likely" else "weak"
            cev = ctrl.get("evidence") if isinstance(ctrl.get("evidence"), dict) else {}
            add_hit(
                kind,
                strength,
                file=str(ctrl.get("file") or cev.get("file") or file_rel or ""),
                line_no=int(ctrl.get("line") or cev.get("line") or 0) or None,
                reason=str((cev or {}).get("reason") or f"dataflow control kind={kind}"),
                snippet=(cev or {}).get("snippet"),
                source="dataflow",
            )
        elif isinstance(ctrl, str) and ctrl:
            add_hit(
                "control",
                "weak",
                file=file_rel or None,
                line_no=line or None,
                reason=f"Named control reference: {ctrl}",
                source="dataflow",
            )

    # Phase 2 global controls collocated with this file
    if dataflow:
        for ctrl in dataflow.get("controls") or []:
            if not isinstance(ctrl, dict):
                continue
            cfile = str(ctrl.get("file") or "")
            if file_rel and cfile and Path(cfile).name != Path(file_rel).name and cfile != file_rel:
                # Allow same-directory middleware later; skip distant here
                continue
            kind = str(ctrl.get("kind") or "control")
            eff = str(ctrl.get("effectiveness") or "unknown")
            strength = "confirmed" if eff == "confirmed" else "likely"
            cev = ctrl.get("evidence") if isinstance(ctrl.get("evidence"), dict) else {}
            add_hit(
                kind,
                strength,
                file=cfile or file_rel,
                line_no=int(ctrl.get("line") or 0) or None,
                reason=str((cev or {}).get("reason") or f"dataflow inventory control={kind}"),
                snippet=(cev or {}).get("snippet"),
                source="dataflow_inventory",
            )

    # Phase 1 controls on the same file only (not sibling routes)
    if application_model:
        for ctrl in application_model.get("controls") or []:
            if not isinstance(ctrl, dict):
                continue
            cev = ctrl.get("evidence") if isinstance(ctrl.get("evidence"), dict) else {}
            cfile = str(cev.get("file") or ctrl.get("file") or "")
            if file_rel and cfile and not (
                cfile == file_rel or Path(cfile).name == Path(file_rel).name
            ):
                continue
            kind = str(ctrl.get("type") or ctrl.get("kind") or "control")
            add_hit(
                kind if kind in {"authorization", "authentication", "csrf", "cors"} else "framework",
                "likely",
                file=cfile or file_rel,
                line_no=int(cev.get("line") or ctrl.get("line") or 0) or None,
                reason=str(cev.get("reason") or ctrl.get("name") or "app_model control"),
                snippet=cev.get("snippet"),
                source="app_model",
            )

    # Scan primary file + related files
    files_to_scan = _related_files(root, file_rel, application_model=application_model)
    for rel, content in files_to_scan:
        if not content:
            continue
        # Mark adversarial comments so they are never treated as FP instructions
        for m in _ADVERSARIAL_COMMENT.finditer(content):
            abs_line = content.count("\n", 0, m.start()) + 1
            add_hit(
                "ignored_comment",
                "weak",
                file=rel,
                line_no=abs_line,
                reason="Adversarial/repo comment ignored (not a judge instruction)",
                snippet=content.splitlines()[abs_line - 1][:120] if abs_line else None,
                source="ignored_comment",
            )

        primary = bool(file_rel) and (
            rel == file_rel or Path(rel).name == Path(file_rel).name
        )
        for kind, strength, pattern, reason in _COUNTER_PATTERNS:
            for m in pattern.finditer(content):
                abs_line = content.count("\n", 0, m.start()) + 1
                # Sink-local controls: keep confirmed hits in primary file;
                # non-primary files only contribute config/framework/authz/middleware.
                if not primary:
                    if kind not in {
                        "configuration",
                        "framework",
                        "authorization",
                        "tenant_isolation",
                        "allowlist",
                        "path_jail",
                    }:
                        continue
                elif line > 0 and abs(abs_line - line) > 80:
                    if strength != "confirmed" and kind not in {
                        "allowlist",
                        "path_jail",
                        "configuration",
                        "authorization",
                    }:
                        continue
                snippet_line = (
                    content.splitlines()[abs_line - 1] if 0 < abs_line <= len(content.splitlines()) else ""
                )
                if _ADVERSARIAL_COMMENT.search(snippet_line):
                    continue
                add_hit(
                    kind,
                    strength,
                    file=rel,
                    line_no=abs_line,
                    reason=reason,
                    snippet=snippet_line,
                    source="scan",
                )

        # Name-only sanitize/validate — record as weak, never confirmed
        for m in _NAME_ONLY_CONTROL.finditer(content):
            abs_line = content.count("\n", 0, m.start()) + 1
            snippet_line = (
                content.splitlines()[abs_line - 1] if 0 < abs_line <= len(content.splitlines()) else ""
            )
            add_hit(
                "name_only_control",
                "weak",
                file=rel,
                line_no=abs_line,
                reason="Function name looks like sanitize/validate — not proof of effectiveness",
                snippet=snippet_line,
                source="name_only",
            )

    return hits


def _related_files(
    root: Path,
    file_rel: str,
    *,
    application_model: dict[str, Any] | None = None,
) -> list[tuple[str, str]]:
    """Resolve primary file + imported neighbors + nearby middleware/config."""
    out: list[tuple[str, str]] = []
    seen: set[str] = set()

    def try_add(rel: str) -> None:
        rel_n = rel.replace("\\", "/")
        if rel_n in seen:
            return
        path = root / rel_n
        if not path.is_file():
            # try basename search under root (shallow)
            matches = list(root.rglob(Path(rel_n).name))[:3]
            if not matches:
                return
            path = matches[0]
            rel_n = rel_path(path, root)
        try:
            content = read_text(path)
        except OSError:
            return
        seen.add(rel_n)
        out.append((rel_n, content))

    if file_rel:
        try_add(file_rel)

    # Follow relative imports from primary
    primary_content = out[0][1] if out else ""
    if primary_content:
        for m in _IMPORT_PY.finditer(primary_content):
            mod = (m.group(1) or m.group(2) or "").strip()
            if not mod or mod.split(".")[0] in {
                "flask",
                "fastapi",
                "django",
                "requests",
                "os",
                "sys",
                "re",
                "json",
                "typing",
                "pathlib",
                "urllib",
            }:
                continue
            # Same-package style: foo.bar → foo/bar.py
            candidate = mod.replace(".", "/") + ".py"
            if "/" in candidate or file_rel:
                # Prefer sibling module
                base = Path(file_rel).parent if file_rel else Path(".")
                sibling = str(base / f"{mod.split('.')[-1]}.py")
                try_add(sibling)
            try_add(candidate)
        for m in _REQUIRE_JS.finditer(primary_content):
            rel_imp = (m.group(1) or m.group(2) or "").strip()
            if not rel_imp:
                continue
            base = Path(file_rel).parent if file_rel else Path(".")
            for ext in ("", ".js", ".ts", ".jsx", ".tsx"):
                try_add(str(base / f"{rel_imp}{ext}"))

    # Same-file only for entrypoints — do NOT scan unrelated sibling routes
    # (parameterization in another handler must not disprove this finding).
    if application_model and file_rel:
        for ep in application_model.get("entrypoints") or []:
            efile = str(ep.get("file") or "")
            if efile and (efile == file_rel or Path(efile).name == Path(file_rel).name):
                try_add(efile)

    # Config / middleware-named files only (not every .py sibling)
    search_dirs = [root]
    if file_rel:
        search_dirs.append(root / Path(file_rel).parent)
    for d in search_dirs:
        if not d.is_dir():
            continue
        try:
            for child in d.iterdir():
                if not child.is_file() or child.stat().st_size >= 200_000:
                    continue
                if child.name in _CONFIG_NAMES or _MIDDLEWARE_HINT.search(child.name):
                    try_add(rel_path(child, root))
        except OSError:
            continue

    return out
