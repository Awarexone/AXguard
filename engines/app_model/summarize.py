"""Human-readable markdown summary of an application model."""

from __future__ import annotations

from typing import Any


def render_summary_markdown(model: dict[str, Any]) -> str:
    app = model.get("application") or {}
    summary = model.get("summary") or {}
    name = app.get("name") or "unknown"

    frameworks = _names(app.get("frameworks"))
    databases = _names(app.get("databases"))
    languages = _names(app.get("languages"))
    externals = [str(x.get("name")) for x in model.get("external_services") or []]
    ai = model.get("ai_components") or []

    auth_required = summary.get("authenticated_count", 0)
    auth_unknown = summary.get("auth_unknown_count", 0)
    unauth = summary.get("unauthenticated_count", 0)

    lines = [
        f"# Application Model: {name}",
        "",
        f"- **Schema**: {model.get('schema_version', 'unknown')}",
        f"- **Target**: `{model.get('target', '')}`",
        f"- **Generated**: {model.get('generated_at', '')}",
        "",
        "## Stack",
        "",
        f"- Languages: {_join(languages) or 'unknown'}",
        f"- Frameworks: {_join(frameworks) or 'unknown'}",
        f"- Runtimes: {_join(_names(app.get('runtimes'))) or 'unknown'}",
        f"- Package managers: {_join(_names(app.get('package_managers'))) or 'unknown'}",
        f"- Databases: {_join(databases) or 'unknown'}",
        f"- Cloud: {_join(_names(app.get('cloud'))) or 'unknown'}",
        f"- Infrastructure: {_join(_names(app.get('infrastructure'))) or 'unknown'}",
        "",
        "## Attack surface",
        "",
        f"- Endpoints: {summary.get('endpoint_count', len(model.get('entrypoints') or []))}",
        f"- Authenticated (likely/confirmed): {auth_required}",
        f"- Authentication unknown: {auth_unknown}",
        f"- Unauthenticated (status=none): {unauth}",
        f"- Sinks: {summary.get('sink_count', len(model.get('sinks') or []))}",
        f"- Security controls: {summary.get('control_count', len(model.get('security_controls') or []))}",
        f"- Trust boundaries: {summary.get('trust_boundary_count', len(model.get('trust_boundaries') or []))}",
        "",
        "## External services",
        "",
    ]
    if externals:
        for name_ in sorted(set(externals)):
            lines.append(f"- {name_}")
    else:
        lines.append("- none discovered")

    lines.extend(["", "## Sensitive assets", ""])
    assets = model.get("assets") or []
    if assets:
        for a in assets[:50]:
            lines.append(
                f"- {a.get('kind')}: `{a.get('name')}` @ `{a.get('location')}` (value=REDACTED)"
            )
        if len(assets) > 50:
            lines.append(f"- … {len(assets) - 50} more")
    else:
        lines.append("- none discovered")

    lines.extend(["", "## AI components", ""])
    if ai:
        for c in ai:
            lines.append(f"- {c.get('kind')}: {c.get('name')} ({c.get('confidence')})")
    else:
        lines.append("- none discovered")

    lines.extend(["", "## Notable entrypoints", ""])
    for ep in (model.get("entrypoints") or [])[:30]:
        auth = (ep.get("authentication") or {}).get("status", "unknown")
        lines.append(
            f"- `{ep.get('method')} {ep.get('path')}` "
            f"({ep.get('file')}:{ep.get('line')}) auth={auth} conf={ep.get('confidence')}"
        )
    if not model.get("entrypoints"):
        lines.append("- none discovered")

    lines.extend(["", "## Sink inventory (not findings)", ""])
    by_type: dict[str, int] = {}
    for s in model.get("sinks") or []:
        t = str(s.get("type", "other"))
        by_type[t] = by_type.get(t, 0) + 1
    if by_type:
        for t, n in sorted(by_type.items()):
            lines.append(f"- {t}: {n}")
    else:
        lines.append("- none discovered")

    lines.append("")
    return "\n".join(lines)


def _names(items: Any) -> list[str]:
    if not items:
        return []
    out = []
    for x in items:
        if isinstance(x, dict):
            out.append(str(x.get("name", x)))
        else:
            out.append(str(x))
    return out


def _join(items: list[str]) -> str:
    return ", ".join(items)
