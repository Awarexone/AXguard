"""Attack-graph node factories + structural detectors.

Nodes are a graph *over* existing Phase 1-5 records — each node keeps a ``refs``
list pointing back at the source artifact instead of copying fields. Where the
upstream pipeline emits nothing usable (app_model reported 0 assets / 0
ai_components on the fixture app), this module adds **deterministic,
evidence-gated** structural detectors, scoped entirely to the attack_graph
package, that emit finding-like / asset / tool nodes with explicit evidence.
These never fabricate: a detector that does not match emits nothing.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any


# ---------------------------------------------------------------------------
# id helpers
# ---------------------------------------------------------------------------
def _slug(text: str) -> str:
    return re.sub(r"[^a-zA-Z0-9]+", "_", str(text or "")).strip("_").lower()


def entrypoint_id(method: str, path: str) -> str:
    return f"entrypoint:{_slug(method)}:{_slug(path)}"


def finding_id(raw_id: str) -> str:
    return f"finding:{_slug(raw_id)}"


def seed_id(vtype: str, file: str, line: int) -> str:
    return f"seed:{_slug(vtype)}:{_slug(Path(str(file)).name)}:{int(line or 0)}"


def asset_id(name: str, file: str) -> str:
    return f"asset:{_slug(Path(str(file)).name)}:{_slug(name)}"


def control_id(name: str, file: str) -> str:
    return f"control:{_slug(Path(str(file)).name)}:{_slug(name)}"


def identity_id(name: str) -> str:
    return f"identity:{_slug(name)}"


def ai_id(name: str, file: str) -> str:
    return f"ai_component:{_slug(Path(str(file)).name)}:{_slug(name)}"


def tool_id(name: str, file: str) -> str:
    return f"tool:{_slug(Path(str(file)).name)}:{_slug(name)}"


# ---------------------------------------------------------------------------
# node factories
# ---------------------------------------------------------------------------
def make_node(
    node_id: str,
    node_type: str,
    label: str,
    *,
    kind: str | None = None,
    location: dict[str, Any] | None = None,
    refs: list[dict[str, Any]] | None = None,
    evidence: list[dict[str, Any]] | None = None,
    **extra: Any,
) -> dict[str, Any]:
    node: dict[str, Any] = {
        "id": node_id,
        "type": node_type,
        "label": label,
        "kind": kind,
        "location": location or {},
        "refs": refs or [],
        "evidence": evidence or [],
    }
    node.update(extra)
    return node


def entrypoint_node(ep: dict[str, Any], reachability: str) -> dict[str, Any]:
    method = ep.get("method") or ep.get("kind") or "GET"
    path = ep.get("path") or ep.get("handler") or "?"
    return make_node(
        entrypoint_id(method, path),
        "entrypoint",
        f"{method} {path}",
        kind=ep.get("kind") or "http",
        location={"file": ep.get("file"), "line": ep.get("line")},
        refs=[{"source": "application-model.json", "id": f"{method} {path}"}],
        reachability=reachability,
        handler=ep.get("handler"),
        authentication=(ep.get("authentication") or {}).get("status", "unknown"),
    )


def queue_entrypoint_node(handler: str, file: str, line: int) -> dict[str, Any]:
    return make_node(
        f"entrypoint:queue:{_slug(Path(str(file)).name)}:{_slug(handler)}",
        "entrypoint",
        f"queue consumer {handler}()",
        kind="queue",
        location={"file": file, "line": line},
        refs=[{"source": "application-model.json", "id": handler}],
        reachability="unknown",
        handler=handler,
        authentication="unknown",
        evidence=[
            {
                "type": "TRUST_BOUNDARY",
                "description": (
                    "No code-visible publisher/route for this consumer; network "
                    "reachability is unknown (not defaulted to public or internal)."
                ),
                "file": file,
                "line": line,
            }
        ],
    )


def finding_node_from_adversary(finding: dict[str, Any]) -> dict[str, Any]:
    loc = finding.get("location") or {}
    vtype = finding.get("vulnerability_type") or "finding"
    return make_node(
        finding_id(finding.get("id") or f"{vtype}:{loc.get('file')}:{loc.get('line')}"),
        "finding",
        f"{vtype} ({finding.get('status')})",
        kind=vtype,
        location={"file": loc.get("file"), "line": loc.get("line")},
        refs=[
            {"source": "adversary.json", "id": finding.get("id")},
            {"source": "verification.json", "id": finding.get("from_judgment_id")},
        ],
        status=finding.get("status"),
        confidence=finding.get("confidence"),
        confidence_level=finding.get("confidence_level"),
        severity=finding.get("severity"),
        root_cause=finding.get("root_cause"),
        origin="adversary",
    )


def seed_finding_node(
    vtype: str,
    file: str,
    line: int,
    *,
    status: str,
    description: str,
    evidence: list[dict[str, Any]] | None = None,
    severity: str = "high",
) -> dict[str, Any]:
    """A candidate-seed finding node emitted by an attack-graph structural
    detector for a pattern the upstream hunters missed or conservatively
    dropped. Never CONFIRMED — a structural pattern is at best ``LIKELY``.
    """
    ev = list(evidence or [])
    ev.insert(
        0,
        {
            "type": "CODE_PATTERN",
            "description": description,
            "file": file,
            "line": line,
        },
    )
    return make_node(
        seed_id(vtype, file, line),
        "candidate_seed",
        f"{vtype} ({status}, structural seed)",
        kind=vtype,
        location={"file": file, "line": line},
        refs=[{"source": "attack_graph.seed", "id": f"{vtype}:{Path(str(file)).name}:{line}"}],
        status=status,
        confidence="likely" if status == "LIKELY" else "unknown",
        confidence_level=None,
        severity=severity,
        origin="attack_graph_seed",
        evidence=ev,
    )


def asset_node(
    name: str,
    file: str,
    line: int,
    kind: str,
    *,
    description: str,
) -> dict[str, Any]:
    return make_node(
        asset_id(name, file),
        "asset",
        name,
        kind=kind,
        location={"file": file, "line": line},
        refs=[{"source": "attack_graph.asset", "id": f"{Path(str(file)).name}:{name}"}],
        evidence=[{"type": "CODE_PATTERN", "description": description, "file": file, "line": line}],
    )


def identity_node(name: str, kind: str, *, tenant: str | None = None, role: str | None = None) -> dict[str, Any]:
    return make_node(
        identity_id(name),
        "identity",
        name,
        kind=kind,
        tenant=tenant,
        role=role,
        refs=[{"source": "application-model.json", "id": name}],
    )


def control_node(
    name: str,
    file: str,
    line: int,
    *,
    effectiveness: str,
    kind: str = "authorization",
    description: str,
) -> dict[str, Any]:
    return make_node(
        control_id(name, file),
        "control",
        name,
        kind=kind,
        location={"file": file, "line": line},
        refs=[{"source": "application-model.json", "id": name}],
        effectiveness=effectiveness,
        evidence=[{"type": "SECURITY_CONTROL", "description": description, "file": file, "line": line}],
    )


def ai_component_node(name: str, file: str, line: int, *, description: str) -> dict[str, Any]:
    return make_node(
        ai_id(name, file),
        "ai_component",
        name,
        kind="agent",
        location={"file": file, "line": line},
        refs=[{"source": "attack_graph.ai", "id": f"{Path(str(file)).name}:{name}"}],
        evidence=[{"type": "CODE_PATTERN", "description": description, "file": file, "line": line}],
    )


def tool_node(name: str, file: str, line: int, *, privileged: bool, description: str) -> dict[str, Any]:
    return make_node(
        tool_id(name, file),
        "tool",
        name,
        kind="fs-read" if "file" in name or "read" in name else "tool",
        location={"file": file, "line": line},
        refs=[{"source": "attack_graph.tool", "id": f"{Path(str(file)).name}:{name}"}],
        privileged=privileged,
        evidence=[{"type": "CODE_PATTERN", "description": description, "file": file, "line": line}],
    )


# ---------------------------------------------------------------------------
# structural source detectors (deterministic, evidence-gated)
# ---------------------------------------------------------------------------
def read_source(file: str) -> str:
    try:
        return Path(file).read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return ""


def _line_of(source: str, needle: str, default: int = 1) -> int:
    for i, ln in enumerate(source.splitlines(), 1):
        if needle in ln:
            return i
    return default


def detect_credential_asset(file: str, source: str) -> dict[str, Any] | None:
    """Detect a dict/const of cloud credentials or API tokens."""
    m = re.search(
        r"^([A-Z_]{3,})\s*=\s*\{[^}]*(aws_access_key|aws_secret_key|api_token|"
        r"internal_api_token|credential|secret_key)",
        source,
        re.MULTILINE | re.DOTALL | re.IGNORECASE,
    )
    if not m:
        return None
    name = m.group(1)
    line = _line_of(source, name + " =")
    return asset_node(
        name, file, line, "credential",
        description=f"credential/token store `{name}` returned by an internal handler",
    )


def detect_secret_file_asset(file: str, source: str) -> dict[str, Any] | None:
    m = re.search(r"^([A-Z_]{3,})\s*=\s*['\"][^'\"]*(secrets|\.env)[^'\"]*['\"]", source, re.MULTILINE | re.IGNORECASE)
    if not m:
        return None
    name = m.group(1)
    line = _line_of(source, name + " =")
    return asset_node(name, file, line, "secret", description=f"secrets file path `{name}` readable via a privileged tool")


def detect_sql_table_asset(file: str, source: str) -> dict[str, Any] | None:
    # Anchor on SELECT so we never match the `from __future__ import` line.
    m = re.search(r"SELECT\b[\s\S]{0,200}?\bFROM\s+([a-zA-Z_][a-zA-Z0-9_]*)", source, re.IGNORECASE)
    if not m:
        return None
    table = m.group(1)
    sensitive = bool(re.search(r"payment_token|password|email|secret|token|credit", source, re.IGNORECASE))
    line = _line_of(source, m.group(0))
    kind = "credential" if sensitive else "database"
    return asset_node(
        f"{table} table", file, line, kind,
        description=f"database table `{table}` (sensitive columns: {sensitive})",
    )


def detect_filesystem_asset(file: str, source: str) -> dict[str, Any] | None:
    if "subprocess" not in source and "shell=True" not in source:
        return None
    line = _line_of(source, "subprocess")
    return asset_node("host filesystem", file, line, "filesystem", description="arbitrary command execution on worker host")


def detect_pii_dict_asset(file: str, source: str) -> dict[str, Any] | None:
    m = re.search(r"^([A-Z_]{3,})\s*=\s*\{[^}]*(email|billing_email|invoice|amount)", source, re.MULTILINE | re.DOTALL | re.IGNORECASE)
    if not m:
        return None
    name = m.group(1)
    line = _line_of(source, name + " =")
    return asset_node(name, file, line, "pii", description=f"PII/financial record store `{name}`")


def detect_agent_and_tool(file: str, source: str) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
    """Detect a tool-calling agent (class with ``self.tools = {...}``) and a
    privileged tool method (opens a file / shells out / makes network calls).
    """
    if "self.tools" not in source and "self.tools =" not in source:
        return None, None
    cls = re.search(r"class\s+([A-Za-z_][A-Za-z0-9_]*)", source)
    agent_name = cls.group(1) if cls else "Agent"
    agent_line = _line_of(source, "self.tools")
    agent = ai_component_node(
        agent_name, file, agent_line,
        description="tool-calling agent: untrusted content concatenated into instruction context (no delimiter/provenance framing)",
    )
    # privileged tool: a method that reads a file / execs / networks. Allow an
    # optional return annotation (``-> str:``) after the parameter list.
    tm = re.search(
        r"def\s+([a-z_][a-z0-9_]*)\s*\([^)]*\)[^\n:]*:\s*\n(?:[^\n]*\n){0,4}?[^\n]*(open\(|subprocess|requests\.)",
        source,
    )
    tool = None
    if tm:
        tname = tm.group(1)
        tline = _line_of(source, f"def {tname}")
        tool = tool_node(
            tname, file, tline, privileged=True,
            description="privileged tool reachable from model output: no path allowlist, no human-confirmation gate",
        )
    return agent, tool
