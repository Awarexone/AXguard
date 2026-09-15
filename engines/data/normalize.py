"""Normalize examples into AXGuard canonical shapes."""

from __future__ import annotations

import re
from typing import Any

_CWE_RE = re.compile(r"CWE-?(\d+)", re.I)

_VULN_ALIASES = {
    "sqli": "sql-injection",
    "sql injection": "sql-injection",
    "sql_injection": "sql-injection",
    "xss": "xss",
    "cross-site scripting": "xss",
    "ssrf": "ssrf",
    "command injection": "command-injection",
    "cmdi": "command-injection",
    "path traversal": "path-traversal",
    "lfi": "path-traversal",
    "rce": "command-injection",
    "prompt injection": "prompt-injection",
    "bola": "broken-object-level-authz",
    "idor": "broken-object-level-authz",
}

_LANG_ALIASES = {
    "py": "python",
    "python3": "python",
    "js": "javascript",
    "node": "javascript",
    "ts": "typescript",
    "golang": "go",
}


def normalize_cwe(raw: str | None) -> str | None:
    if not raw:
        return None
    m = _CWE_RE.search(str(raw))
    if not m:
        return None
    return f"CWE-{int(m.group(1))}"


def normalize_vuln_type(raw: str | None) -> str:
    text = str(raw or "").strip().lower().replace("_", "-")
    return _VULN_ALIASES.get(text, text or "unknown")


def normalize_language(raw: str | None) -> str:
    text = str(raw or "").strip().lower()
    return _LANG_ALIASES.get(text, text or "unknown")


def normalize_vulnerability_example(raw: dict[str, Any]) -> dict[str, Any]:
    return {
        "example_id": raw.get("example_id") or raw.get("id") or "unknown",
        "language": normalize_language(raw.get("language")),
        "framework": str(raw.get("framework") or "unknown").lower(),
        "code": str(raw.get("code") or ""),
        "vulnerable": bool(raw.get("vulnerable", True)),
        "vulnerability_type": normalize_vuln_type(
            raw.get("vulnerability_type") or raw.get("vuln") or raw.get("type")
        ),
        "cwe": normalize_cwe(raw.get("cwe")),
        "owasp": raw.get("owasp"),
        "evidence": list(raw.get("evidence") or []),
        "root_cause": raw.get("root_cause"),
        "fix": raw.get("fix"),
        "source": raw.get("source") or "synthetic",
        "kind": "CODE_VULNERABILITY",
    }


def normalize_fp_example(raw: dict[str, Any]) -> dict[str, Any]:
    return {
        "example_id": raw.get("example_id") or raw.get("id") or "unknown",
        "candidate": dict(raw.get("candidate") or {}),
        "evidence": list(raw.get("evidence") or []),
        "counter_evidence": list(raw.get("counter_evidence") or []),
        "controls": list(raw.get("controls") or []),
        "data_flow": list(raw.get("data_flow") or []),
        "unknowns": list(raw.get("unknowns") or []),
        "verdict": str(raw.get("verdict") or "FALSE_POSITIVE"),
        "reason": str(raw.get("reason") or "INSUFFICIENT_EVIDENCE"),
        "confidence": str(raw.get("confidence") or "HIGH"),
        "kind": "FALSE_POSITIVE",
        "source": raw.get("source") or "synthetic",
    }


def normalize_attack_path_example(raw: dict[str, Any]) -> dict[str, Any]:
    return {
        "example_id": raw.get("example_id") or raw.get("id") or "unknown",
        "entry_point": raw.get("entry_point") or "INTERNET",
        "steps": list(raw.get("steps") or []),
        "status": str(raw.get("status") or "UNKNOWN"),
        "impact": raw.get("impact") or "UNKNOWN",
        "kind": "ATTACK_CHAIN",
        "source": raw.get("source") or "synthetic",
    }


def normalize_ai_security_example(raw: dict[str, Any]) -> dict[str, Any]:
    return {
        "example_id": raw.get("example_id") or raw.get("id") or "unknown",
        "label": str(raw.get("label") or "UNKNOWN").upper(),  # BENIGN | MALICIOUS
        "category": str(raw.get("category") or "PROMPT_INJECTION"),
        "prompt": str(raw.get("prompt") or raw.get("input") or ""),
        "context": raw.get("context"),
        "expected_behavior": raw.get("expected_behavior"),
        "kind": "AI_SECURITY",
        "source": raw.get("source") or "synthetic",
    }


def normalize_example(raw: dict[str, Any]) -> dict[str, Any]:
    kind = str(raw.get("kind") or raw.get("type") or "").upper()
    if kind in {"FALSE_POSITIVE", "FP"} or "verdict" in raw:
        return normalize_fp_example(raw)
    if kind in {"ATTACK_CHAIN", "ATTACK_PATH", "ATTACK_GRAPH"} or "steps" in raw:
        return normalize_attack_path_example(raw)
    if kind in {"AI_SECURITY", "PROMPT_INJECTION"} or "label" in raw:
        return normalize_ai_security_example(raw)
    return normalize_vulnerability_example(raw)
