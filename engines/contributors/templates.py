"""Contribution templates — concrete stubs, no hype."""

from __future__ import annotations

from typing import Any

from engines.contributors.schema import (
    TYPE_ATTACK_PATH_PATTERN,
    TYPE_BUG_FIX,
    TYPE_DOCUMENTATION,
    TYPE_DX,
    TYPE_FALSE_POSITIVE_FIX,
    TYPE_FRAMEWORK_SUPPORT,
    TYPE_LABELS,
    TYPE_MCP_SECURITY_CASE,
    TYPE_PERFORMANCE,
    TYPE_REGRESSION_TEST,
    TYPE_SECURITY_RULE,
    TYPE_SYNTHETIC_SECURITY_CASE,
)

TEMPLATES: dict[str, dict[str, Any]] = {
    TYPE_BUG_FIX: {
        "title": "Bug Fix",
        "files": {
            "README.md": (
                "# Bug Fix contribution\n\n"
                "## What broke\n\nDescribe the incorrect behavior.\n\n"
                "## Root cause\n\nShort technical note.\n\n"
                "## Fix\n\nWhat changed and why it is safe.\n\n"
                "## Test plan\n\n- [ ] Repro before fix\n- [ ] Pass after fix\n"
            ),
            "COMMIT_MSG.txt": "fix: describe the bug and the safe correction.\n",
            "PR_DRAFT.md": (
                "## Summary\n- Fixes <behavior>\n\n"
                "## Test plan\n- [ ] Unit / regression coverage\n"
            ),
        },
    },
    TYPE_SECURITY_RULE: {
        "title": "Security Rule",
        "files": {
            "README.md": (
                "# Security Rule contribution\n\n"
                "## Pattern\n\nWhat the rule should detect.\n\n"
                "## False positive notes\n\nWhen it must stay quiet.\n\n"
                "## Fixtures\n\nAdd positive and negative examples under `fixtures/`.\n"
            ),
            "rule.yaml.stub": (
                "id: AXG-TODO\n"
                "severity: medium\n"
                "title: TODO\n"
                "description: TODO\n"
                "patterns:\n  - TODO\n"
            ),
            "COMMIT_MSG.txt": "rules: add detection for <pattern>.\n",
            "PR_DRAFT.md": (
                "## Summary\n- Adds rule for <pattern>\n\n"
                "## Test plan\n- [ ] Positive fixture hits\n- [ ] Negative fixture stays clean\n"
            ),
        },
    },
    TYPE_REGRESSION_TEST: {
        "title": "Regression Test",
        "files": {
            "README.md": (
                "# Regression Test contribution\n\n"
                "## Failure mode\n\nWhat regressed.\n\n"
                "## Fixture\n\nMinimal case under `fixtures/`.\n"
            ),
            "test_regression.py.stub": (
                "\"\"\"Regression coverage for <case>.\"\"\"\n\n"
                "def test_regression_case():\n"
                "    assert True  # replace with real assertion\n"
            ),
            "COMMIT_MSG.txt": "test: add regression coverage for <case>.\n",
            "PR_DRAFT.md": (
                "## Summary\n- Adds regression test for <case>\n\n"
                "## Test plan\n- [ ] Fails without the fix\n- [ ] Passes with the fix\n"
            ),
        },
    },
    TYPE_FALSE_POSITIVE_FIX: {
        "title": "False Positive Fix",
        "files": {
            "README.md": (
                "# False Positive Fix contribution\n\n"
                "## Why it looked dangerous\n\n"
                "## Control that made it safe\n\n"
                "## Proposed change\n\nRule / adversary / corpus update.\n"
            ),
            "fp_case.json.stub": (
                "{\n"
                '  "status": "FALSE_POSITIVE",\n'
                '  "reason": "TODO",\n'
                '  "control": "TODO"\n'
                "}\n"
            ),
            "COMMIT_MSG.txt": "fix(fp): stop reporting safe <pattern>.\n",
            "PR_DRAFT.md": (
                "## Summary\n- Documents / fixes a false positive\n\n"
                "## Test plan\n- [ ] Case stays rejected\n"
            ),
        },
    },
    TYPE_FRAMEWORK_SUPPORT: {
        "title": "Framework Support",
        "files": {
            "README.md": (
                "# Framework Support contribution\n\n"
                "## Framework\n\n## Entry points / sinks observed\n\n"
                "## Adapter notes\n"
            ),
            "COMMIT_MSG.txt": "feat: add support for <framework>.\n",
            "PR_DRAFT.md": (
                "## Summary\n- Framework support for <name>\n\n"
                "## Test plan\n- [ ] Surface / flow fixtures\n"
            ),
        },
    },
    TYPE_ATTACK_PATH_PATTERN: {
        "title": "Attack Path Pattern",
        "files": {
            "README.md": (
                "# Attack Path Pattern contribution\n\n"
                "## Chain\n\nSource → steps → sink\n\n"
                "## Evidence that confirmed it\n"
            ),
            "path_pattern.json.stub": (
                "{\n"
                '  "source": "TODO",\n'
                '  "steps": [],\n'
                '  "sink": "TODO"\n'
                "}\n"
            ),
            "COMMIT_MSG.txt": "docs/patterns: capture attack path <name>.\n",
            "PR_DRAFT.md": (
                "## Summary\n- Captures a confirmed attack-path pattern\n\n"
                "## Test plan\n- [ ] Pattern reproduces on fixture\n"
            ),
        },
    },
    TYPE_SYNTHETIC_SECURITY_CASE: {
        "title": "Synthetic Security Case",
        "files": {
            "README.md": (
                "# Synthetic Security Case\n\n"
                "Opt-in learning pack only. No private customer code.\n\n"
                "## Intended lesson\n"
            ),
            "case.json.stub": "{\n  \"category\": \"TODO\",\n  \"expected\": \"TODO\"\n}\n",
            "COMMIT_MSG.txt": "data: add synthetic security case <name>.\n",
            "PR_DRAFT.md": (
                "## Summary\n- Synthetic case for evaluation / research\n\n"
                "## Test plan\n- [ ] Scrubbed\n- [ ] License-safe\n"
            ),
        },
    },
    TYPE_MCP_SECURITY_CASE: {
        "title": "MCP Security Case",
        "files": {
            "README.md": (
                "# MCP Security Case\n\n"
                "## Tool / resource surface\n\n## Risk\n\n## Expected control\n"
            ),
            "mcp_case.json.stub": (
                "{\n"
                '  "surface": "TODO",\n'
                '  "risk": "TODO",\n'
                '  "control": "TODO"\n'
                "}\n"
            ),
            "COMMIT_MSG.txt": "data: add MCP security case <name>.\n",
            "PR_DRAFT.md": (
                "## Summary\n- MCP security case\n\n"
                "## Test plan\n- [ ] No secrets\n- [ ] Reproducible locally\n"
            ),
        },
    },
    TYPE_DOCUMENTATION: {
        "title": "Documentation",
        "files": {
            "README.md": (
                "# Documentation contribution\n\n"
                "## Audience\n\n## Gap observed\n\n## Proposed page / section\n"
            ),
            "COMMIT_MSG.txt": "docs: clarify <topic>.\n",
            "PR_DRAFT.md": (
                "## Summary\n- Docs update for <topic>\n\n"
                "## Test plan\n- [ ] Links resolve\n"
            ),
        },
    },
    TYPE_PERFORMANCE: {
        "title": "Performance",
        "files": {
            "README.md": (
                "# Performance contribution\n\n"
                "## Slow path observed\n\n## Measurement\n\n## Change\n"
            ),
            "COMMIT_MSG.txt": "perf: improve <path>.\n",
            "PR_DRAFT.md": (
                "## Summary\n- Performance improvement\n\n"
                "## Test plan\n- [ ] Before/after notes\n"
            ),
        },
    },
    TYPE_DX: {
        "title": "Developer Experience",
        "files": {
            "README.md": (
                "# DX contribution\n\n"
                "## Friction observed\n\n## Proposed improvement\n"
            ),
            "COMMIT_MSG.txt": "dx: improve <workflow>.\n",
            "PR_DRAFT.md": (
                "## Summary\n- DX improvement\n\n"
                "## Test plan\n- [ ] Command / docs still work\n"
            ),
        },
    },
}


def list_templates() -> list[dict[str, str]]:
    out = []
    for key, tmpl in TEMPLATES.items():
        out.append(
            {
                "type": key,
                "title": str(tmpl.get("title") or TYPE_LABELS.get(key, key)),
            }
        )
    return out


def get_template(contribution_type: str) -> dict[str, Any] | None:
    if contribution_type in TEMPLATES:
        return dict(TEMPLATES[contribution_type])
    # Aliases
    aliases = {
        "DOCS": TYPE_DOCUMENTATION,
        "TEST": TYPE_REGRESSION_TEST,
        "RULE": TYPE_SECURITY_RULE,
        "NOVEL_FINDING": TYPE_SECURITY_RULE,
        "AI_AGENT": TYPE_MCP_SECURITY_CASE,
    }
    mapped = aliases.get(contribution_type)
    if mapped and mapped in TEMPLATES:
        return dict(TEMPLATES[mapped])
    return None


def render_template_files(
    contribution_type: str,
    *,
    substitutions: dict[str, str] | None = None,
) -> dict[str, str]:
    tmpl = get_template(contribution_type)
    if tmpl is None:
        return {}
    subs = substitutions or {}
    files = dict(tmpl.get("files") or {})
    rendered: dict[str, str] = {}
    for name, body in files.items():
        text = str(body)
        for key, value in subs.items():
            text = text.replace(f"<{key}>", value)
        rendered[name] = text
    return rendered
