---
name: command-injection
description: Analyze OS command and shell injection in application code — use when reviewing subprocess, exec, system, shell=True, or user-influenced shell strings (CWE-78 / CWE-77 / A03:2021).
version: "1.0.0"
author: AwareXone
license: MIT
domain: application-security
subcategory: injection
tags: [command-injection, rce, shell, cwe-78]
frameworks:
  cwe: [CWE-78, CWE-77]
  owasp_top10: [A03:2021]
  owasp_api_top10: []
  owasp_llm_top10: []
  owasp_wstg: []
  owasp_asvs: []
  mitre_attack: []
  mitre_atlas: []
  nist_csf: []
  nist_ai_rmf: []
related_skills: [ssti-analysis, path-traversal, file-upload-security, deserialization-security, security-triage, security-remediation]
related_commands: [/axguard-inject, /axguard-audit, /axguard-scan]
related_rules: [injection.]
references:
  - https://owasp.org/Top10/A03_2021-Injection/
  - https://cwe.mitre.org/data/definitions/78.html
  - https://cwe.mitre.org/data/definitions/77.html
last_reviewed: "2026-09-15"
---

# Command Injection Analysis

## Purpose

Teach defensive analysis of **OS command injection** and unsafe shell invocation: untrusted input alters the command line interpreted by a shell or exec API, yielding RCE on the application host.

## When to Use / When Not to Use

**Use when:**

- Code uses `os.system`, `subprocess` with `shell=True`, `exec`/`spawn` with string commands, `Runtime.exec`, backticks, `child_process.exec`, CI hooks, image/ffmpeg wrappers, ping/traceroute utilities.
- After AXguard hits `injection.*` shell/exec rules.
- Agent/tool runners execute model-suggested shell commands (`/axguard-agent` adjacency).

**Do not use when:**

- Process APIs use fixed argv arrays with no shell and no user-controlled binary path (still review path traversal on filenames separately).
- Pure in-process `eval` of language code (different skill / `injection.python-eval` class — still injection, but not OS command).

## Security Concepts

Shell metacharacters (`|;$&\`\n`) change command **structure**. Argument arrays avoid the shell; they do not fix a user-controlled **executable path** or unsafe flags. `shell=False` + argv is the default safe pattern when an external binary is required.

## Threat Model

Attacker goals:

1. Execute arbitrary OS commands as the app user.
2. Read secrets, pivot laterally, install persistence.
3. Abuse privileged wrappers (sudoers, setuid helpers, container breakout via mounts).

## Analysis Workflow

1. Find sinks: `system`, `popen`, `subprocess.*`, `exec(`, `spawn(`, `Runtime.exec`, `ProcessBuilder` with concatenated strings.
2. Determine if a **shell** is involved (`shell=True`, `/bin/sh -c`, string form of `exec`).
3. Trace attacker influence on command string, argv elements, env, or cwd.
4. Check whether “sanitization” is denylist-based (usually insufficient) vs allowlisted tokens.
5. Confirm whether the binary itself is fixed or user-selectable.
6. Assess runtime privileges (container root, cloud role, access to secrets mounts).
7. For AI agents: treat model/tool output as untrusted input to the same sinks.

## Evidence Requirements

- Sink location and shell vs argv mode
- Source of taint into command/args
- Missing allowlist or unsafe concatenation
- Privilege/impact context of the process

## False Positive Controls

- Hard-coded argv, no user influence
- Validated allowlist of subcommands/flags mapped server-side
- Library wrappers that only accept typed enums
- Test harnesses intentionally calling shells on fixtures

## Remediation

1. Prefer native libraries over shelling out.
2. Use argv arrays; never `shell=True` with untrusted data.
3. Allowlist executables and arguments; reject metacharacters by refusing shell entirely.
4. Drop privileges; isolate in a locked-down worker/container.
5. For agents: require human approval / strict tool allowlists for shell tools.

## Verification

```text
Detect shell sinks → Convert to argv/allowlist → Re-run axguard → Confirm no string-built shell calls remain
```

## Related Skills

- `ssti-analysis`, `deserialization-security` — alternate RCE classes
- `path-traversal`, `file-upload-security` — often chained into command tools
- `security-triage`, `security-remediation`

## Framework Mapping

- CWE-78 (OS Command Injection), CWE-77 (Command Injection)
- OWASP Top 10 2021 A03:2021 Injection

## References

- https://owasp.org/Top10/A03_2021-Injection/
- https://cwe.mitre.org/data/definitions/78.html
- https://cwe.mitre.org/data/definitions/77.html

## Research Provenance

Primary sources:

- OWASP Top 10:2021 A03 (accessed 2026-09-15)
- CWE-78, CWE-77 (accessed 2026-09-15)

Secondary / internal:

- AXGuard `rules/injection.json`, `/axguard-inject`
- AwareXone Agentic-Bug-Hunter command-injection methodology (concepts only; not copied)

Datasets:

- UVID HF dataset — category linkage concepts only (MIT license metadata review 2026-09-15)
