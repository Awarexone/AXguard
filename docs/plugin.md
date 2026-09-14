# Plugin & skills

AXguard installs into coding-agent harnesses the same way AwareXone’s Agentic Bug Hunter does: copy `skills/` and `commands/` into the harness config dir.

## Install targets

| `--agent` | Global root | Project root |
|---|---|---|
| `claude` | `~/.claude` | `.claude` |
| `cursor` | `~/.cursor` | `.cursor` |
| `opencode` | `~/.config/opencode` | `.opencode` |
| `codex` | `~/.codex` | `.codex` |
| `agents` | `~/.agents` | `.agents` (skills only) |
| `all` | all of the above | — |

```bash
./install.sh --agent claude
./install.sh --agent cursor --project
./install.sh --agent all
./uninstall.sh --agent cursor
```

Manifest: `.claude-plugin/plugin.json`

## Layout expectations

```text
skills/axguard-audit/SKILL.md
skills/axguard-cso/SKILL.md
…
commands/axguard-audit.md
commands/axguard-scan.md
…
```

Claude Code / Cursor expose `commands/*.md` as slash commands (`/axguard-audit`). Skills load by description match or explicit invoke.

## Authoring rules

1. **Command** — steps an agent can follow without guessing (exact CLI, paths, outputs).  
2. **Skill** — `description` must include trigger phrases (“pre-ship”, “audit”, “IDOR”, …).  
3. Keep specialist names stable (Pre-ship Lead, CSO, Triage, …) — they appear in the README catalog.  
4. When adding/removing installable names, update arrays in `uninstall.sh`.

## Local verify

```bash
./install.sh --agent cursor --project
# In Cursor/Claude: /axguard-help via asking for axguard audit, or run:
axguard audit . --out-dir .findings/axguard
ls .findings/axguard/
```

## Relationship to CLI

The plugin does not reimplement scanning. It routes the agent to `axguard scan` / `axguard audit` and then enforces triage/fix/report discipline.
