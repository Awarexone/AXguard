#!/usr/bin/env bash
# Remove AXguard skills/commands from agent harnesses.

set -euo pipefail

AGENT="${AXGUARD_AGENT:-claude}"
SCOPE="global"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

SKILLS=(
  axguard-audit axguard-preship axguard-cso axguard-triage axguard-remediate axguard-report axguard-knowledge
  threat-modeling attack-surface-mapping security-architecture-review
  authentication-analysis authorization-analysis session-security jwt-security oauth-security
  api-security sql-injection xss-analysis ssrf-analysis ssti-analysis command-injection
  path-traversal file-upload-security deserialization-security prototype-pollution
  graphql-security websocket-security
  secrets-detection cloud-security configuration-security supply-chain-security
  ai-application-security prompt-injection ai-agent-security mcp-security
  security-triage security-remediation
)
COMMANDS=(
  axguard-audit.md axguard-scan.md axguard-surface.md axguard-flow.md axguard-verify.md axguard-adversary.md axguard-secrets.md axguard-auth.md
  axguard-inject.md axguard-ssrf.md axguard-xss.md axguard-cloud.md
  axguard-agent.md axguard-sql.md axguard-ssti.md axguard-path.md
  axguard-crypto.md axguard-supply.md axguard-graphql.md axguard-upload.md
  axguard-debug.md axguard-threat-model.md axguard-triage.md axguard-fix.md
  axguard-report.md axguard-ci.md
)

while [ "$#" -gt 0 ]; do
  case "$1" in
    --agent) shift; AGENT="${1:?}" ;;
    --agent=*) AGENT="${1#*=}" ;;
    --global) SCOPE="global" ;;
    --project) SCOPE="project" ;;
    -h|--help)
      echo "Usage: ./uninstall.sh [--agent claude|cursor|opencode|codex|agents|all] [--global|--project]"
      exit 0
      ;;
    *) echo "Unknown option: $1" >&2; exit 2 ;;
  esac
  shift
done

remove_named() {
  local dest="$1"
  shift
  local name
  for name in "$@"; do
    if [ -e "$dest/$name" ]; then
      rm -rf "$dest/$name"
      echo "removed $dest/$name"
    fi
  done
}

do_pair() {
  local root_skills="$1"
  local root_commands="$2"
  remove_named "$root_skills" "${SKILLS[@]}"
  remove_named "$root_commands" "${COMMANDS[@]}"
}

do_claude() {
  local root; if [ "$SCOPE" = "project" ]; then root=".claude"; else root="$HOME/.claude"; fi
  do_pair "$root/skills" "$root/commands"
}

do_cursor() {
  local root; if [ "$SCOPE" = "project" ]; then root=".cursor"; else root="$HOME/.cursor"; fi
  do_pair "$root/skills" "$root/commands"
}

do_opencode() {
  local root
  if [ "$SCOPE" = "project" ]; then root=".opencode"; else root="${OPENCODE_CONFIG_DIR:-$HOME/.config/opencode}"; fi
  do_pair "$root/skills" "$root/commands"
}

do_codex() {
  local root; if [ "$SCOPE" = "project" ]; then root=".codex"; else root="${CODEX_HOME:-$HOME/.codex}"; fi
  do_pair "$root/skills" "$root/commands"
}

do_agents() {
  local root; if [ "$SCOPE" = "project" ]; then root=".agents"; else root="$HOME/.agents"; fi
  remove_named "$root/skills" "${SKILLS[@]}"
}

case "$AGENT" in
  claude) do_claude ;;
  cursor) do_cursor ;;
  opencode) do_opencode ;;
  codex) do_codex ;;
  agents) do_agents ;;
  all) do_claude; do_cursor; do_opencode; do_codex; do_agents ;;
  *) echo "Unknown agent: $AGENT" >&2; exit 2 ;;
esac
