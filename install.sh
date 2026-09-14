#!/usr/bin/env bash
# Install AXguard skills + commands into coding-agent harnesses.

set -euo pipefail

AGENT="${AXGUARD_AGENT:-claude}"
SCOPE="global"

usage() {
  cat <<'EOF'
Usage: ./install.sh [--agent claude|cursor|opencode|codex|agents|all] [--global|--project]

Defaults:
  ./install.sh                 Install for Claude Code globally (~/.claude)

Examples:
  ./install.sh --agent cursor
  ./install.sh --agent all
  ./install.sh --agent claude --project
EOF
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --agent) shift; AGENT="${1:?--agent requires a value}" ;;
    --agent=*) AGENT="${1#*=}" ;;
    --global) SCOPE="global" ;;
    --project) SCOPE="project" ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown option: $1" >&2; usage >&2; exit 2 ;;
  esac
  shift
done

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

copy_tree_items() {
  local src_glob="$1"
  local dest_dir="$2"
  local label="$3"
  mkdir -p "$dest_dir"
  local item name
  for item in $src_glob; do
    [ -e "$item" ] || continue
    name="$(basename "$item")"
    rm -rf "$dest_dir/$name"
    mkdir -p "$dest_dir/$name"
    cp -R "$item"/. "$dest_dir/$name/"
    echo "installed $label: $name → $dest_dir/$name"
  done
}

copy_files() {
  local src_glob="$1"
  local dest_dir="$2"
  local label="$3"
  mkdir -p "$dest_dir"
  local item name
  for item in $src_glob; do
    [ -f "$item" ] || continue
    name="$(basename "$item")"
    cp "$item" "$dest_dir/$name"
    echo "installed $label: $name → $dest_dir/$name"
  done
}

install_claude() {
  local root
  if [ "$SCOPE" = "project" ]; then root=".claude"; else root="$HOME/.claude"; fi
  echo "AXguard → Claude Code ($SCOPE)"
  copy_tree_items "skills/*" "$root/skills" "skill"
  copy_files "commands/*.md" "$root/commands" "command"
}

install_cursor() {
  local root
  if [ "$SCOPE" = "project" ]; then root=".cursor"; else root="$HOME/.cursor"; fi
  echo "AXguard → Cursor ($SCOPE)"
  copy_tree_items "skills/*" "$root/skills" "skill"
  # Cursor also picks up project rules; commands map to skills for slash-style prompts
  mkdir -p "$root/commands"
  copy_files "commands/*.md" "$root/commands" "command"
}

install_opencode() {
  local root
  if [ "$SCOPE" = "project" ]; then
    root=".opencode"
  else
    root="${OPENCODE_CONFIG_DIR:-$HOME/.config/opencode}"
  fi
  echo "AXguard → OpenCode ($SCOPE)"
  copy_tree_items "skills/*" "$root/skills" "skill"
  copy_files "commands/*.md" "$root/commands" "command"
}

install_codex() {
  local root
  if [ "$SCOPE" = "project" ]; then root=".codex"; else root="${CODEX_HOME:-$HOME/.codex}"; fi
  echo "AXguard → Codex ($SCOPE)"
  copy_tree_items "skills/*" "$root/skills" "skill"
  copy_files "commands/*.md" "$root/commands" "command"
}

install_agents() {
  local root
  if [ "$SCOPE" = "project" ]; then root=".agents"; else root="$HOME/.agents"; fi
  echo "AXguard → shared Agent Skills ($SCOPE)"
  copy_tree_items "skills/*" "$root/skills" "skill"
}

echo ""
cat <<'BANNER'
  ▄▀█ ▀▄▀ █▀▀ █░█ ▄▀█ █▀█ █▀▄
  █▀█ █░█ █▄█ █▄█ █▀█ █▀▄ █▄▀
  install · skills + commands
BANNER
echo ""

case "$AGENT" in
  claude) install_claude ;;
  cursor) install_cursor ;;
  opencode) install_opencode ;;
  codex) install_codex ;;
  agents) install_agents ;;
  all)
    install_claude
    install_cursor
    install_opencode
    install_codex
    install_agents
    ;;
  *)
    echo "Unknown agent: $AGENT" >&2
    usage >&2
    exit 2
    ;;
esac

echo ""
echo "CLI (optional but recommended):"
echo "  python3 -m venv .venv && source .venv/bin/activate"
echo "  pip install -e ."
echo "  axguard help"
echo "  axguard audit ."
echo ""
echo "Start with the workflow you need (not the full catalog):"
echo "  /axguard-audit          full A→Z + HTML/MD reports"
echo "  /axguard-scan           fast check while coding"
echo "  /axguard-threat-model   first look / CSO framing"
echo "  /axguard-triage         kill false positives"
echo "  /axguard-fix            patch confirmed bugs"
echo "  /axguard-ci             PR fail-on-high gate"
echo ""
echo "Cheat sheet: COMMANDS-QUICK-REF.md"
echo ""
