#!/bin/zsh
set -euo pipefail
DIR="$(cd "$(dirname "$0")" && pwd)"
NAME="${1:-mcp-firewall-fs}"
codex mcp remove "mcp-direct-fs" >/dev/null 2>&1 || true
codex mcp remove "mcp-firewall-fs" >/dev/null 2>&1 || true
codex mcp remove "${NAME}" >/dev/null 2>&1 || true
codex mcp add "${NAME}" -- "${DIR}/run.sh"
echo "Configured Codex MCP server: ${NAME}"
echo "Other demo MCP servers were removed to avoid routing requests to the wrong server."
