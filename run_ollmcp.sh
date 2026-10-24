#!/usr/bin/env bash
# Live demo: ollmcp + a local Ollama model connected to the demo MCP server,
# either directly (unsafe) or through the firewall (safe).
#
# Usage: ./run_ollmcp.sh safe|unsafe    (OLLAMA_MODEL selects the model, default llama3.2)
set -euo pipefail

case "${1:-}" in
    safe) SCENARIO_DIR=with_fw ;;
    unsafe) SCENARIO_DIR=without_fw ;;
    *) echo "Usage: $0 safe|unsafe" >&2; exit 2 ;;
esac

ROOT="$(cd "$(dirname "$0")" && pwd)"
MODEL="${OLLAMA_MODEL:-llama3.2}"

if command -v ollmcp >/dev/null 2>&1; then
    MCP_CLI=(ollmcp)
elif command -v uvx >/dev/null 2>&1; then
    MCP_CLI=(uvx ollmcp)
    # HOME is replaced below; keep uv's cache in the real one so that ollmcp is not
    # downloaded again on every run.
    export UV_CACHE_DIR="${UV_CACHE_DIR:-${XDG_CACHE_HOME:-$HOME/.cache}/uv}"
else
    echo "Install ollmcp with 'python3 -m pip install ollmcp' or install uv/uvx." >&2
    exit 1
fi

# Isolated client configuration, removed on exit.
STATE="$(mktemp -d "${TMPDIR:-/tmp}/mcp-firewall-$1.XXXXXX")"
trap 'rm -rf "$STATE"' EXIT
mkdir -p "$STATE/home/.config/ollmcp"

python3 - "$STATE" "$ROOT/$SCENARIO_DIR/run.sh" "$MODEL" <<'PY'
import json
import sys

state, server_script, model = sys.argv[1:]
servers = {"mcpServers": {"demo": {"command": "bash", "args": [server_script]}}}
client = {
    "defaultProvider": "ollama",
    "providers": {"ollama": {"host": "http://localhost:11434", "model": model, "apiKey": ""}},
    "agentSettings": {"loopLimit": 12},
    "hilSettings": {"enabled": False},
    "displaySettings": {"showToolExecution": True, "showMetrics": False, "answerRenderMode": "plain"},
}
for path, config in ((f"{state}/servers.json", servers), (f"{state}/home/.config/ollmcp/config.json", client)):
    with open(path, "w", encoding="utf-8") as config_file:
        json.dump(config, config_file)
PY

cd "$STATE"
# Not `exec`: the EXIT trap has to run afterwards to remove $STATE.
HOME="$STATE/home" "${MCP_CLI[@]}" --servers-json "$STATE/servers.json" --provider ollama --model "$MODEL"
