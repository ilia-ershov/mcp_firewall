#!/bin/zsh
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
STATE="$(mktemp -d "${TMPDIR:-/tmp}/mcp-firewall-unsafe.XXXXXX")"
CONFIG="${STATE}/servers.json"
OLLMC_CONFIG="${STATE}/home/.config/ollmcp"
mkdir -p "$OLLMC_CONFIG"
trap 'rm -rf "$STATE"' EXIT

python3 - "$CONFIG" "$ROOT" <<'PY'
import json
import sys

config_path, root = sys.argv[1:]
config = {
    "mcpServers": {
        "demo": {
            "command": "bash",
            "args": [f"{root}/without_fw/run.sh"],
        }
    }
}
with open(config_path, "w", encoding="utf-8") as config_file:
    json.dump(config, config_file)
PY

python3 - "$OLLMC_CONFIG/config.json" "${OLLAMA_MODEL:-llama3.2}" <<'PY'
import json
import sys

config_path, model = sys.argv[1:]
config = {
    "defaultProvider": "ollama",
    "providers": {
        "ollama": {
            "host": "http://localhost:11434",
            "model": model,
            "apiKey": "",
        }
    },
    "agentSettings": {"loopLimit": 12},
    "hilSettings": {"enabled": False},
    "displaySettings": {"showToolExecution": True, "showMetrics": False, "answerRenderMode": "plain"},
}
with open(config_path, "w", encoding="utf-8") as config_file:
    json.dump(config, config_file)
PY

if command -v ollmcp >/dev/null 2>&1; then
    MCP_CLI=(ollmcp)
elif command -v uvx >/dev/null 2>&1; then
    MCP_CLI=(uvx ollmcp)
else
    echo "Install ollmcp with 'python3 -m pip install ollmcp' or install uv/uvx." >&2
    exit 1
fi

export HOME="${STATE}/home"
cd "$STATE"
exec "${MCP_CLI[@]}" \
    --servers-json "$CONFIG" \
    --provider ollama \
    --model "${OLLAMA_MODEL:-llama3.2}"
