#!/bin/zsh
set -euo pipefail
DIR="$(cd "$(dirname "$0")" && pwd)"
exec python3 "${DIR}/firewall.py" python3 "/Users/thomas/MCP_FIREWALL/demo_mcp_server.py" "${DIR}"
