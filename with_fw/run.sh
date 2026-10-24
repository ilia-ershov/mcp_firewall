#!/bin/zsh
set -euo pipefail
DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "${DIR}/.." && pwd)"
exec python3 "${ROOT}/firewall.py" python3 "${ROOT}/demo_mcp_server.py" "${DIR}"
