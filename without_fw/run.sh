#!/usr/bin/env bash
# MCP stdio entry point of the unprotected scenario: the backend alone, scoped to
# this directory.
set -euo pipefail
DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(dirname "$DIR")"
exec python3 "$ROOT/demo_mcp_server.py" "$DIR"
