#!/usr/bin/env bash
# Live demo, protected: ollmcp -> Ollama -> firewall.py -> demo_mcp_server.py
exec "$(dirname "$0")/run_ollmcp.sh" safe
