# Copilot instructions for mcp_firewall

## Project purpose

This repository is a minimal demonstration of MCP security boundaries. It compares an unsafe filesystem MCP server with a wrapped version that blocks prompt injection, secret leakage, and high-entropy obfuscation before tool output reaches the model.

The root README explains the two scenarios and the `ollmcp` + Ollama
workflow; the per-demo READMEs describe the two demo modes:

- `without_fw/` shows the unprotected filesystem server
- `with_fw/` shows the same server behind `firewall.py`

## Commands

There is no formal build, test, or lint suite in this repo.

Use the minimal validation that matches the project:

- Syntax check the Python entry points:
  - `python3 -m py_compile demo_mcp_server.py with_fw/firewall.py`

Run the demonstration flows:

- Real LLM unsafe version:
  - `./run_unsafe.sh`
  - then paste the contents of `without_fw/PROMPT.txt` into `ollmcp`
- Real LLM protected version:
  - `./run_safe.sh`
  - then paste the contents of `with_fw/PROMPT.txt` into `ollmcp`
- Local protocol-only comparison:
  - `python3 run_demo.py --mode both`

Direct, protocol-only entry points:

- `python3 demo_mcp_server.py <allowed_root>`
- `cd with_fw && ./run.sh`
- `cd without_fw && ./run.sh`

## High-level architecture

- `demo_mcp_server.py` is the backend MCP server. It implements JSON-RPC over stdin/stdout and exposes three tools:
  - `read_text_file`
  - `run_command`
  - `list_allowed_directories`
- The server is intentionally small and path-scoped: it accepts an `allowed_root` directory and blocks access outside it via `os.path.realpath` + `os.path.commonpath`.
- `run_command` is restricted to a small allowlist (`pwd`, `ls`, `echo`) and runs commands with `subprocess.run` under the allowed root.
- `with_fw/firewall.py` is a proxy layer placed in front of the backend server. It reads incoming JSON-RPC messages, captures the tool registry from `tools/list`, and screens tool responses before they reach the client.
- The firewall enforces a few deterministic rules:
  - denies high-risk tool execution before it reaches the backend
  - detects prompt-injection phrases such as “ignore previous instructions” or “system prompt”
  - redacts secret values such as `password=...`, `token=...`, and AWS keys
  - blocks high-entropy or encoded content that looks like obfuscated payloads
- `with_fw/demo_data/` and `without_fw/demo_data/` contain the same malicious or sensitive content, which is the core demonstration payload for comparing protected vs. unprotected behavior.
- The repo is intentionally a teaching/demo project rather than a reusable library or app. Changes should stay small and obvious.

## Key conventions

- Keep protocol behavior aligned with the JSON-RPC MCP pattern used in `demo_mcp_server.py`; do not add a second transport or wrapper unless the repo specifically needs it.
- When changing tool names or descriptions, keep the firewall’s risk classification in sync with `TOOL_RISK_KEYWORDS` and the registry logic in `with_fw/firewall.py`.
- Security checks are intentionally regex-based and deterministic. Do not replace them with broad AI-style heuristics when a rule is already present.
- Path safety is a first-class concern: any new file-access logic should resolve real paths and enforce the allowed-root boundary.
- The important validation cases are the demo files in `demo_data/`:
  - `attack.txt`
  - `notes_for_agent.txt`
  - `obfuscated_payload.txt`
  - `config.env` / `secret_data.txt`

## Repository notes

- Root-level README: overview of the two scenarios and what the repo demonstrates.
- `with_fw/README.md`: short guide to the protected scenario.
- `without_fw/README.md`: short guide to the unprotected scenario.
- `run_unsafe.sh` and `run_safe.sh`: create isolated `ollmcp` server and
  client configs and run the real Ollama-backed agent.
