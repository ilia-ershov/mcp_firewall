# Copilot instructions for mcp_firewall

## Project purpose

This repository is a minimal demonstration of MCP security boundaries. It compares an unprotected MCP server with the same server behind a firewall proxy that blocks high-risk tools, prompt injection (in tool results and in tool descriptions), and encoded payloads, and redacts secrets before tool output reaches the model.

The root README explains the two scenarios and the `ollmcp` + Ollama
workflow; the per-demo READMEs describe the two demo modes:

- `without_fw/` shows the unprotected server
- `with_fw/` shows the same server behind `firewall.py`

## Commands

There are no third-party dependencies; everything uses the Python standard library.

- Run the test suite (from the repository root):
  - `python3 -m unittest`
- Replay the demo prompt without an LLM:
  - `python3 run_demo.py` (`--mode unsafe|safe|both`, `--json` for full responses)

Run the demonstration flows:

- Real LLM unsafe version:
  - `./run_unsafe.sh`
  - then paste the contents of `without_fw/PROMPT.txt` into `ollmcp`
- Real LLM protected version:
  - `./run_safe.sh`
  - then paste the contents of `with_fw/PROMPT.txt` into `ollmcp`

Direct, protocol-only entry points:

- `python3 demo_mcp_server.py <allowed_root>`
- `python3 firewall.py <server command> [args...]`
- `./without_fw/run.sh`
- `./with_fw/run.sh`

## High-level architecture

- `demo_mcp_server.py` is the backend MCP server. It implements newline-delimited JSON-RPC over stdin/stdout and exposes three tools:
  - `read_text_file`
  - `run_command`
  - `list_allowed_directories`
- The server is intentionally small and path-scoped: it accepts an `allowed_root` directory and blocks access outside it via `os.path.realpath` + `os.path.commonpath`, including the operands of `ls`.
- `run_command` is restricted to a small allowlist (`pwd`, `ls`, `echo`) and runs commands with `subprocess.run` under the allowed root.
- `DemoMCPServer.handle()` processes one message without I/O; `serve()` is the stdio loop.
- `firewall.py` is a proxy placed in front of the backend server. It has two parts:
  - the policy: module-level patterns and functions (`is_high_risk_tool`, `contains_injection`, `redact_secrets`, `looks_encoded`, `sanitize_text`, `sanitize`);
  - `MCPFirewall`: `on_client_message()` / `on_server_message()` route messages without I/O, and `run()` does the stdio transport with a client-reader thread.
- The firewall enforces a few deterministic rules:
  - denies high-risk tool calls before they reach the backend
  - hides tools whose `tools/list` entries contain injected instructions
  - blocks responses with prompt-injection phrases such as "ignore previous instructions"
  - redacts secret values such as `password=...`, `"token": "..."`, and AWS keys, before measuring entropy
  - blocks responses with several high-entropy (base64/hex) blobs and redacts a single one
  - inspects every string of `tools/call`, `resources/read` and `prompts/get` results and errors, and drops responses that match no pending request
- `with_fw/demo_data/` and `without_fw/demo_data/` contain the same malicious or sensitive content, which is the core demonstration payload for comparing protected vs. unprotected behavior. A test keeps the two copies identical.
- The scenario directories are the backend's allowed roots, so code must stay outside them.
- The repo is intentionally a teaching/demo project rather than a reusable library or app. Changes should stay small and obvious.

## Key conventions

- Keep protocol behavior aligned with the JSON-RPC MCP pattern used in `demo_mcp_server.py`; do not add a second transport or wrapper unless the repo specifically needs it.
- When changing tool names or descriptions, keep the firewall's risk classification in sync with `HIGH_RISK_TOOL_KEYWORDS` in `firewall.py`.
- When changing the tool calls in a `PROMPT.txt`, update `PROMPT_STEPS` in `run_demo.py`; a test checks that they match.
- Security checks are intentionally regex-based and deterministic. Do not replace them with broad AI-style heuristics when a rule is already present. Add a test for every new rule, covering both what it must catch and what it must not.
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
- `run_ollmcp.sh safe|unsafe` (wrapped by `run_safe.sh` and `run_unsafe.sh`): creates isolated `ollmcp` server and client configs in a temporary directory, runs the real Ollama-backed agent, and removes the directory on exit.
- `tests/`: stdlib `unittest` suite; `tests/test_demo.py` holds the end-to-end checks.
