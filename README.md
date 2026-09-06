# MCP Firewall

### A transparent security boundary for Model Context Protocol tools

MCP Firewall is a small, reproducible security demonstration showing how
untrusted MCP tool output can influence an LLM — and how a protocol-aware
firewall can inspect and stop that output before it reaches the model.

The project compares two identical MCP workflows:

```text
UNSAFE  ollmcp → Ollama → MCP server
SAFE    ollmcp → Ollama → firewall proxy → MCP server
```

The model, prompt, backend server, and test data remain the same in both
scenarios. The only difference is the presence of the firewall. This makes the
security boundary visible and easy to reproduce.

## Why this project exists

MCP gives language models access to external tools, files, and services. That
capability is powerful, but tool results should not automatically be treated as
trusted instructions. A file returned by an MCP server may contain:

- prompt injection;
- credentials or tokens;
- encoded payloads;
- instructions to invoke additional high-risk tools.

MCP Firewall demonstrates a simple defensive position:

> **Inspect tool calls and tool results at the protocol boundary before they
> enter the model context.**

## What the demo proves

The repository contains matching test data in `without_fw/demo_data/` and
`with_fw/demo_data/`:


| File                     | Demonstrated threat                           |
| ------------------------ | --------------------------------------------- |
| `config.env`             | Passwords, tokens, and AWS-style credentials  |
| `secret_data.txt`        | Sensitive application configuration           |
| `attack.txt`             | Prompt injection requesting command execution |
| `notes_for_agent.txt`    | Instructions attempting to redirect the agent |
| `obfuscated_payload.txt` | Encoded and high-entropy content              |

In **unsafe mode**, the backend response is returned directly to the MCP
client. The model can see the file contents and may decide to follow the
embedded instructions.

In **safe mode**, the firewall:

- blocks high-risk tools such as `run_command`;
- detects prompt-injection phrases;
- redacts values that look like secrets;
- blocks suspicious encoded or high-entropy payloads;
- returns an MCP error instead of forwarding a blocked result.

## Architecture

### Backend MCP server

[`demo_mcp_server.py`](demo_mcp_server.py) is a deliberately small MCP server
that implements JSON-RPC over `stdin` and `stdout`.

It exposes three tools:

- `read_text_file` — reads a text file inside the configured root;
- `run_command` — allows only `pwd`, `ls`, and `echo`;
- `list_allowed_directories` — reports the configured root directory.

File access is scoped with `realpath` and `commonpath`, preventing paths from
escaping the allowed directory.

### Firewall proxy

[`with_fw/firewall.py`](with_fw/firewall.py) starts the backend as a child
process and proxies the JSON-RPC stream between the client and server.

The proxy:

1. captures the tool registry from `tools/list`;
2. classifies tools from their names and descriptions;
3. blocks high-risk `tools/call` requests before they reach the backend;
4. scans textual and structured tool results;
5. blocks prompt injection and suspicious encoded content;
6. redacts detected secrets;
7. forwards only the sanitized response.

The checks are intentionally deterministic and implemented with regular
expressions and Shannon entropy calculations. This keeps the behavior
observable and makes the project suitable for security experimentation.

## Live demonstration with Ollama

The recommended client is
[`ollmcp`](https://github.com/jonigl/mcp-client-for-ollama), connected to a
local Ollama model. The client displays tool calls and results in real time,
while its agent loop lets the model continue through multiple MCP calls before
writing a final summary.

### Prerequisites

- macOS, Linux, or another Unix-like environment;
- Python 3.11+;
- [Ollama](https://ollama.com/download);
- an Ollama model with tool-calling support;
- `ollmcp`.

Install a lightweight local model:

```bash
ollama pull llama3.2
```

Install the client:

```bash
python3 -m pip install --upgrade ollmcp
```

Alternatively, install `uv`; the launcher scripts automatically fall back to
`uvx ollmcp` when `ollmcp` is not installed globally:

```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
```

### Run the unsafe scenario

From the repository root:

```bash
./run_unsafe.sh
```

Paste the contents of [`without_fw/PROMPT.txt`](without_fw/PROMPT.txt) into
the client. The model will call the backend directly and report what it could
read or execute.

### Run the protected scenario

Exit the previous session and run:

```bash
./run_safe.sh
```

Paste the contents of [`with_fw/PROMPT.txt`](with_fw/PROMPT.txt). The same
workflow now passes through the firewall, so blocked calls and sanitized
responses become visible in the terminal.

The launchers are designed for a repeatable demo:

- `llama3.2` is the default model;
- `OLLAMA_MODEL` can select another installed model;
- MCP confirmations are disabled so the sequence runs without interruptions;
- the agent loop allows up to 12 iterations;
- temporary client configuration is isolated and removed on exit.

Example:

```bash
OLLAMA_MODEL=llama3.2 ./run_safe.sh
```

## Protocol-only verification

To test the MCP transport and firewall without an LLM:

```bash
python3 run_demo.py --mode both
```

This harness sends JSON-RPC requests directly and prints the contrast between
unsafe responses and firewall decisions. It is useful for quick regression
checks, but it does not replace the live model demonstration.

Run the MCP processes directly when needed:

```bash
./without_fw/run.sh
./with_fw/run.sh
```

Both processes communicate through standard input and output.

## Validation

There is no separate build system or test framework. The project uses small,
targeted checks appropriate for a protocol demonstration:

```bash
zsh -n run_unsafe.sh run_safe.sh with_fw/run.sh without_fw/run.sh
python3 -m py_compile demo_mcp_server.py with_fw/firewall.py run_demo.py
python3 run_demo.py --mode both
```

## Repository layout

```text
demo_mcp_server.py  Minimal backend MCP server
run_demo.py         Protocol-only regression harness
run_unsafe.sh       Ollama + ollmcp without the firewall
run_safe.sh         Ollama + ollmcp through the firewall

without_fw/
  run.sh            Direct backend launcher
  PROMPT.txt        Unsafe scenario prompt
  demo_data/        Threat demonstration files

with_fw/
  firewall.py       JSON-RPC proxy and security filters
  run.sh            Firewall + backend launcher
  PROMPT.txt        Safe scenario prompt
  demo_data/        Matching threat demonstration files
```

## Limitations and possible extensions

The firewall uses transparent, rule-based checks. That makes the prototype
easy to understand, but real deployments would need stronger controls such as
capability-based authorization, structured content policies, secret managers,
process isolation, audit logging, and adversarial evaluation.

Natural next steps would include:

- structured allow/deny policies per tool and argument;
- explicit secret-provider integration instead of regex-only detection;
- a test matrix for false positives and false negatives;
- signed or authenticated MCP server identities;
- metrics and audit events for blocked requests;
- transport support beyond local stdio.

## License

This repository is intended as a personal educational and portfolio project.
