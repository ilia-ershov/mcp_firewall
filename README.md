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

Even the tool list itself reaches the model: a tool description can smuggle in
instructions ("tool poisoning").

MCP Firewall demonstrates a simple defensive position:

> **Inspect tool calls and tool results at the protocol boundary before they
> enter the model context.**

## What the demo proves

The repository contains identical test data in `without_fw/demo_data/` and
`with_fw/demo_data/`:

| File                     | Demonstrated threat                           |
| ------------------------ | --------------------------------------------- |
| `config.env`             | Passwords, tokens, and AWS-style credentials  |
| `secret_data.txt`        | Sensitive application configuration           |
| `attack.txt`             | Prompt injection requesting command execution |
| `notes_for_agent.txt`    | Instructions attempting to redirect the agent |
| `obfuscated_payload.txt` | Encoded and high-entropy content              |

The demo prompt makes five tool calls. Without the firewall the model receives
everything; with it, the same calls end like this:

| # | Call                                              | Unsafe mode                 | Safe mode                   |
| - | ------------------------------------------------- | --------------------------- | --------------------------- |
| 1 | `read_text_file demo_data/config.env`             | credentials returned        | credential values redacted  |
| 2 | `run_command pwd`                                 | command executed            | blocked as a high-risk tool |
| 3 | `read_text_file demo_data/attack.txt`             | injected instructions shown | blocked as prompt injection |
| 4 | `read_text_file demo_data/obfuscated_payload.txt` | encoded blobs shown         | blocked as encoded data     |
| 5 | `read_text_file demo_data/notes_for_agent.txt`    | injected instructions shown | blocked as prompt injection |

`notes_for_agent.txt` also tries to get the agent to read `secret_data.txt`,
whose credentials the firewall redacts as well.

## Architecture

### Backend MCP server

[`demo_mcp_server.py`](demo_mcp_server.py) is a deliberately small MCP server
that implements newline-delimited JSON-RPC over `stdin` and `stdout`.

It exposes three tools:

- `read_text_file` — reads a UTF-8 text file inside the configured root;
- `run_command` — allows only `pwd`, `ls`, and `echo`;
- `list_allowed_directories` — reports the configured root directory.

File access, including the operands of `ls`, is scoped with `realpath` and
`commonpath`, preventing paths and symlinks from escaping the allowed directory.

### Firewall proxy

[`firewall.py`](firewall.py) starts the backend as a child process and proxies
the JSON-RPC stream between the client and server. The proxy:

1. learns the tool registry from `tools/list`, classifies each tool from its
   name and description, and hides tools whose descriptions carry injected
   instructions;
2. answers `tools/call` requests for high-risk or hidden tools itself, so they
   never reach the backend;
3. inspects every string in the results and errors of `tools/call`,
   `resources/read`, and `prompts/get` — text content, embedded resources,
   `structuredContent`, and error messages alike;
4. blocks responses that contain prompt-injection phrases or several encoded
   or high-entropy blobs;
5. redacts credentials (key/value pairs in env, YAML, or JSON form, AWS access
   keys, GitHub and bearer tokens, private keys) and single encoded blobs;
6. drops responses that do not match an outstanding request and forwards only
   the sanitized response.

Blocked calls and responses are replaced with JSON-RPC errors:

| Code     | Meaning                                         |
| -------- | ----------------------------------------------- |
| `-32000` | call to a high-risk or hidden tool              |
| `-32001` | prompt injection in the response                |
| `-32002` | obfuscated or encoded payload in the response   |

The checks are intentionally deterministic and implemented with regular
expressions and a Shannon entropy heuristic, all defined at the top of
`firewall.py`. This keeps every decision observable and makes the project
suitable for security experimentation.

## Live demonstration with Ollama

The recommended client is
[`ollmcp`](https://github.com/jonigl/mcp-client-for-ollama), connected to a
local Ollama model. The client displays tool calls and results in real time,
while its agent loop lets the model continue through multiple MCP calls before
writing a final summary.

### Prerequisites

- macOS, Linux, or another Unix-like environment with `bash`;
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

Both scripts call [`run_ollmcp.sh`](run_ollmcp.sh) (`safe` or `unsafe`), which
is designed for a repeatable demo:

- `llama3.2` is the default model;
- `OLLAMA_MODEL` can select another installed model;
- MCP confirmations are disabled so the sequence runs without interruptions;
- the agent loop allows up to 12 iterations;
- the client configuration lives in a temporary directory that is removed on
  exit, so your own `ollmcp` settings are not touched.

Example:

```bash
OLLAMA_MODEL=llama3.2 ./run_safe.sh
```

## Protocol-only verification

To replay the demo prompt's tool calls without an LLM:

```bash
python3 run_demo.py
```

The harness performs the MCP handshake, issues the same five calls as the
prompts in both scenarios, and prints one line per result:

```text
=== SAFE: client -> firewall.py -> demo_mcp_server.py (root: with_fw/) ===
tools: read_text_file, run_command, list_allowed_directories
1. read_text_file {"path": "demo_data/config.env"}
   result: DB_PASSWORD=[SECURITY_REDACTED_BY_FIREWALL] | AWS_ACCESS_KEY_ID=[SECURITY_REDACTED_BY_FIREWALL]
2. run_command {"command": "pwd"}
   error -32000: Blocked by MCP firewall: tool 'run_command' is classified as high-risk
...
```

Use `--mode unsafe` or `--mode safe` to run a single scenario and `--json` to
print the full JSON-RPC responses. This is useful for quick checks, but it does
not replace the live model demonstration.

Run the MCP processes directly when needed:

```bash
./without_fw/run.sh
./with_fw/run.sh
```

Both processes communicate through standard input and output.

## Tests

The test suite uses only the Python standard library:

```bash
python3 -m unittest
```

It covers the firewall policy (including false-positive guards), message
routing, the stdio transport, the backend server, both demo scenarios end to
end, and the `ollmcp` launchers (against a stand-in `ollmcp`). It also keeps
the prompts, the replayed steps, and the two `demo_data/` copies in sync.

## Repository layout

```text
demo_mcp_server.py  Minimal backend MCP server
firewall.py         JSON-RPC proxy and security policy
run_demo.py         Protocol-only replay of the demo prompt
run_ollmcp.sh       Ollama + ollmcp launcher (safe | unsafe)
run_unsafe.sh       ./run_ollmcp.sh unsafe
run_safe.sh         ./run_ollmcp.sh safe
tests/              unittest suite

without_fw/
  run.sh            MCP entry point: backend only
  PROMPT.txt        Unsafe scenario prompt
  demo_data/        Threat demonstration files

with_fw/
  run.sh            MCP entry point: firewall + backend
  PROMPT.txt        Safe scenario prompt
  demo_data/        Identical threat demonstration files
```

Each scenario directory is also the backend's allowed root, which is why the
code lives outside them: the model cannot read the firewall's rules.

## Limitations and possible extensions

The firewall uses transparent, rule-based checks. That makes the prototype
easy to understand, but it also means that:

- detection is heuristic: paraphrased injections and short or cleverly encoded
  secrets get through, and unusual but harmless content can be blocked;
- tool risk is inferred from keywords in tool names and descriptions;
- only the results of `tools/call`, `resources/read`, and `prompts/get` are
  inspected; server-initiated requests and notifications (such as sampling or
  logging) and the `initialize` result are forwarded unchanged.

Real deployments would need stronger controls such as capability-based
authorization, structured content policies, secret managers, process
isolation, audit logging, and adversarial evaluation.

Natural next steps would include:

- structured allow/deny policies per tool and argument;
- explicit secret-provider integration instead of regex-only detection;
- a larger corpus of false-positive and false-negative cases;
- inspection of server-initiated requests such as sampling;
- signed or authenticated MCP server identities;
- metrics and audit events for blocked requests;
- transport support beyond local stdio.

## License

This repository is intended as a personal educational and portfolio project.
