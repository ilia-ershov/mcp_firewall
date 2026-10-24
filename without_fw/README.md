# Unprotected MCP scenario

This directory holds the unsafe scenario: the MCP client talks to
[`demo_mcp_server.py`](../demo_mcp_server.py) directly, without any filtering
of responses. The backend is scoped to this directory.

From the repository root, run:

```bash
./run_unsafe.sh
```

Then paste the contents of `without_fw/PROMPT.txt` into `ollmcp`.

In this mode the demo credentials, the prompt injections, and the obfuscated
payload all reach the model unfiltered, and `run_command` executes.

`python3 run_demo.py --mode unsafe` shows the same results without an LLM.
