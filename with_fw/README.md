# Protected MCP scenario

This directory holds the safe scenario: [`firewall.py`](../firewall.py) sits
between the MCP client and [`demo_mcp_server.py`](../demo_mcp_server.py), and
the backend is scoped to this directory.

From the repository root, run:

```bash
./run_safe.sh
```

Then paste the contents of `with_fw/PROMPT.txt` into `ollmcp`.

Expected behavior:

- the credentials in `config.env` reach the model only as
  `[SECURITY_REDACTED_BY_FIREWALL]`;
- `run_command` is blocked as a high-risk tool;
- `attack.txt` and `notes_for_agent.txt` are blocked as prompt injection;
- `obfuscated_payload.txt` is blocked as encoded data.

`python3 run_demo.py --mode safe` shows the same results without an LLM.
