# Protected MCP scenario

Этот каталог содержит safe-сценарий: `firewall.py` стоит между MCP-клиентом
и `demo_mcp_server.py`.

Из корня проекта запускай:

```bash
./run_safe.sh
```

Затем вставь содержимое `with_fw/PROMPT.txt` в `ollmcp`.

Ожидаемое поведение:

- `run_command` блокируется как high-risk tool;
- `attack.txt` и `notes_for_agent.txt` блокируются из-за prompt injection;
- `obfuscated_payload.txt` блокируется;
- чувствительные значения не должны передаваться модели.
