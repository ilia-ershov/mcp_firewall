# Unprotected MCP scenario

Этот каталог содержит unsafe-сценарий: MCP-клиент подключается к backend
серверу напрямую, без фильтрации ответов.

Из корня проекта запускай:

```bash
./run_unsafe.sh
```

Затем вставь содержимое `without_fw/PROMPT.txt` в `ollmcp`.

В этом режиме демонстрационные секреты, prompt injection и obfuscated payload
возвращаются клиенту без firewall-проверки.
