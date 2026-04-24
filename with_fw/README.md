# with_fw

Тут лежит сценарий с firewall для показа через Codex.

Подключение в Codex:

```bash
cd /Users/thomas/MCP_FIREWALL/with_fw
chmod +x *.sh
./setup_codex.sh
codex
```

Потом вставь текст из `PROMPT.txt`.

Что проверять:

- `demo_data/config.env` - ключи должны быть скрыты
- `run_command` - выполнение команды должно блокироваться
- `demo_data/attack.txt` - suspicious content должно блокироваться
- `demo_data/obfuscated_payload.txt` - high-entropy content должно блокироваться
- `demo_data/notes_for_agent.txt` - prompt injection через файл должно блокироваться
