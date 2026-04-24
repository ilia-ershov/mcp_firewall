# without_fw

Тут лежит сценарий без firewall для показа через Codex.

Подключение в Codex:

```bash
cd /Users/thomas/MCP_FIREWALL/without_fw
chmod +x *.sh
./setup_codex.sh
codex
```

Потом вставь текст из `PROMPT.txt`.

Что проверять:

- `demo_data/config.env` - ключи видны
- `run_command` - выполнение команды разрешено
- `demo_data/attack.txt` - suspicious content читается
- `demo_data/obfuscated_payload.txt` - obfuscated data читается
- `demo_data/notes_for_agent.txt` - prompt injection через файл читается
