# MCP_FIREWALL

Проект для показа через Codex двух сценариев:

- [without_fw](/Users/thomas/MCP_FIREWALL/without_fw) - MCP filesystem server без защиты
- [with_fw](/Users/thomas/MCP_FIREWALL/with_fw) - тот же сценарий, но через [firewall.py](/Users/thomas/MCP_FIREWALL/with_fw/firewall.py)

Что демонстрируется:

- чтение файла с ключами
- чтение файла с prompt injection через файл
- чтение файла с obfuscated or encoded data
- различие поведения без firewall и с firewall
