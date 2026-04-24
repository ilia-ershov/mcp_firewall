#!/usr/bin/env python3
import asyncio
import json
import math
import re
import sys
from contextlib import suppress
from collections import Counter
from typing import Any


TOOL_RISK_KEYWORDS = {
    "high": ("execute", "command", "bash", "shell", "write", "delete", "remove", "fs_"),
    "medium": ("read", "search", "list", "fetch"),
}

SECRET_VALUE_PATTERNS = [
    re.compile(r"(?i)\b([A-Z0-9_]*password)\s*[:=]\s*([^\s\"']+)"),
    re.compile(r"(?i)\b([A-Z0-9_]*token)\s*[:=]\s*([^\s\"']+)"),
    re.compile(r"(?i)\b([A-Z0-9_]*api[_-]?key)\s*[:=]\s*([^\s\"']+)"),
    re.compile(r"\b([A-Z0-9_]*AWS_ACCESS_KEY_ID)\s*[:=]\s*(AKIA[0-9A-Z]{16})"),
]

SECRET_BLOCK_PATTERNS = [
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"-----BEGIN (?:RSA )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA )?PRIVATE KEY-----"),
]

INJECTION_PATTERNS = [
    re.compile(r"ignore\s+previous\s+instructions", re.IGNORECASE),
    re.compile(r"system\s+prompt", re.IGNORECASE),
    re.compile(r"you\s+are\s+no\s+longer", re.IGNORECASE),
    re.compile(r"bypass(?:ing)?", re.IGNORECASE),
    re.compile(r"override", re.IGNORECASE),
    re.compile(r"exfiltrat", re.IGNORECASE),
]

REDACTION = "[SECURITY_REDACTED_BY_FIREWALL]"
ENTROPY_REDACTION = "[HIGH_ENTROPY_REDACTED_BY_FIREWALL]"
HIGH_ENTROPY_PATTERN = re.compile(r"\b[A-Za-z0-9+/=_-]{24,}\b")
HIGH_ENTROPY_BLOCK_THRESHOLD = 2


class MCPFirewall:
    def __init__(self, server_cmd: list[str]) -> None:
        self.server_cmd = server_cmd
        self.server_process: asyncio.subprocess.Process | None = None
        self.tool_registry: dict[str, str] = {}
        self.pending_requests: dict[Any, dict[str, Any]] = {}

    async def start(self) -> None:
        self.server_process = await asyncio.create_subprocess_exec(
            *self.server_cmd,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=sys.stderr,
        )
        await asyncio.gather(self._client_to_server_loop(), self._server_to_client_loop())

    async def _client_to_server_loop(self) -> None:
        assert self.server_process is not None
        assert self.server_process.stdin is not None

        while True:
            raw_line = await asyncio.to_thread(sys.stdin.readline)
            if not raw_line:
                self.server_process.stdin.close()
                await self.server_process.stdin.wait_closed()
                return

            line = raw_line.strip()
            if not line:
                continue

            try:
                message = json.loads(line)
            except json.JSONDecodeError:
                self._send_error(None, -32700, "Firewall rejected invalid JSON")
                continue

            request_id = message.get("id")
            method = message.get("method")

            if method == "tools/call":
                params = message.get("params", {})
                tool_name = params.get("name", "")
                risk = self.tool_registry.get(tool_name) or self._classify_tool(tool_name, "")
                if risk == "High":
                    self._send_error(
                        request_id,
                        -32000,
                        f"User denied execution of high-risk tool: {tool_name}",
                    )
                    continue

                self.pending_requests[request_id] = {
                    "method": method,
                    "tool_name": tool_name,
                    "risk": risk,
                }
            elif method == "tools/list":
                self.pending_requests[request_id] = {"method": method}

            self.server_process.stdin.write((json.dumps(message, ensure_ascii=False) + "\n").encode())
            await self.server_process.stdin.drain()

    async def _server_to_client_loop(self) -> None:
        assert self.server_process is not None
        assert self.server_process.stdout is not None

        while True:
            raw_line = await self.server_process.stdout.readline()
            if not raw_line:
                return

            line = raw_line.decode().strip()
            if not line:
                continue

            try:
                message = json.loads(line)
            except json.JSONDecodeError:
                self._send_error(None, -32603, "Firewall received invalid server JSON")
                continue

            request_id = message.get("id")
            request_meta = self.pending_requests.pop(request_id, {})

            if request_meta.get("method") == "tools/list":
                self._capture_tool_registry(message)
            elif request_meta.get("method") == "tools/call":
                if self._sanitize_tool_response(message):
                    continue

            self._send(message)

    def _capture_tool_registry(self, message: dict[str, Any]) -> None:
        tools = message.get("result", {}).get("tools", [])
        for tool in tools:
            name = tool.get("name", "")
            description = tool.get("description", "")
            self.tool_registry[name] = self._classify_tool(name, description)

    def _classify_tool(self, name: str, description: str) -> str:
        text = f"{name} {description}".lower()
        if any(keyword in text for keyword in TOOL_RISK_KEYWORDS["high"]):
            return "High"
        if any(keyword in text for keyword in TOOL_RISK_KEYWORDS["medium"]):
            return "Medium"
        return "Low"

    def _sanitize_tool_response(self, message: dict[str, Any]) -> bool:
        result = message.get("result", {})
        content = result.get("content")
        if not isinstance(content, list):
            content = []

        for item in content:
            if not isinstance(item, dict):
                continue
            text = item.get("text")
            if not isinstance(text, str):
                continue

            if self._looks_like_injection(text):
                self._send_error(
                    message.get("id"),
                    -32001,
                    "The tool output contained suspicious instructions and was blocked",
                )
                return True

            if self._contains_too_many_high_entropy_chunks(text):
                self._send_error(
                    message.get("id"),
                    -32002,
                    "The tool output contained obfuscated or encoded high-entropy data and was blocked",
                )
                return True

            item["text"] = self._redact_secrets(text)

        structured_content = result.get("structuredContent")
        if structured_content is not None:
            blocked, sanitized_structured = self._sanitize_nested_text(structured_content)
            if blocked:
                self._send_error(
                    message.get("id"),
                    -32001,
                    "The tool output contained suspicious instructions and was blocked",
                )
                return True
            result["structuredContent"] = sanitized_structured

        return False

    def _looks_like_injection(self, text: str) -> bool:
        matches = sum(1 for pattern in INJECTION_PATTERNS if pattern.search(text))
        return matches >= 1

    def _redact_secrets(self, text: str) -> str:
        sanitized = text
        for pattern in SECRET_VALUE_PATTERNS:
            sanitized = pattern.sub(lambda match: f"{match.group(1)}={REDACTION}", sanitized)
        for pattern in SECRET_BLOCK_PATTERNS:
            sanitized = pattern.sub(REDACTION, sanitized)
        sanitized = HIGH_ENTROPY_PATTERN.sub(self._replace_high_entropy_match, sanitized)
        return sanitized

    def _replace_high_entropy_match(self, match: re.Match[str]) -> str:
        value = match.group(0)
        if self._looks_like_obfuscated_or_encoded(value):
            return ENTROPY_REDACTION
        return value

    def _contains_too_many_high_entropy_chunks(self, text: str) -> bool:
        matches = 0
        for match in HIGH_ENTROPY_PATTERN.finditer(text):
            if self._looks_like_obfuscated_or_encoded(match.group(0)):
                matches += 1
                if matches >= HIGH_ENTROPY_BLOCK_THRESHOLD:
                    return True
        return False

    def _looks_like_obfuscated_or_encoded(
        self,
        data: str,
        *,
        min_length: int = 24,
        min_entropy: float = 3.5,
        min_normalized_entropy: float = 0.92,
    ) -> bool:
        if self._looks_like_natural_language(data):
            return False

        stripped = "".join(data.split())
        if len(stripped) < min_length:
            return False

        entropy = self._shannon_entropy(stripped)
        normalized = self._normalized_shannon_entropy(stripped)
        return (
            entropy >= min_entropy
            and normalized >= min_normalized_entropy
            and self._has_machine_like_character_mix(stripped)
        )

    def _looks_like_natural_language(self, data: str) -> bool:
        letter_chunks = re.findall(r"[A-Za-z]{3,}", data)
        if len(letter_chunks) < 4:
            return False

        total_letters = sum(len(chunk) for chunk in letter_chunks)
        return total_letters >= len(data) * 0.55 and data.count(" ") >= 3

    def _has_machine_like_character_mix(self, data: str) -> bool:
        return any(char.isdigit() for char in data) or any(char.isupper() for char in data) or any(
            char in "+/=_-" for char in data
        )

    def _shannon_entropy(self, data: str) -> float:
        if not data:
            return 0.0

        counts = Counter(data)
        length = len(data)
        entropy = 0.0
        for count in counts.values():
            probability = count / length
            entropy -= probability * math.log2(probability)
        return entropy

    def _normalized_shannon_entropy(self, data: str) -> float:
        if not data:
            return 0.0

        alphabet_size = len(set(data))
        if alphabet_size <= 1:
            return 0.0

        max_entropy = math.log2(alphabet_size)
        if max_entropy == 0.0:
            return 0.0
        return self._shannon_entropy(data) / max_entropy

    def _sanitize_nested_text(self, value: Any) -> tuple[bool, Any]:
        if isinstance(value, str):
            if self._looks_like_injection(value):
                return True, value
            if self._contains_too_many_high_entropy_chunks(value):
                return True, value
            return False, self._redact_secrets(value)
        if isinstance(value, list):
            sanitized_items = []
            for item in value:
                blocked, sanitized_item = self._sanitize_nested_text(item)
                if blocked:
                    return True, value
                sanitized_items.append(sanitized_item)
            return False, sanitized_items
        if isinstance(value, dict):
            sanitized_dict: dict[str, Any] = {}
            for key, item in value.items():
                blocked, sanitized_item = self._sanitize_nested_text(item)
                if blocked:
                    return True, value
                sanitized_dict[key] = sanitized_item
            return False, sanitized_dict
        return False, value

    def _send(self, message: dict[str, Any]) -> None:
        sys.stdout.write(json.dumps(message, ensure_ascii=False) + "\n")
        sys.stdout.flush()

    def _send_error(self, request_id: Any, code: int, message: str) -> None:
        self._send({"jsonrpc": "2.0", "id": request_id, "error": {"code": code, "message": message}})


async def main() -> int:
    if len(sys.argv) < 2:
        print("Usage: python firewall.py <server command> [args...]", file=sys.stderr)
        return 1

    firewall = MCPFirewall(sys.argv[1:])
    try:
        await firewall.start()
    finally:
        if firewall.server_process is not None:
            with suppress(ProcessLookupError):
                firewall.server_process.terminate()
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
