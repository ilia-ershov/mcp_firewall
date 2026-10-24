#!/usr/bin/env python3
"""MCP firewall: a stdio proxy that inspects JSON-RPC traffic at the protocol boundary.

    MCP client <-> firewall.py <-> backend MCP server (child process)

Requests:  `tools/call` for a high-risk tool is answered with an error and never
           reaches the backend.
Responses: results (and errors) of `tools/call`, `resources/read` and
           `prompts/get` are blocked when they contain prompt-injection phrases
           or several encoded blobs; otherwise secrets and single encoded blobs
           are redacted. `tools/list` is screened for tools whose descriptions
           carry injected instructions ("tool poisoning").

Usage: firewall.py <server command> [args...]
"""
from __future__ import annotations

import json
import math
import re
import subprocess
import sys
import threading
import unicodedata
from collections import Counter
from contextlib import suppress
from typing import Any, Iterator

# --- Policy ------------------------------------------------------------------

HIGH_RISK_TOOL_KEYWORDS = ("execute", "command", "bash", "shell", "write", "delete", "remove", "fs_")

INJECTION_PATTERNS = [
    re.compile(
        r"\b(?:ignor(?:e|es|ing)|disregard(?:s|ing)?|forget(?:s|ting)?)\s+(?:all\s+|any\s+)?(?:the\s+|your\s+)?"
        r"(?:previous|prior|above|earlier|preceding)\s+(?:instructions|directions|rules|prompts?)",
        re.IGNORECASE,
    ),
    re.compile(r"\byou\s+are\s+no\s+longer\b", re.IGNORECASE),
    re.compile(
        r"\b(?:reveal|show|print|repeat|output|leak)\s+(?:me\s+)?(?:your\s+|the\s+)?"
        r"(?:system|hidden|initial)\s+prompt",
        re.IGNORECASE,
    ),
    re.compile(
        r"\bbypass(?:es|ing)?\s+(?:the\s+|any\s+|all\s+)?"
        r"(?:security|safety|firewall|filters?|restrictions|guardrails)\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"\boverrid(?:e|es|ing)\s+(?:the\s+|your\s+|all\s+|any\s+)?(?:previous\s+|prior\s+|system\s+)?"
        r"(?:instructions|rules|guidelines|restrictions)\b",
        re.IGNORECASE,
    ),
    re.compile(r"\bexfiltrat", re.IGNORECASE),
    re.compile(r"\bdo\s+not\s+(?:tell|inform|alert|notify)\s+the\s+user\b", re.IGNORECASE),
]

# `key = value`, `key: value` and `"key": "value"` where the key names a credential.
SECRET_ASSIGNMENT_PATTERN = re.compile(
    r"(?P<key>\b[A-Za-z0-9_.-]*(?:password|passwd|secret(?:[_-]?key)?|token|api[_-]?key"
    r"|access[_-]?key(?:[_-]?id)?|private[_-]?key))"
    r"(?P<sep>[\"']?[ \t]*[:=][ \t]*[\"']?)"
    r"(?P<value>[^\s\"']+)",
    re.IGNORECASE,
)

# Credentials recognisable by their shape alone.
SECRET_LITERAL_PATTERNS = [
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),  # AWS access key id
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"),  # GitHub token
    re.compile(r"(?<=[Bb]earer )[A-Za-z0-9._~+/=-]{8,}"),
]

REDACTION = "[SECURITY_REDACTED_BY_FIREWALL]"
ENTROPY_REDACTION = "[HIGH_ENTROPY_REDACTED_BY_FIREWALL]"

# Candidate encoded tokens: base64/base64url/hex runs with optional padding. `=` only
# terminates a token, so `key=value` yields the value rather than the whole pair.
ENCODED_TOKEN_PATTERN = re.compile(r"(?<![A-Za-z0-9+/_-])[A-Za-z0-9+/_-]{20,}={0,2}(?![A-Za-z0-9+/=_-])")
HEX_PATTERN = re.compile(r"[0-9a-fA-F]+")
MIN_HEX_LENGTH = 32
MIN_HEX_ENTROPY = 3.0
# Identifiers, paths and prose stay below this; random base64 of 32+ characters usually exceeds it.
MIN_BASE64_ENTROPY = 4.5
ENCODED_BLOCK_THRESHOLD = 2  # this many encoded tokens in one string block the response

# Base64 payload fields of MCP image/audio/blob content, which always carry a mimeType.
BINARY_FIELDS = {"data", "blob"}

# Methods whose results reach the model and are therefore inspected.
INSPECTED_METHODS = {"tools/call", "resources/read", "prompts/get"}

HIGH_RISK_REASON = "is classified as high-risk"
POISONED_REASON = "was hidden because its description contained prompt-injection instructions"

# --- JSON-RPC error codes ------------------------------------------------------

PARSE_ERROR = -32700
INVALID_REQUEST = -32600
INVALID_PARAMS = -32602
TOOL_BLOCKED = -32000
INJECTION_BLOCKED = -32001
ENCODED_BLOCKED = -32002

SHUTDOWN_TIMEOUT_SECONDS = 5


class Blocked(Exception):
    """Raised when content must not be forwarded to the client."""

    def __init__(self, code: int, reason: str) -> None:
        super().__init__(reason)
        self.code = code
        self.reason = reason


def is_high_risk_tool(name: str, description: str = "") -> bool:
    text = f"{name} {description}".lower()
    return any(keyword in text for keyword in HIGH_RISK_TOOL_KEYWORDS)


def contains_injection(text: str) -> bool:
    # Fold look-alike characters (e.g. full-width letters) and drop invisible ones
    # (e.g. zero-width spaces) so they cannot be used to split a phrase.
    folded = unicodedata.normalize("NFKC", text)
    normalized = "".join(char for char in folded if unicodedata.category(char) != "Cf")
    return any(pattern.search(normalized) for pattern in INJECTION_PATTERNS)


def redact_secrets(text: str) -> str:
    for pattern in SECRET_LITERAL_PATTERNS:
        text = pattern.sub(REDACTION, text)
    return SECRET_ASSIGNMENT_PATTERN.sub(lambda match: f"{match['key']}{match['sep']}{REDACTION}", text)


def shannon_entropy(data: str) -> float:
    length = len(data)
    return -sum(count / length * math.log2(count / length) for count in Counter(data).values())


def looks_encoded(token: str) -> bool:
    """Heuristic for base64 and hex blobs."""
    body = token.rstrip("=")
    if body.startswith("/"):
        # A path (also `./x`, `~/x` and URL paths): judge each component on its own so
        # that long directory names do not add up to a high-entropy token.
        return any(looks_encoded(part) for part in body.split("/") if len(part) >= 20)
    has_digit = any(char.isdigit() for char in body)
    if HEX_PATTERN.fullmatch(body):
        return (
            len(body) >= MIN_HEX_LENGTH
            and has_digit
            and not body.isdigit()
            and shannon_entropy(body.lower()) >= MIN_HEX_ENTROPY
        )
    # Random base64 of this length almost surely mixes all three character classes;
    # identifiers, constants and paths rarely do.
    has_upper = any(char.isupper() for char in body)
    has_lower = any(char.islower() for char in body)
    return has_digit and has_upper and has_lower and shannon_entropy(body) >= MIN_BASE64_ENTROPY


def find_encoded_tokens(text: str) -> list[str]:
    return [match[0] for match in ENCODED_TOKEN_PATTERN.finditer(text) if looks_encoded(match[0])]


def sanitize_text(text: str, *, binary: bool = False) -> str:
    """Return text that is safe to forward, or raise Blocked."""
    if contains_injection(text):
        raise Blocked(INJECTION_BLOCKED, "the response contained prompt-injection instructions")
    if binary:
        return text
    # Redact first so that labelled secrets are not mistaken for encoded payloads.
    text = redact_secrets(text)
    encoded = find_encoded_tokens(text)
    if len(encoded) >= ENCODED_BLOCK_THRESHOLD:
        raise Blocked(ENCODED_BLOCKED, "the response contained obfuscated or encoded high-entropy data")
    if encoded:
        text = ENCODED_TOKEN_PATTERN.sub(lambda m: ENTROPY_REDACTION if looks_encoded(m[0]) else m[0], text)
    return text


def sanitize(value: Any) -> Any:
    """Return a sanitized copy of a JSON value, or raise Blocked."""
    if isinstance(value, str):
        return sanitize_text(value)
    if isinstance(value, list):
        return [sanitize(item) for item in value]
    if isinstance(value, dict):
        is_binary_content = "mimeType" in value
        sanitized: dict[str, Any] = {}
        for key, item in value.items():
            if contains_injection(key):
                raise Blocked(INJECTION_BLOCKED, "the response contained prompt-injection instructions")
            if is_binary_content and key in BINARY_FIELDS and isinstance(item, str):
                sanitized[key] = sanitize_text(item, binary=True)
            else:
                sanitized[key] = sanitize(item)
        return sanitized
    return value


def _iter_strings(value: Any) -> Iterator[str]:
    """Yield every string in a JSON value, dictionary keys included."""
    if isinstance(value, str):
        yield value
    elif isinstance(value, list):
        for item in value:
            yield from _iter_strings(item)
    elif isinstance(value, dict):
        for key, item in value.items():
            yield key
            yield from _iter_strings(item)


# --- Proxy -------------------------------------------------------------------


class MCPFirewall:
    """Routes JSON-RPC messages between an MCP client (stdio) and a backend server process."""

    def __init__(self, server_cmd: list[str]) -> None:
        self.server_cmd = server_cmd
        self.server: subprocess.Popen[bytes] | None = None
        # Tool name -> why calls to it are blocked (None: allowed), learned from tools/list.
        self.tool_verdicts: dict[str, str | None] = {}
        # Id of each in-flight client request -> its method.
        self.pending: dict[str | int, str] = {}
        self._client_lock = threading.Lock()

    # Message routing. These methods do no I/O so they can be tested directly.

    def on_client_message(self, message: Any) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
        """Route a client message; returns (message for the server, direct reply to the client)."""
        if not isinstance(message, dict):
            return None, _error(None, INVALID_REQUEST, "Firewall rejected a non-object JSON-RPC message")
        if "method" not in message:
            return message, None  # The client's response to a server-initiated request.

        is_request = "id" in message
        request_id = message.get("id")
        if not isinstance(message["method"], str) or (is_request and not _is_valid_id(request_id)):
            reply_id = request_id if _is_valid_id(request_id) else None
            return None, _error(reply_id, INVALID_REQUEST, "Firewall rejected an invalid JSON-RPC request")

        if message["method"] == "tools/call":
            rejection = self._check_tool_call(message.get("params"))
            if rejection is not None:
                return None, (_error(request_id, *rejection) if is_request else None)
        if is_request:
            self.pending[request_id] = message["method"]
        return message, None

    def on_server_message(self, message: Any) -> dict[str, Any] | None:
        """Return the message to forward to the client, or None to drop it."""
        if not isinstance(message, dict):
            _log("dropped a non-object message from the server")
            return None
        if "method" in message:
            return message  # Server-initiated requests and notifications are not inspected.

        request_id = message.get("id")
        method = self.pending.pop(request_id, None) if _is_valid_id(request_id) else None
        if method is None:
            _log(f"dropped a server response to unknown request id {request_id!r}")
            return None
        if method == "tools/list":
            return self._screen_tool_list(message)
        if method in INSPECTED_METHODS:
            return self._inspect_response(message)
        return message

    def _check_tool_call(self, params: Any) -> tuple[int, str] | None:
        name = params.get("name") if isinstance(params, dict) else None
        if not isinstance(name, str):
            return INVALID_PARAMS, "tools/call requires a string 'name' parameter"
        if name in self.tool_verdicts:
            reason = self.tool_verdicts[name]
        else:
            reason = HIGH_RISK_REASON if is_high_risk_tool(name) else None
        if reason is None:
            return None
        return TOOL_BLOCKED, f"Blocked by MCP firewall: tool '{name}' {reason}"

    def _screen_tool_list(self, message: dict[str, Any]) -> dict[str, Any]:
        result = message.get("result")
        tools = result.get("tools") if isinstance(result, dict) else None
        if not isinstance(tools, list):
            return message

        visible = []
        for tool in tools:
            if not isinstance(tool, dict) or not isinstance(tool.get("name"), str):
                continue
            name = tool["name"]
            if any(contains_injection(text) for text in _iter_strings(tool)):
                self.tool_verdicts[name] = POISONED_REASON
                continue
            description = tool.get("description")
            high_risk = is_high_risk_tool(name, description if isinstance(description, str) else "")
            self.tool_verdicts[name] = HIGH_RISK_REASON if high_risk else None
            visible.append(tool)
        return {**message, "result": {**result, "tools": visible}}

    def _inspect_response(self, message: dict[str, Any]) -> dict[str, Any]:
        try:
            return {key: sanitize(value) if key in ("result", "error") else value for key, value in message.items()}
        except Blocked as blocked:
            return _error(message.get("id"), blocked.code, f"Blocked by MCP firewall: {blocked.reason}")

    # Transport.

    def run(self) -> int:
        try:
            self.server = subprocess.Popen(self.server_cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE)
        except OSError as exc:
            _log(f"cannot start MCP server {self.server_cmd[0]!r}: {exc}")
            return 1

        threading.Thread(target=self._pump_client_to_server, name="client-reader", daemon=True).start()
        try:
            self._pump_server_to_client()
        finally:
            _stop(self.server)
        return self.server.returncode if self.server.returncode >= 0 else 1

    def _pump_client_to_server(self) -> None:
        assert self.server is not None and self.server.stdin is not None
        # A private reader for fd 0: if this daemon thread is still blocked in a read at
        # exit, interpreter shutdown never has to take the lock of sys.stdin's buffer.
        client_in = open(sys.stdin.fileno(), "rb", closefd=False)
        try:
            for line in client_in:
                if not line.strip():
                    continue
                try:
                    message = _decode(line)
                except ValueError:
                    self._send_to_client(_error(None, PARSE_ERROR, "Firewall rejected invalid JSON"))
                    continue
                try:
                    to_server, reply = self.on_client_message(message)
                except Exception as exc:  # Fail closed but keep the session alive.
                    _log(f"dropped a client message after an internal error: {exc!r}")
                    continue
                if reply is not None:
                    self._send_to_client(reply)
                if to_server is not None:
                    self.server.stdin.write(_encode(to_server))
                    self.server.stdin.flush()
        except OSError:
            pass  # The backend went away; the server-to-client pump ends the session.
        finally:
            # Client EOF: let the backend exit on its own, as the MCP stdio shutdown sequence asks.
            with suppress(OSError):
                self.server.stdin.close()
            with suppress(subprocess.TimeoutExpired):
                self.server.wait(timeout=SHUTDOWN_TIMEOUT_SECONDS)
            _stop(self.server)

    def _pump_server_to_client(self) -> None:
        assert self.server is not None and self.server.stdout is not None
        for line in self.server.stdout:
            if not line.strip():
                continue
            try:
                message = _decode(line)
            except ValueError:
                _log("dropped invalid JSON from the server")
                continue
            try:
                outgoing = self.on_server_message(message)
            except Exception as exc:  # Fail closed but keep the session alive.
                _log(f"dropped a server message after an internal error: {exc!r}")
                continue
            if outgoing is not None:
                self._send_to_client(outgoing)

    def _send_to_client(self, message: dict[str, Any]) -> None:
        data = _encode(message)
        with self._client_lock:
            sys.stdout.buffer.write(data)
            sys.stdout.buffer.flush()


def _is_valid_id(value: Any) -> bool:
    # MCP request ids are strings or integers (never null); bool is excluded because True == 1.
    return isinstance(value, (str, int)) and not isinstance(value, bool)


def _decode(line: bytes) -> Any:
    try:
        return json.loads(line)
    except RecursionError as exc:
        raise ValueError("JSON nested too deeply") from exc


def _encode(message: dict[str, Any]) -> bytes:
    # ASCII-only output: lone surrogates and other odd strings cannot break the encoding.
    return (json.dumps(message) + "\n").encode("ascii")


def _error(request_id: Any, code: int, message: str) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": request_id, "error": {"code": code, "message": message}}


def _stop(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=SHUTDOWN_TIMEOUT_SECONDS)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()


def _log(text: str) -> None:
    print(f"mcp-firewall: {text}", file=sys.stderr, flush=True)


def main(argv: list[str]) -> int:
    if not argv:
        print("Usage: firewall.py <server command> [args...]", file=sys.stderr)
        return 1
    return MCPFirewall(argv).run()


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
