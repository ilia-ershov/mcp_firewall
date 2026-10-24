#!/usr/bin/env python3
"""Minimal MCP server speaking newline-delimited JSON-RPC over stdin/stdout.

Every tool is scoped to a single allowed root directory:

- read_text_file            read a UTF-8 text file inside the root
- run_command               run `pwd`, `ls` or `echo` inside the root
- list_allowed_directories  report the root

Usage: demo_mcp_server.py <allowed_root>
"""
from __future__ import annotations

import json
import os
import shlex
import subprocess
import sys
from typing import Any, BinaryIO, Callable

PROTOCOL_VERSION = "2024-11-05"
ALLOWED_COMMANDS = {"pwd", "ls", "echo"}
COMMAND_TIMEOUT_SECONDS = 5

PARSE_ERROR = -32700
INVALID_REQUEST = -32600
METHOD_NOT_FOUND = -32601
INVALID_PARAMS = -32602
FILE_NOT_FOUND = -32004
ACCESS_DENIED = -32005
COMMAND_NOT_ALLOWED = -32006
COMMAND_FAILED = -32007

TOOLS: list[dict[str, Any]] = [
    {
        "name": "read_text_file",
        "description": "Read the contents of a text file within the allowed directory.",
        "inputSchema": {
            "type": "object",
            "properties": {"path": {"type": "string"}},
            "required": ["path"],
        },
    },
    {
        "name": "run_command",
        "description": "Execute a shell-like command inside the allowed directory. High risk.",
        "inputSchema": {
            "type": "object",
            "properties": {"command": {"type": "string"}},
            "required": ["command"],
        },
    },
    {
        "name": "list_allowed_directories",
        "description": "Return the allowed root directory for this MCP server.",
        "inputSchema": {"type": "object", "properties": {}},
    },
]


class RequestError(Exception):
    """A failure reported to the client as a JSON-RPC error."""

    def __init__(self, code: int, message: str) -> None:
        super().__init__(message)
        self.code = code


class DemoMCPServer:
    def __init__(self, allowed_root: str) -> None:
        self.allowed_root = os.path.realpath(allowed_root)
        self._methods: dict[str, Callable[[Any], dict[str, Any]]] = {
            "initialize": self._initialize,
            "ping": lambda params: {},
            "tools/list": lambda params: {"tools": TOOLS},
            "tools/call": self._call_tool,
        }
        self._tools: dict[str, Callable[[dict[str, Any]], str]] = {
            "read_text_file": self._read_text_file,
            "run_command": self._run_command,
            "list_allowed_directories": lambda arguments: self.allowed_root,
        }

    def serve(self, stdin: BinaryIO, stdout: BinaryIO) -> int:
        for line in stdin:
            if not line.strip():
                continue
            try:
                message = json.loads(line)
            except (ValueError, RecursionError):
                response: dict[str, Any] | None = _error(None, PARSE_ERROR, "Invalid JSON")
            else:
                response = self.handle(message)
            if response is not None:
                stdout.write((json.dumps(response) + "\n").encode("utf-8"))
                stdout.flush()
        return 0

    def handle(self, message: Any) -> dict[str, Any] | None:
        """Process one JSON-RPC message and return the response (None for notifications)."""
        if not isinstance(message, dict):
            return _error(None, INVALID_REQUEST, "Invalid Request")
        if "id" not in message:
            return None  # Notifications such as notifications/initialized are never answered.

        request_id = message["id"]
        method = message.get("method")
        if not isinstance(method, str):
            return _error(request_id, INVALID_REQUEST, "Invalid Request")
        handler = self._methods.get(method)
        if handler is None:
            return _error(request_id, METHOD_NOT_FOUND, f"Method not found: {method}")

        try:
            result = handler(message.get("params"))
        except RequestError as exc:
            return _error(request_id, exc.code, str(exc))
        return {"jsonrpc": "2.0", "id": request_id, "result": result}

    def _initialize(self, params: Any) -> dict[str, Any]:
        return {
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": {"tools": {}},
            "serverInfo": {"name": "demo-mcp-server", "version": "1.0.0"},
        }

    def _call_tool(self, params: Any) -> dict[str, Any]:
        if not isinstance(params, dict) or not isinstance(params.get("name"), str):
            raise RequestError(INVALID_PARAMS, "tools/call requires a string 'name'")
        arguments = params.get("arguments") or {}
        if not isinstance(arguments, dict):
            raise RequestError(INVALID_PARAMS, "arguments must be an object")
        tool = self._tools.get(params["name"])
        if tool is None:
            raise RequestError(INVALID_PARAMS, f"Unknown tool: {params['name']}")

        text = tool(arguments)
        # structuredContent duplicates the text so the firewall's structured scanning is exercised.
        return {"content": [{"type": "text", "text": text}], "structuredContent": {"content": text}}

    def _read_text_file(self, arguments: dict[str, Any]) -> str:
        path = _string_argument(arguments, "path")
        resolved = self._resolve_path(path)
        if not os.path.exists(resolved):
            raise RequestError(FILE_NOT_FOUND, f"File not found: {path}")
        if not os.path.isfile(resolved):
            raise RequestError(INVALID_PARAMS, f"Not a regular file: {path}")
        try:
            with open(resolved, encoding="utf-8") as fh:
                return fh.read()
        except UnicodeDecodeError:
            raise RequestError(INVALID_PARAMS, f"Not a UTF-8 text file: {path}") from None
        except OSError as exc:
            raise RequestError(ACCESS_DENIED, f"Cannot read {path}: {exc.strerror}") from None

    def _run_command(self, arguments: dict[str, Any]) -> str:
        command = _string_argument(arguments, "command")
        try:
            argv = shlex.split(command)
        except ValueError as exc:
            raise RequestError(INVALID_PARAMS, f"Invalid command: {exc}") from None
        if not argv:
            raise RequestError(INVALID_PARAMS, "Empty command")
        if argv[0] not in ALLOWED_COMMANDS:
            raise RequestError(COMMAND_NOT_ALLOWED, f"Command '{argv[0]}' is not allowed in this demo server")
        if argv[0] == "ls":
            for operand in _path_operands(argv[1:]):
                self._resolve_path(operand)

        try:
            completed = subprocess.run(
                argv,
                cwd=self.allowed_root,
                capture_output=True,
                encoding="utf-8",
                errors="replace",
                timeout=COMMAND_TIMEOUT_SECONDS,
                check=False,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise RequestError(COMMAND_FAILED, f"Command failed: {exc}") from None
        return completed.stdout or completed.stderr or f"Command exited with code {completed.returncode}"

    def _resolve_path(self, path: str) -> str:
        """Resolve path (relative to the root) and reject anything outside the root."""
        resolved = os.path.realpath(os.path.join(self.allowed_root, path))
        if os.path.commonpath([self.allowed_root, resolved]) != self.allowed_root:
            raise RequestError(ACCESS_DENIED, f"Access denied outside allowed directory: {path}")
        return resolved


def _string_argument(arguments: dict[str, Any], name: str) -> str:
    value = arguments.get(name)
    if not isinstance(value, str):
        raise RequestError(INVALID_PARAMS, f"{name} must be a string")
    return value


def _path_operands(args: list[str]) -> list[str]:
    """Return the non-option arguments of an `ls` invocation."""
    operands: list[str] = []
    options_done = False
    for arg in args:
        if options_done or not arg.startswith("-"):
            operands.append(arg)
        elif arg == "--":
            options_done = True
    return operands


def _error(request_id: Any, code: int, message: str) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": request_id, "error": {"code": code, "message": message}}


def main(argv: list[str]) -> int:
    if len(argv) != 1:
        print("Usage: demo_mcp_server.py <allowed_root>", file=sys.stderr)
        return 1
    if not os.path.isdir(argv[0]):
        print(f"Not a directory: {argv[0]}", file=sys.stderr)
        return 1
    return DemoMCPServer(argv[0]).serve(sys.stdin.buffer, sys.stdout.buffer)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
