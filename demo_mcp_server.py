#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import shlex
import subprocess
import sys
from typing import Any


ALLOWED_COMMANDS = {"pwd", "ls", "echo"}


class DemoMCPServer:
    def __init__(self, allowed_root: str) -> None:
        self.allowed_root = os.path.realpath(allowed_root)

    def serve(self) -> int:
        for raw_line in sys.stdin:
            line = raw_line.strip()
            if not line:
                continue

            try:
                message = json.loads(line)
            except json.JSONDecodeError:
                self._send_error(None, -32700, "Invalid JSON")
                continue

            method = message.get("method")
            request_id = message.get("id")

            if method == "initialize":
                self._send(
                    {
                        "jsonrpc": "2.0",
                        "id": request_id,
                        "result": {
                            "protocolVersion": "2024-11-05",
                            "capabilities": {"tools": {}},
                            "serverInfo": {"name": "demo-mcp-server", "version": "1.0.0"},
                        },
                    }
                )
                continue

            if method == "notifications/initialized":
                continue

            if method == "ping":
                self._send({"jsonrpc": "2.0", "id": request_id, "result": {}})
                continue

            if method == "tools/list":
                self._send({"jsonrpc": "2.0", "id": request_id, "result": {"tools": self._tools()}})
                continue

            if method == "tools/call":
                params = message.get("params", {})
                tool_name = params.get("name")
                arguments = params.get("arguments", {})
                self._handle_tool_call(request_id, tool_name, arguments)
                continue

            self._send_error(request_id, -32601, f"Method not found: {method}")
        return 0

    def _tools(self) -> list[dict[str, Any]]:
        return [
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

    def _handle_tool_call(self, request_id: Any, tool_name: str, arguments: dict[str, Any]) -> None:
        if tool_name == "read_text_file":
            path = arguments.get("path")
            if not isinstance(path, str):
                self._send_error(request_id, -32602, "path must be a string")
                return
            self._read_text_file(request_id, path)
            return

        if tool_name == "run_command":
            command = arguments.get("command")
            if not isinstance(command, str):
                self._send_error(request_id, -32602, "command must be a string")
                return
            self._run_command(request_id, command)
            return

        if tool_name == "list_allowed_directories":
            self._send_text_result(request_id, self.allowed_root)
            return

        self._send_error(request_id, -32601, f"Unknown tool: {tool_name}")

    def _read_text_file(self, request_id: Any, path: str) -> None:
        try:
            resolved = self._resolve_path(path)
            with open(resolved, "r", encoding="utf-8") as fh:
                data = fh.read()
        except FileNotFoundError:
            self._send_error(request_id, -32004, f"File not found: {path}")
            return
        except PermissionError as exc:
            self._send_error(request_id, -32005, str(exc))
            return

        self._send_text_result(request_id, data)

    def _run_command(self, request_id: Any, command: str) -> None:
        try:
            parts = shlex.split(command)
        except ValueError as exc:
            self._send_error(request_id, -32602, f"Invalid command: {exc}")
            return

        if not parts:
            self._send_error(request_id, -32602, "Empty command")
            return

        if parts[0] not in ALLOWED_COMMANDS:
            self._send_error(
                request_id,
                -32006,
                f"Command '{parts[0]}' is not allowed in this demo server",
            )
            return

        try:
            result = subprocess.run(
                parts,
                cwd=self.allowed_root,
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
        except Exception as exc:
            self._send_error(request_id, -32007, f"Command failed: {exc}")
            return

        output = result.stdout if result.stdout else result.stderr
        if not output:
            output = f"Command exited with code {result.returncode}"
        self._send_text_result(request_id, output)

    def _resolve_path(self, path: str) -> str:
        candidate = path
        if not os.path.isabs(candidate):
            candidate = os.path.join(self.allowed_root, candidate)
        resolved = os.path.realpath(candidate)
        if os.path.commonpath([self.allowed_root, resolved]) != self.allowed_root:
            raise PermissionError(f"Access denied outside allowed directory: {path}")
        return resolved

    def _send_text_result(self, request_id: Any, text: str) -> None:
        self._send(
            {
                "jsonrpc": "2.0",
                "id": request_id,
                "result": {
                    "content": [{"type": "text", "text": text}],
                    "structuredContent": {"content": text},
                },
            }
        )

    def _send(self, message: dict[str, Any]) -> None:
        sys.stdout.write(json.dumps(message, ensure_ascii=False) + "\n")
        sys.stdout.flush()

    def _send_error(self, request_id: Any, code: int, message: str) -> None:
        self._send({"jsonrpc": "2.0", "id": request_id, "error": {"code": code, "message": message}})


def main() -> int:
    if len(sys.argv) != 2:
        print("Usage: python demo_mcp_server.py <allowed_root>", file=sys.stderr)
        return 1
    server = DemoMCPServer(sys.argv[1])
    return server.serve()


if __name__ == "__main__":
    raise SystemExit(main())
