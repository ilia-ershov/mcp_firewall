#!/usr/bin/env python3
"""Replay the live demo's tool calls without an LLM.

Starts the backend directly (unsafe) or behind the firewall (safe), performs the
MCP handshake, issues the same five tool calls as the PROMPT.txt files and
prints what the client receives.
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent
SERVER_PATH = ROOT / "demo_mcp_server.py"
FIREWALL_PATH = ROOT / "firewall.py"
SCENARIO_DIRS = {"unsafe": ROOT / "without_fw", "safe": ROOT / "with_fw"}

# The calls from without_fw/PROMPT.txt and with_fw/PROMPT.txt, in the same order.
PROMPT_STEPS: list[tuple[str, dict[str, str]]] = [
    ("read_text_file", {"path": "demo_data/config.env"}),
    ("run_command", {"command": "pwd"}),
    ("read_text_file", {"path": "demo_data/attack.txt"}),
    ("read_text_file", {"path": "demo_data/obfuscated_payload.txt"}),
    ("read_text_file", {"path": "demo_data/notes_for_agent.txt"}),
]


def build_command(mode: str) -> list[str]:
    server = [sys.executable, str(SERVER_PATH), str(SCENARIO_DIRS[mode])]
    return [sys.executable, str(FIREWALL_PATH), *server] if mode == "safe" else server


class StdioClient:
    """Minimal synchronous MCP client for a server speaking JSON-RPC over stdio."""

    def __init__(self, command: list[str]) -> None:
        self.process = subprocess.Popen(
            command,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            encoding="utf-8",
            cwd=ROOT,
        )
        self.stderr = ""
        self._next_id = 1

    def __enter__(self) -> StdioClient:
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()

    def send(self, message: dict[str, Any]) -> None:
        assert self.process.stdin is not None
        self.process.stdin.write(json.dumps(message) + "\n")
        self.process.stdin.flush()

    def request(self, method: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        message: dict[str, Any] = {"jsonrpc": "2.0", "id": self._next_id, "method": method}
        self._next_id += 1
        if params is not None:
            message["params"] = params
        self.send(message)
        assert self.process.stdout is not None
        line = self.process.stdout.readline()
        if not line:
            raise RuntimeError(f"Server closed the connection while handling {method}")
        return json.loads(line)

    def initialize(self) -> dict[str, Any]:
        response = self.request(
            "initialize",
            {"protocolVersion": "2024-11-05", "capabilities": {}, "clientInfo": {"name": "run_demo", "version": "1.0"}},
        )
        self.send({"jsonrpc": "2.0", "method": "notifications/initialized"})
        return response

    def call_tool(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        return self.request("tools/call", {"name": name, "arguments": arguments})

    def close(self) -> None:
        """Close stdin, wait for the server to exit and keep its stderr in self.stderr."""
        if self.process.returncode is not None:
            return
        try:
            _, self.stderr = self.process.communicate(timeout=10)
        except subprocess.TimeoutExpired:
            self.process.kill()
            _, self.stderr = self.process.communicate()


def summarize(response: dict[str, Any], width: int = 100) -> str:
    if "error" in response:
        error = response["error"]
        return f"error {error['code']}: {error['message']}"
    texts = [item.get("text", "") for item in response["result"].get("content", [])]
    flat = " | ".join(line for text in texts for line in text.splitlines() if line)
    return "result: " + (flat if len(flat) <= width else flat[: width - 1] + "…")


def run_demo(mode: str, *, raw: bool = False) -> None:
    route = "client -> firewall.py -> demo_mcp_server.py" if mode == "safe" else "client -> demo_mcp_server.py"
    print(f"\n=== {mode.upper()}: {route} (root: {SCENARIO_DIRS[mode].name}/) ===")

    with StdioClient(build_command(mode)) as client:
        client.initialize()
        tools = client.request("tools/list")["result"]["tools"]
        print("tools: " + ", ".join(tool["name"] for tool in tools))
        for number, (name, arguments) in enumerate(PROMPT_STEPS, start=1):
            response = client.call_tool(name, arguments)
            print(f"{number}. {name} {json.dumps(arguments)}")
            if raw:
                print(json.dumps(response, ensure_ascii=False, indent=2))
            else:
                print(f"   {summarize(response)}")

    if client.stderr.strip():
        print(f"server stderr:\n{client.stderr.strip()}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--mode", choices=["unsafe", "safe", "both"], default="both", help="which scenario to run (default: both)"
    )
    parser.add_argument("--json", action="store_true", help="print full JSON-RPC responses")
    args = parser.parse_args()

    for mode in ("unsafe", "safe") if args.mode == "both" else (args.mode,):
        run_demo(mode, raw=args.json)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
