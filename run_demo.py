#!/usr/bin/env python3
"""Run the MCP firewall demo locally without a Codex client."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent
UNSAFE_DIR = ROOT / "without_fw"
SAFE_DIR = ROOT / "with_fw"
SERVER_PATH = ROOT / "demo_mcp_server.py"
FIREWALL_PATH = SAFE_DIR / "firewall.py"


def build_server_command(mode: str, demo_dir: Path) -> list[str]:
    if mode == "unsafe":
        return [sys.executable, str(SERVER_PATH), str(demo_dir)]
    if mode == "safe":
        return [
            sys.executable,
            str(FIREWALL_PATH),
            sys.executable,
            str(SERVER_PATH),
            str(demo_dir),
        ]
    raise ValueError(f"Unknown mode: {mode}")


def call_tool(process: subprocess.Popen[str], *, method: str, params: dict[str, Any] | None = None, request_id: int) -> dict[str, Any]:
    message = {"jsonrpc": "2.0", "id": request_id, "method": method}
    if params is not None:
        message["params"] = params
    process.stdin.write(json.dumps(message, ensure_ascii=False) + "\n")
    process.stdin.flush()
    response = process.stdout.readline()
    if not response:
        raise RuntimeError(f"No response for {method} request {request_id}")
    return json.loads(response)


def print_json(value: Any, indent: int = 2) -> None:
    print(json.dumps(value, ensure_ascii=False, indent=indent))


def run_demo(mode: str) -> None:
    demo_dir = UNSAFE_DIR if mode == "unsafe" else SAFE_DIR
    command = build_server_command(mode, demo_dir)
    print(f"\n=== {mode.upper()} mode: {demo_dir.name} ===")

    with subprocess.Popen(
        command,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        cwd=str(ROOT),
    ) as process:
        assert process.stdin is not None
        assert process.stdout is not None

        try:
            list_response = call_tool(process, method="tools/list", request_id=1)
            print("tools/list:")
            print_json(list_response)

            for index, file_name in enumerate([
                "demo_data/secret_data.txt",
                "demo_data/attack.txt",
                "demo_data/notes_for_agent.txt",
                "demo_data/obfuscated_payload.txt",
            ], start=100):
                print(f"\nReading {file_name}")
                response = call_tool(
                    process,
                    method="tools/call",
                    params={"name": "read_text_file", "arguments": {"path": file_name}},
                    request_id=index,
                )
                print_json(response)

            print("\nRunning a command")
            response = call_tool(
                process,
                method="tools/call",
                params={"name": "run_command", "arguments": {"command": "pwd"}},
                request_id=200,
            )
            print_json(response)
        finally:
            if process.stdin is not None:
                process.stdin.close()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)

            stderr = process.stderr.read() if process.stderr is not None else ""
            if stderr.strip():
                print("\nServer stderr:")
                print(stderr.strip())


def main() -> int:
    parser = argparse.ArgumentParser(description="Run the MCP firewall demo locally without Codex.")
    parser.add_argument(
        "--mode",
        choices=["unsafe", "safe", "both"],
        default="both",
        help="Which demo to run: unsafe, safe, or both.",
    )
    args = parser.parse_args()

    if args.mode in {"unsafe", "safe"}:
        run_demo(args.mode)
    else:
        run_demo("unsafe")
        run_demo("safe")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
