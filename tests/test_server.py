import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import demo_mcp_server
from demo_mcp_server import DemoMCPServer

SERVER_PATH = Path(demo_mcp_server.__file__)


def call(name, arguments=None, request_id=1):
    params = {"name": name}
    if arguments is not None:
        params["arguments"] = arguments
    return {"jsonrpc": "2.0", "id": request_id, "method": "tools/call", "params": params}


class ServerTestCase(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        (self.root / "notes.txt").write_text("hello\n", encoding="utf-8")
        (self.root / "binary.dat").write_bytes(b"\x00\xff\xfe")
        (self.root / "sub").mkdir()
        self.server = DemoMCPServer(str(self.root))

    def assertText(self, response, expected):
        self.assertNotIn("error", response)
        self.assertEqual(response["result"]["content"], [{"type": "text", "text": expected}])
        self.assertEqual(response["result"]["structuredContent"], {"content": expected})

    def assertErrorCode(self, response, code):
        self.assertEqual(response["error"]["code"], code, response)


class ProtocolTests(ServerTestCase):
    def test_initialize_and_tools_list(self):
        init = self.server.handle({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})
        self.assertEqual(init["result"]["protocolVersion"], demo_mcp_server.PROTOCOL_VERSION)
        tools = self.server.handle({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
        self.assertEqual(
            [tool["name"] for tool in tools["result"]["tools"]],
            ["read_text_file", "run_command", "list_allowed_directories"],
        )

    def test_notifications_are_never_answered(self):
        for method in ("notifications/initialized", "notifications/cancelled", "anything/else"):
            self.assertIsNone(self.server.handle({"jsonrpc": "2.0", "method": method}))

    def test_invalid_messages(self):
        self.assertErrorCode(self.server.handle([1, 2]), demo_mcp_server.INVALID_REQUEST)
        self.assertErrorCode(self.server.handle({"jsonrpc": "2.0", "id": 1}), demo_mcp_server.INVALID_REQUEST)
        self.assertErrorCode(
            self.server.handle({"jsonrpc": "2.0", "id": 1, "method": "nope"}), demo_mcp_server.METHOD_NOT_FOUND
        )

    def test_invalid_tool_calls(self):
        bad_params = [None, [], {"name": 5}, {"name": "read_text_file", "arguments": []}]
        for params in bad_params:
            response = self.server.handle({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": params})
            self.assertErrorCode(response, demo_mcp_server.INVALID_PARAMS)
        self.assertErrorCode(self.server.handle(call("no_such_tool")), demo_mcp_server.INVALID_PARAMS)
        self.assertErrorCode(self.server.handle(call("read_text_file", {"path": 3})), demo_mcp_server.INVALID_PARAMS)


class ReadTextFileTests(ServerTestCase):
    def test_reads_relative_and_absolute_paths_inside_root(self):
        self.assertText(self.server.handle(call("read_text_file", {"path": "notes.txt"})), "hello\n")
        absolute = str(self.root / "notes.txt")
        self.assertText(self.server.handle(call("read_text_file", {"path": absolute})), "hello\n")

    def test_rejects_paths_outside_root(self):
        for path in ("../outside.txt", "/etc/hosts", "sub/../../x"):
            response = self.server.handle(call("read_text_file", {"path": path}))
            self.assertErrorCode(response, demo_mcp_server.ACCESS_DENIED)

    def test_rejects_symlink_escaping_root(self):
        (self.root / "link").symlink_to("/etc")
        response = self.server.handle(call("read_text_file", {"path": "link/hosts"}))
        self.assertErrorCode(response, demo_mcp_server.ACCESS_DENIED)

    def test_reports_unreadable_targets_as_errors(self):
        cases = {
            "missing.txt": demo_mcp_server.FILE_NOT_FOUND,
            "sub": demo_mcp_server.INVALID_PARAMS,
            "binary.dat": demo_mcp_server.INVALID_PARAMS,
        }
        for path, code in cases.items():
            with self.subTest(path=path):
                self.assertErrorCode(self.server.handle(call("read_text_file", {"path": path})), code)


class RunCommandTests(ServerTestCase):
    def test_allowed_commands_run_inside_root(self):
        self.assertText(self.server.handle(call("run_command", {"command": "pwd"})), os.path.realpath(self.root) + "\n")
        self.assertText(self.server.handle(call("run_command", {"command": "echo 'a b'"})), "a b\n")
        listing = self.server.handle(call("run_command", {"command": "ls -1 sub ."}))
        self.assertIn("notes.txt", listing["result"]["content"][0]["text"])

    def test_disallowed_and_malformed_commands(self):
        cases = {
            "cat notes.txt": demo_mcp_server.COMMAND_NOT_ALLOWED,
            "": demo_mcp_server.INVALID_PARAMS,
            "echo 'unterminated": demo_mcp_server.INVALID_PARAMS,
        }
        for command, code in cases.items():
            with self.subTest(command=command):
                self.assertErrorCode(self.server.handle(call("run_command", {"command": command})), code)

    def test_ls_cannot_list_outside_root(self):
        for command in ("ls /", "ls -la ..", "ls -- /etc", "ls sub/../.."):
            with self.subTest(command=command):
                response = self.server.handle(call("run_command", {"command": command}))
                self.assertErrorCode(response, demo_mcp_server.ACCESS_DENIED)

    def test_list_allowed_directories(self):
        self.assertText(self.server.handle(call("list_allowed_directories")), os.path.realpath(self.root))


class StdioTests(ServerTestCase):
    def test_serves_over_stdio_and_survives_bad_input(self):
        lines = [
            "not json",
            json.dumps([1]),
            json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}),
            json.dumps(call("read_text_file", {"path": "binary.dat"}, request_id=2)),
            json.dumps({"jsonrpc": "2.0", "id": 3, "method": "ping"}),
        ]
        completed = subprocess.run(
            [sys.executable, str(SERVER_PATH), str(self.root)],
            input="\n".join(lines) + "\n",
            capture_output=True,
            text=True,
            timeout=10,
            check=True,
        )
        responses = [json.loads(line) for line in completed.stdout.splitlines()]
        self.assertEqual(
            [(r["id"], r.get("error", {}).get("code")) for r in responses],
            [
                (None, demo_mcp_server.PARSE_ERROR),
                (None, demo_mcp_server.INVALID_REQUEST),
                (2, demo_mcp_server.INVALID_PARAMS),
                (3, None),
            ],
        )
        self.assertEqual(completed.stderr, "")


if __name__ == "__main__":
    unittest.main()
