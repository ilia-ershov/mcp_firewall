"""End-to-end checks of the demo scenarios as the live demo runs them."""

import filecmp
import json
import os
import re
import subprocess
import tempfile
import unittest
from pathlib import Path

import firewall
from run_demo import PROMPT_STEPS, ROOT, SCENARIO_DIRS, StdioClient, build_command

SHELL_SCRIPTS = sorted(ROOT.glob("*.sh")) + sorted(ROOT.glob("*_fw/run.sh"))


def replay_prompt(command):
    with StdioClient(command) as client:
        client.initialize()
        responses = [client.call_tool(name, arguments) for name, arguments in PROMPT_STEPS]
    return responses, client.stderr


def error_codes(responses):
    return [response.get("error", {}).get("code") for response in responses]


class ScenarioTests(unittest.TestCase):
    def test_unsafe_scenario_exposes_everything(self):
        responses, stderr = replay_prompt(build_command("unsafe"))
        self.assertEqual(error_codes(responses), [None] * len(PROMPT_STEPS))
        texts = [response["result"]["content"][0]["text"] for response in responses]
        self.assertIn("DB_PASSWORD=supersecret", texts[0])
        self.assertEqual(texts[1].strip(), str(SCENARIO_DIRS["unsafe"]))
        self.assertIn("Ignore previous instructions", texts[2])
        self.assertEqual(stderr, "")

    def test_safe_scenario_redacts_and_blocks(self):
        responses, stderr = replay_prompt(build_command("safe"))
        self.assertEqual(
            error_codes(responses),
            [None, firewall.TOOL_BLOCKED, firewall.INJECTION_BLOCKED, firewall.ENCODED_BLOCKED, firewall.INJECTION_BLOCKED],
        )
        config = responses[0]["result"]
        for text in (config["content"][0]["text"], config["structuredContent"]["content"]):
            self.assertEqual(text, f"DB_PASSWORD={firewall.REDACTION}\nAWS_ACCESS_KEY_ID={firewall.REDACTION}\n")
        self.assertEqual(stderr, "")

    def test_scenario_launchers(self):
        for mode, expected in (("unsafe", None), ("safe", firewall.TOOL_BLOCKED)):
            with self.subTest(mode=mode), StdioClient(["bash", str(SCENARIO_DIRS[mode] / "run.sh")]) as client:
                client.initialize()
                response = client.call_tool("run_command", {"command": "pwd"})
                self.assertEqual(response.get("error", {}).get("code"), expected)


FAKE_OLLMCP = """#!/usr/bin/env bash
set -e
printf '%s\\n' "$@" > "$FAKE_OUT/args"
printf '%s\\n' "$HOME" "$PWD" > "$FAKE_OUT/env"
cp "$2" "$FAKE_OUT/servers.json"
cp "$HOME/.config/ollmcp/config.json" "$FAKE_OUT/config.json"
"""


class LauncherTests(unittest.TestCase):
    """Run the ollmcp launchers against a fake ollmcp that records how it was started."""

    def run_launcher(self, script):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        bin_dir, out_dir, tmp_dir = (Path(tmp.name) / name for name in ("bin", "out", "tmp"))
        for directory in (bin_dir, out_dir, tmp_dir):
            directory.mkdir()
        fake = bin_dir / "ollmcp"
        fake.write_text(FAKE_OLLMCP, encoding="utf-8")
        fake.chmod(0o755)
        env = {
            **os.environ,
            "PATH": f"{bin_dir}{os.pathsep}{os.environ['PATH']}",
            "TMPDIR": str(tmp_dir),
            "OLLAMA_MODEL": "test-model",
            "FAKE_OUT": str(out_dir),
        }
        subprocess.run([str(ROOT / script)], env=env, check=True, timeout=30)
        self.assertEqual(list(tmp_dir.iterdir()), [], "the launcher left its temporary state behind")
        return out_dir

    def test_launchers_configure_ollmcp_and_clean_up(self):
        for script, scenario in (("run_safe.sh", "safe"), ("run_unsafe.sh", "unsafe")):
            with self.subTest(script=script):
                out = self.run_launcher(script)
                home, cwd = (out / "env").read_text(encoding="utf-8").splitlines()
                state = Path(home).parent
                self.assertEqual(Path(cwd).resolve(), state.resolve())
                args = (out / "args").read_text(encoding="utf-8").splitlines()
                self.assertEqual(
                    args, ["--servers-json", str(state / "servers.json"), "--provider", "ollama", "--model", "test-model"]
                )
                servers = json.loads((out / "servers.json").read_text(encoding="utf-8"))
                self.assertEqual(
                    servers["mcpServers"]["demo"], {"command": "bash", "args": [str(SCENARIO_DIRS[scenario] / "run.sh")]}
                )
                config = json.loads((out / "config.json").read_text(encoding="utf-8"))
                self.assertEqual(config["providers"]["ollama"]["model"], "test-model")

    def test_rejects_unknown_scenarios(self):
        completed = subprocess.run([str(ROOT / "run_ollmcp.sh"), "nope"], capture_output=True, text=True)
        self.assertEqual(completed.returncode, 2)
        self.assertIn("Usage", completed.stderr)


class ConsistencyTests(unittest.TestCase):
    def test_prompts_match_the_replayed_steps(self):
        step_pattern = re.compile(r"^\d+\. Call `(\w+)` with (\w+) `([^`]+)`\.$", re.MULTILINE)
        for directory in SCENARIO_DIRS.values():
            with self.subTest(prompt=directory.name):
                prompt = (directory / "PROMPT.txt").read_text(encoding="utf-8")
                steps = [(name, {key: value}) for name, key, value in step_pattern.findall(prompt)]
                self.assertEqual(steps, PROMPT_STEPS)

    def test_both_scenarios_use_identical_demo_data(self):
        unsafe, safe = (directory / "demo_data" for directory in SCENARIO_DIRS.values())
        comparison = filecmp.dircmp(unsafe, safe)
        self.assertEqual(comparison.left_only + comparison.right_only, [])
        _, mismatch, errors = filecmp.cmpfiles(unsafe, safe, comparison.common_files, shallow=False)
        self.assertEqual(mismatch + errors, [])

    def test_shell_scripts_parse(self):
        self.assertTrue(SHELL_SCRIPTS)
        for script in SHELL_SCRIPTS:
            with self.subTest(script=script.name):
                subprocess.run(["bash", "-n", str(script)], check=True)


if __name__ == "__main__":
    unittest.main()
