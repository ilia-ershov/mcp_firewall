"""End-to-end checks of the demo scenarios as the live demo runs them."""

import filecmp
import re
import subprocess
import unittest

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
