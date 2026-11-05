"""Edge cases found by hand before 0.1.2: wrong types, odd names, duplicate servers."""
import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from mcplint import cli, exitcode


class EdgeCaseTests(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        self.root = Path(self.td.name)

    def tearDown(self):
        self.td.cleanup()

    def config(self, data, name="c.json"):
        path = self.root / name
        path.write_text(json.dumps(data), encoding="utf-8")
        return str(path)

    def scan(self, argv):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
            code = cli.main(argv)
        return code, buf.getvalue()

    def test_empty_server_block_is_a_pass_not_a_guess(self):
        code, out = self.scan(["scan", self.config({"mcpServers": {}})])
        self.assertEqual(code, exitcode.OK)
        self.assertNotIn("MCP000", out)

    def test_wrong_type_is_unknown_not_a_crash(self):
        for field, value in (("command", 123), ("url", ["http://a"]), ("args", "-y pkg"),
                             ("autoApprove", "read_file"), ("tools", {"a": 1})):
            with self.subTest(field=field):
                code, out = self.scan(["scan", self.config({"mcpServers": {"x": {field: value}}})])
                self.assertEqual(code, exitcode.FINDINGS)
                self.assertIn("MCP009", out)

    def test_pointer_escapes_slashes_in_names(self):
        data = {"mcpServers": {"a/b": {"command": "sh", "args": ["-c", "ls"]}}}
        _, out = self.scan(["scan", self.config(data)])
        self.assertIn("/mcpServers/a~1b/command", out)

    def test_dash_c_only_counts_as_a_command_string(self):
        quiet = {"mcpServers": {"x": {"command": "git", "args": ["-c", "user.name=x", "status"]}}}
        _, out = self.scan(["scan", self.config(quiet)])
        self.assertNotIn("MCP001", out)
        loud = {"mcpServers": {"x": {"command": "python", "args": ["-c", "import os; os.system(1)"]}}}
        _, out = self.scan(["scan", self.config(loud)])
        self.assertIn("MCP001", out)

    def test_parent_dir_is_a_path_segment_not_a_substring(self):
        quiet = {"mcpServers": {"x": {"command": "npx", "roots": ["/repo/my..thing"]}}}
        _, out = self.scan(["scan", self.config(quiet)])
        self.assertNotIn("MCP004", out)
        loud = {"mcpServers": {"x": {"command": "npx", "roots": ["/repo/../etc"]}}}
        _, out = self.scan(["scan", self.config(loud)])
        self.assertIn("MCP004", out)

    def test_schema_needs_no_type_keyword(self):
        data = {"mcpServers": {"x": {"command": "npx", "tools": [
            {"name": "t", "inputSchema": {"properties": {"p": {"type": "string"}}}}]}}}
        _, out = self.scan(["scan", self.config(data)])
        self.assertNotIn("MCP006", out)

    def test_duplicate_server_names_across_files_are_an_error(self):
        a = self.config({"mcpServers": {"s": {"command": "npx"}}}, "a.json")
        b = self.config({"mcpServers": {"s": {"command": "sh", "args": ["-c", "ls"]}}}, "b.json")
        code, out = self.scan(["scan", a, b])
        self.assertEqual(code, exitcode.FINDINGS)
        self.assertIn("MCP011", out)

    def test_bom_from_windows_editors_is_accepted(self):
        path = self.root / "bom.json"
        path.write_text(json.dumps({"mcpServers": {"x": {"command": "npx"}}}), encoding="utf-8-sig")
        code, _ = self.scan(["scan", str(path)])
        self.assertEqual(code, exitcode.OK)

    def test_unknown_rule_id_is_a_usage_error_not_a_silent_pass(self):
        cfg = self.config({"mcpServers": {"x": {"command": "npx"}}})
        code, out = self.scan(["scan", cfg, "--rule", "MCP999"])
        self.assertEqual(code, exitcode.USAGE)
        self.assertIn("unknown rule id: MCP999", out)

    def test_a_typo_in_the_flags_is_not_read_as_drift(self):
        with self.assertRaises(SystemExit) as caught:
            with contextlib.redirect_stderr(io.StringIO()):
                cli.main(["--bogus"])
        self.assertEqual(caught.exception.code, exitcode.USAGE)

    def test_unknown_policy_version_is_a_usage_error(self):
        bad = self.root / "policy.json"
        bad.write_text(json.dumps({"version": 99, "servers": {}}), encoding="utf-8")
        cfg = self.config({"mcpServers": {"x": {"command": "npx"}}})
        code, out = self.scan(["check", cfg, "--baseline", str(bad)])
        self.assertEqual(code, exitcode.USAGE)
        self.assertIn("unsupported policy version", out)


if __name__ == "__main__":
    unittest.main()
