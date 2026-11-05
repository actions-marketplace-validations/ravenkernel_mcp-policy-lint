import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from mcp_policy_lint import cli, exitcode
from mcp_policy_lint.samples import SAFE_MCP, UNSAFE_MCP
from mcp_policy_lint.model import Policy
from mcp_policy_lint.policy import build_policy, load_policy
from mcp_policy_lint.normalize import from_paths
from mcp_policy_lint.diff import diff


class E2ETests(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        self.root = Path(self.td.name)
        (self.root / "safe.json").write_text(SAFE_MCP, encoding="utf-8")
        (self.root / "unsafe.json").write_text(UNSAFE_MCP, encoding="utf-8")
        self.safe, self.unsafe = str(self.root / "safe.json"), str(self.root / "unsafe.json")

    def tearDown(self):
        self.td.cleanup()

    def run_cli(self, argv):
        with contextlib.redirect_stdout(io.StringIO()):
            return cli.main(argv)

    def test_demo_is_offline_and_fails(self):
        # CLI returns a failing code on the intentionally unsafe fixture.
        self.assertEqual(self.run_cli(["demo"]), exitcode.FINDINGS)

    def test_init_then_check_produces_drift(self):
        out = str(self.root / "policy.lock.json")
        self.assertEqual(self.run_cli(["init", self.safe, "--out", out]), exitcode.OK)
        policy = load_policy(Path(out).read_text(encoding="utf-8"))
        self.assertIn("files", policy.servers)
        servers, _ = from_paths([Path(self.unsafe)])
        rows = diff(servers, policy)
        self.assertTrue(any(r.kind == "server_added" for r in rows))
        self.assertEqual(self.run_cli(["check", self.unsafe, "--baseline", out]),
                         exitcode.DRIFT)

    def test_scan_json_is_machine_readable(self):
        self.assertEqual(self.run_cli(["scan", self.unsafe, "--format", "json"]),
                         exitcode.FINDINGS)

    def test_html_is_self_contained(self):
        from mcp_policy_lint.report import render_html
        from mcp_policy_lint.rules import evaluate
        from mcp_policy_lint.normalize import from_paths as fp
        servers, _ = fp([Path(self.unsafe)])
        page = render_html(evaluate(servers), [], 1)
        self.assertIn("<!doctype html>", page)
        self.assertNotIn("<script src", page)
        self.assertNotIn("<link ", page)

    def test_missing_file_is_usage_error(self):
        self.assertEqual(self.run_cli(["scan", str(self.root / "nope.json")]),
                         exitcode.USAGE)


if __name__ == "__main__":
    unittest.main()
