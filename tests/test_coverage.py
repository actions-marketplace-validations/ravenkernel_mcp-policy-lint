"""The honesty layer: what the tool did not understand must not read as a pass."""
import contextlib
import io
import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from mcplint import cli, exitcode
from mcplint.diff import diff
from mcplint.model import Policy
from mcplint.normalize import normalize
from mcplint.policy import build_policy
from mcplint.rules import evaluate


def run_cli(argv):
    with contextlib.redirect_stdout(io.StringIO()):
        return cli.main(argv)


class CoverageTests(unittest.TestCase):
    def setUp(self):
        self.td = TemporaryDirectory()
        self.root = Path(self.td.name)

    def tearDown(self):
        self.td.cleanup()

    def write(self, name, obj):
        p = self.root / name
        p.write_text(json.dumps(obj), encoding="utf-8")
        return str(p)

    def test_unrecognized_shape_cannot_pass(self):
        p = self.write("a.json", {"serversV2": {"x": {"command": "npx"}}})
        servers, notes = normalize(json.loads(Path(p).read_text()), source=p)
        self.assertEqual(servers, [])
        self.assertTrue(notes and all(f.unknown for f in notes))
        self.assertEqual(exitcode.decide(exitcode.resolve(notes), []), exitcode.FINDINGS)
        self.assertEqual(run_cli(["check", p]), exitcode.FINDINGS)

    def test_unmodeled_field_fails_by_default_and_can_be_relaxed(self):
        p = self.write("d.json", {"mcpServers": {"d": {"command": "npx",
                                                       "transport": {"type": "sse"}}}})
        servers, notes = normalize(json.loads(Path(p).read_text()), source=p)
        self.assertEqual(servers[0].unmodeled, ["transport"])
        self.assertIn("MCP009", {f.rule_id for f in notes})
        self.assertEqual(run_cli(["check", p]), exitcode.FINDINGS)
        self.assertEqual(run_cli(["check", p, "--unknown", "warn"]), exitcode.OK)
        self.assertEqual(run_cli(["check", p, "--unknown", "warn", "--strict"]), exitcode.FINDINGS)
        self.assertEqual(run_cli(["check", p, "--unknown", "ignore"]), exitcode.OK)

    def test_windsurf_serverurl_is_read_and_pointer_is_honest(self):
        p = self.write("b.json", {"mcpServers": {"w": {"serverUrl": "http://api.example.com/mcp",
                                                       "disabled": False}}})
        servers, notes = normalize(json.loads(Path(p).read_text()), source=p)
        self.assertEqual(servers[0].url, "http://api.example.com/mcp")
        self.assertEqual(notes, [])
        hits = [f for f in evaluate(servers) if f.rule_id == "MCP003"]
        self.assertTrue(hits)
        self.assertEqual(hits[0].pointer, "/mcpServers/w/serverUrl")
        self.assertEqual(hits[0].severity, "error")

    def test_loopback_plaintext_is_a_warning(self):
        p = self.write("e.json", {"mcpServers": {"l": {"url": "http://localhost:3000/mcp"}}})
        servers, _ = normalize(json.loads(Path(p).read_text()), source=p)
        hits = [f for f in evaluate(servers) if f.rule_id == "MCP003"]
        self.assertEqual([h.severity for h in hits], ["warn"])
        self.assertEqual(run_cli(["check", p]), exitcode.OK)

    def test_auto_approve_is_reported_and_locked(self):
        p = self.write("c.json", {"mcpServers": {"c": {"command": "npx",
                                                       "autoApprove": ["delete_everything"]}}})
        servers, _ = normalize(json.loads(Path(p).read_text()), source=p)
        self.assertEqual([f.rule_id for f in evaluate(servers)], ["MCP010"])
        live = build_policy(servers).servers["c"]
        self.assertEqual(live["auto_approve"], ["delete_everything"])
        approved = Policy(version=1, servers={"c": dict(live, auto_approve=[])})
        self.assertTrue(any(r.kind == "auto_approve_added" for r in diff(servers, approved)))

    def test_coverage_table_names_what_was_not_consumed(self):
        p = self.write("d.json", {"mcpServers": {"d": {"command": "npx",
                                                       "transport": {"type": "sse"}}}})
        with contextlib.redirect_stdout(io.StringIO()) as buf:
            self.assertEqual(cli.main(["coverage", p]), exitcode.OK)
        out = buf.getvalue()
        self.assertIn("transport", out)
        self.assertIn("unknown, not pass", out)


if __name__ == "__main__":
    unittest.main()
