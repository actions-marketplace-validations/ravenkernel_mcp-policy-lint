"""Approval leaves a receipt; SARIF makes the receipt readable by a machine."""
import contextlib
import io
import json
import os
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from mcp_policy_lint import cli, exitcode
from mcp_policy_lint.policy import load_policy

SAFE = {"mcpServers": {"c": {"command": "npx", "args": ["-y", "@acme/server@1.2.3"]}}}
PLUS = {"mcpServers": {"c": {"command": "npx", "args": ["-y", "@acme/server@1.2.3"],
                             "autoApprove": ["read_anything"]}}}
MIXED = {"mcpServers": {"r": {"url": "http://api.example.com/mcp"},
                        "c": {"command": "npx", "autoApprove": ["delete_everything"]}}}


def run_cli(argv):
    with contextlib.redirect_stdout(io.StringIO()):
        return cli.main(argv)


class _Base(unittest.TestCase):
    def setUp(self):
        self.td = TemporaryDirectory()
        self.root = Path(self.td.name)

    def tearDown(self):
        self.td.cleanup()

    def write(self, name, obj):
        p = self.root / name
        p.write_text(json.dumps(obj), encoding="utf-8")
        return str(p)


class ApproveTests(_Base):
    def test_an_approval_without_a_reason_is_a_usage_error(self):
        p = self.write("a.json", SAFE)
        with self.assertRaises(SystemExit) as caught:
            run_cli(["approve", p, "--baseline", str(self.root / "policy.json")])
        self.assertEqual(caught.exception.code, exitcode.USAGE)

    def test_approve_moves_the_baseline_and_leaves_a_receipt(self):
        base = str(self.root / "policy.json")
        self.assertEqual(run_cli(["init", self.write("a.json", SAFE), "--out", base]), exitcode.OK)
        p = self.write("a.json", PLUS)
        self.assertEqual(run_cli(["check", p, "--baseline", base]), exitcode.DRIFT)

        self.assertEqual(run_cli(["approve", p, "--baseline", base,
                                  "--reason", "audited the new approval list", "--by", "alice"]),
                         exitcode.OK)
        self.assertEqual(run_cli(["check", p, "--baseline", base]), exitcode.OK)

        pol = load_policy(Path(base).read_text(encoding="utf-8"))
        self.assertEqual(len(pol.approvals), 1)
        entry = pol.approvals[0]
        self.assertEqual((entry["by"], entry["reason"]), ("alice", "audited the new approval list"))
        self.assertTrue(entry["id"])
        self.assertTrue(entry["at"].endswith("Z"))
        self.assertIn("auto_approve_added", {c["kind"] for c in entry["changes"]})
        self.assertEqual({c["server"] for c in entry["changes"]}, {"c"})

    def test_approving_nothing_writes_nothing(self):
        base = str(self.root / "policy.json")
        p = self.write("a.json", SAFE)
        self.assertEqual(run_cli(["init", p, "--out", base]), exitcode.OK)
        before = Path(base).read_text(encoding="utf-8")

        self.assertEqual(run_cli(["approve", p, "--baseline", base, "--reason", "no-op"]), exitcode.OK)
        self.assertEqual(Path(base).read_text(encoding="utf-8"), before)

    def test_approve_can_write_a_new_baseline_and_leave_the_old_one_alone(self):
        base = str(self.root / "policy.json")
        self.assertEqual(run_cli(["init", self.write("a.json", SAFE), "--out", base]), exitcode.OK)
        before = Path(base).read_text(encoding="utf-8")
        nxt = str(self.root / "policy.next.json")

        p = self.write("a.json", PLUS)
        self.assertEqual(run_cli(["approve", p, "--baseline", base, "--out", nxt,
                                  "--reason", "staged"]), exitcode.OK)
        self.assertEqual(Path(base).read_text(encoding="utf-8"), before)
        self.assertEqual(run_cli(["check", p, "--baseline", nxt]), exitcode.OK)


class SarifTests(_Base):
    def test_scan_sarif_has_one_rule_per_id_and_honest_levels(self):
        p = self.write("config.json", MIXED)
        cwd = os.getcwd()
        os.chdir(self.root)
        try:
            out = str(self.root / "report.sarif")
            self.assertEqual(run_cli(["scan", "config.json", "--format", "sarif", "--out", out]),
                             exitcode.FINDINGS)
            doc = json.loads(Path(out).read_text(encoding="utf-8"))
        finally:
            os.chdir(cwd)

        self.assertEqual(doc["version"], "2.1.0")
        run = doc["runs"][0]
        levels = {r["ruleId"]: r["level"] for r in run["results"]}
        self.assertEqual(levels["POL003"], "error")
        self.assertEqual(levels["POL010"], "warning")
        self.assertEqual(len(run["tool"]["driver"]["rules"]), len(levels))

        first = run["results"][0]
        uri = first["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        self.assertEqual(uri, "config.json")
        self.assertTrue(first["locations"][0]["logicalLocations"][0]["fullyQualifiedName"]
                        .startswith("/mcpServers/"))
        self.assertIn("partialFingerprints", first)

    def test_check_sarif_reports_drift_with_its_own_exit_code(self):
        base = str(self.root / "policy.json")
        self.assertEqual(run_cli(["init", self.write("a.json", SAFE), "--out", base]), exitcode.OK)
        p = self.write("a.json", PLUS)
        out = str(self.root / "drift.sarif")
        self.assertEqual(run_cli(["check", p, "--baseline", base, "--format", "sarif", "--out", out]),
                         exitcode.DRIFT)

        doc = json.loads(Path(out).read_text(encoding="utf-8"))
        run = doc["runs"][0]
        self.assertIn("DRIFT", {r["ruleId"] for r in run["results"]})
        self.assertEqual(run["invocations"][0]["exitCode"], exitcode.DRIFT)
