import unittest

from mcplint.model import ServerSpec, ToolSpec
from mcplint.rules import REGISTRY, evaluate
from mcplint.samples import SAFE_MCP, UNSAFE_MCP
from mcplint.normalize import normalize
import json


class RuleTests(unittest.TestCase):
    def setUp(self):
        self.safe = normalize(json.loads(SAFE_MCP))[0]
        self.unsafe = normalize(json.loads(UNSAFE_MCP))[0]

    def test_safe_config_has_no_errors(self):
        findings = evaluate(self.safe)
        self.assertFalse([f for f in findings if f.severity == "error"], findings)

    def test_unsafe_triggers_multiple_rules(self):
        ids = {f.rule_id for f in evaluate(self.unsafe)}
        self.assertTrue({"MCP001", "MCP002", "MCP004", "MCP005", "MCP006"} <= ids, ids)

    def test_plaintext_remote(self):
        servers = normalize(json.loads(UNSAFE_MCP))[0]
        remote = [s for s in servers if s.name == "remote"][0]
        self.assertTrue(any(f.rule_id == "MCP003" for f in evaluate([remote])))

    def test_registry_is_populated(self):
        self.assertGreaterEqual(len(REGISTRY), 7)

    def test_every_finding_has_pointer_and_remediation(self):
        for f in evaluate(self.unsafe):
            self.assertTrue(f.pointer.startswith("/"))
            self.assertTrue(f.remediation)


if __name__ == "__main__":
    unittest.main()
