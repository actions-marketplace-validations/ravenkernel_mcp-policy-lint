import contextlib
import importlib.util
import io
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def load():
    spec = importlib.util.spec_from_file_location("gate_selftest", ROOT / "scripts" / "gate_selftest.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class GateSelfTest(unittest.TestCase):
    def test_every_fixture_produces_its_declared_exit_code(self):
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(load().main(), 0)


if __name__ == "__main__":
    unittest.main()
