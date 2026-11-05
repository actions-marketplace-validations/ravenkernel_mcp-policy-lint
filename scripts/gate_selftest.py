"""Reproducible proof of the gate: every fixture names the exit code it must produce.

Usage: python scripts/gate_selftest.py   (no install required)
"""
from __future__ import annotations

import contextlib
import io
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from mcplint import cli  # noqa: E402

FIXTURES = ROOT / "fixtures" / "gate"

# (fixture, extra argv, expected exit code)
CASES = [
    ("safe.json", [], 0),
    ("unknown-shape.json", [], 1),
    ("unmodeled-transport.json", [], 1),
    ("unmodeled-transport.json", ["--unknown", "warn"], 0),
    ("unmodeled-transport.json", ["--unknown", "ignore"], 0),
    ("windsurf-serverurl-http.json", [], 1),
    ("cline-autoapprove.json", [], 0),
    ("cline-autoapprove.json", ["--strict"], 1),
    ("cline-autoapprove-secret.json", [], 1),
    ("localhost-http.json", [], 0),
]


def run(argv):
    with contextlib.redirect_stdout(io.StringIO()) as buf:
        return cli.main(argv), buf.getvalue()


def drift():
    """Same config plus one more pre-approved tool: baseline drift, exit 2."""
    with tempfile.TemporaryDirectory() as tmp:
        lock = Path(tmp) / "policy.lock.json"
        code, out = run(["init", str(FIXTURES / "cline-autoapprove.json"), "--out", str(lock)])
        if code != 0:
            return code, "init failed: " + out
        return run(["check", str(FIXTURES / "cline-autoapprove-plus.json"), "--baseline", str(lock)])


def main():
    print(f"{'fixture':<32}{'argv':<28}{'want':>5}{'got':>5}")
    failures = 0
    for name, extra, want in CASES:
        got, _ = run(["check", str(FIXTURES / name)] + extra)
        ok = got == want
        failures += 0 if ok else 1
        label = " ".join(extra) or "(default)"
        print(f"{name:<32}{label:<28}{want:>5}{got:>5}  {'ok' if ok else 'MISMATCH'}")

    got, out = drift()
    ok = got == 2
    failures += 0 if ok else 1
    print(f"{'cline-autoapprove-plus.json':<32}{'(drift)':<28}{2:>5}{got:>5}  {'ok' if ok else 'MISMATCH'}")
    if not ok:
        print(out)

    total = len(CASES) + 1
    print(f"\n{total - failures}/{total} cases match")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
