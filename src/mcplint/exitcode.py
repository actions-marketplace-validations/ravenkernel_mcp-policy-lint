"""Exit code contract. Precedence: 3 > 2 > 1 > 0."""
from __future__ import annotations

from dataclasses import replace

OK = 0
FINDINGS = 1
DRIFT = 2
USAGE = 3

MEANING = {
    OK: "pass",
    FINDINGS: "findings failed",
    DRIFT: "policy drift / incompatible schema",
    USAGE: "usage or config error",
}

UNKNOWN_MODES = ("error", "warn", "ignore")


def resolve(findings, mode: str = "error"):
    """Give 'unknown' a price. mode decides how high.

    unknown means the rule could not judge: shape unrecognized, field not modeled,
    transport undeclared. Reporting it as a pass is the one lie this tool must not tell.
    """
    if mode not in UNKNOWN_MODES:
        raise ValueError(f"--unknown must be one of {UNKNOWN_MODES}, got {mode!r}")
    if mode == "ignore":
        return [f for f in findings if not getattr(f, "unknown", False)]
    return [replace(f, severity=mode) if getattr(f, "unknown", False) else f for f in findings]


def decide(findings, diffs, strict: bool = False) -> int:
    """findings: list[Finding] after resolve(); diffs: list[DiffRow]."""
    if any(d.severity == "error" for d in diffs):
        return DRIFT
    if any(f.severity == "error" for f in findings):
        return FINDINGS
    if strict and (any(f.severity == "warn" for f in findings)
                   or any(d.severity == "warn" for d in diffs)):
        return FINDINGS
    return OK
