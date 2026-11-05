"""CLI: pure orchestration. Every module below is independently testable."""
from __future__ import annotations

import argparse
import json
import sys
import tempfile
from pathlib import Path

from . import __version__, exitcode
from .discover import discover
from .diff import diff
from .model import Policy
from .normalize import from_paths, normalize
from .policy import build_policy, load_policy
from .report import render_coverage, render_html, render_json, render_ndjson, render_text
from .rules import REGISTRY, evaluate
from .samples import SAFE_MCP, UNSAFE_MCP


def _collect(paths):
    files = discover(paths)
    if not files:
        raise FileNotFoundError("no MCP config found at: " + ", ".join(paths))
    servers, notes = from_paths(files)
    return files, servers, notes


_ORDER = {"error": 0, "warn": 1, "info": 2}


def _findings(servers, notes, only):
    return notes + evaluate(servers, enabled=set(only) if only else None)


def _resolved(servers, notes, only, mode):
    """Resolve unknown severities, then re-sort so the worst findings read first."""
    out = exitcode.resolve(_findings(servers, notes, only), mode)
    return sorted(out, key=lambda f: (_ORDER.get(f.severity, 3), f.server, f.rule_id))


def _emit(text, out=None):
    if out:
        Path(out).write_text(text, encoding="utf-8")
        print(f"wrote {out}")
    else:
        sys.stdout.write(text)


def cmd_scan(args):
    _, servers, notes = _collect(args.path)
    findings = _resolved(servers, notes, args.rule, args.unknown)
    code = exitcode.decide(findings, [], args.strict)
    if args.format == "text":
        _emit(render_text(findings, [], code))
    elif args.format == "ndjson":
        _emit(render_ndjson(findings, []))
    elif args.format == "json":
        _emit(render_json(findings, [], code))
    else:
        _emit(render_html(findings, [], code), args.html_out or "report.html")
    return code


def cmd_init(args):
    _, servers, _ = _collect(args.path)
    policy = build_policy(servers)
    Path(args.out).write_text(policy.to_json(), encoding="utf-8")
    print(f"policy baseline: {args.out} ({len(policy.servers)} servers approved)")
    return exitcode.OK


def cmd_diff(args):
    _, servers, _ = _collect(args.path)
    base = load_policy(Path(args.baseline).read_text(encoding="utf-8"))
    rows = diff(servers, base)
    code = exitcode.decide([], rows, args.strict)
    _emit(render_text([], rows, code))
    return code


def cmd_check(args):
    _, servers, notes = _collect(args.path)
    findings = _resolved(servers, notes, args.rule, args.unknown)
    rows = []
    if args.baseline:
        base = load_policy(Path(args.baseline).read_text(encoding="utf-8"))
        rows = diff(servers, base)
    code = exitcode.decide(findings, rows, args.strict)
    _emit(render_text(findings, rows, code))
    return code


def cmd_coverage(args):
    files, servers, notes = _collect(args.path)
    findings = _resolved(servers, notes, args.rule, args.unknown)
    _emit(render_coverage(files, servers, findings))
    return exitcode.OK


def cmd_rules(args):
    for rid, fn in sorted(REGISTRY.items()):
        print(f"{rid}  {fn.__doc__.strip().splitlines()[0] if fn.__doc__ else fn.__name__}")
    return exitcode.OK


def cmd_demo(args):
    """30-second, offline, no API key, no Docker."""
    with tempfile.TemporaryDirectory() as td:
        safe = Path(td) / "safe.mcp.json"
        unsafe = Path(td) / "unsafe.mcp.json"
        policy_file = Path(td) / "policy.lock.json"
        safe.write_text(SAFE_MCP, encoding="utf-8")
        unsafe.write_text(UNSAFE_MCP, encoding="utf-8")
        s_safe, _ = from_paths([safe])
        policy_file.write_text(build_policy(s_safe).to_json(), encoding="utf-8")
        s_bad, notes = from_paths([unsafe])
        findings = exitcode.resolve(notes + evaluate(s_bad), "error")
        rows = diff(s_bad, load_policy(policy_file.read_text(encoding="utf-8")))
        code = exitcode.decide(findings, [], strict=False)
        print(f"mcplint demo — {len(s_bad)} servers scanned, {len(findings)} findings")
        print("no network, no API key, no Docker")
        print(f"(vs sample baseline: {len(rows)} drift rows — run `mcplint diff` to inspect)\n")
        sys.stdout.write(render_text(findings, [], code))
        sys.stdout.write(render_coverage([unsafe], s_bad, findings))
    return code


def build_parser():
    p = argparse.ArgumentParser(prog="mcplint", description=__doc__)
    p.add_argument("--version", action="version", version=f"mcplint {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    def common(sp, with_path=True):
        if with_path:
            sp.add_argument("path", nargs="+", help="config file or directory")
        sp.add_argument("--rule", action="append", help="only run rule id (repeatable)")
        sp.add_argument("--strict", action="store_true", help="warn also fails")
        sp.add_argument("--unknown", choices=exitcode.UNKNOWN_MODES, default="error",
                        help="how much 'unknown' costs (default: error)")

    s = sub.add_parser("scan", help="lint a config and render findings")
    common(s)
    s.add_argument("--format", choices=["text", "ndjson", "json", "html"], default="text")
    s.add_argument("--html-out", help="output path for --format html")
    s.set_defaults(func=cmd_scan)

    s = sub.add_parser("init", help="write an approved policy baseline")
    s.add_argument("path", nargs="+")
    s.add_argument("--out", default="policy.lock.json")
    s.set_defaults(func=cmd_init)

    s = sub.add_parser("diff", help="compare config against the baseline")
    common(s)
    s.add_argument("--baseline", default="policy.lock.json")
    s.set_defaults(func=cmd_diff)

    s = sub.add_parser("check", help="CI gate: findings + drift -> exit code")
    common(s)
    s.add_argument("--baseline", help="policy.lock.json")
    s.set_defaults(func=cmd_check)

    s = sub.add_parser("coverage", help="what the scan consumed, and what it could not")
    common(s)
    s.set_defaults(func=cmd_coverage)

    s = sub.add_parser("rules", help="list registered rules")
    s.set_defaults(func=cmd_rules)

    s = sub.add_parser("demo", help="30s offline walkthrough, zero setup")
    s.set_defaults(func=cmd_demo)
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return int(args.func(args))
    except (FileNotFoundError, ValueError, json.JSONDecodeError) as exc:
        print(f"mcplint: {exc}", file=sys.stderr)
        return exitcode.USAGE
