"""Renderers. HTML is a single self-contained file, no external resources."""
from __future__ import annotations

import html
import json
from pathlib import Path

from . import __version__
from .model import DiffRow, Finding


def _rows(findings, diffs):
    return [f.as_dict() for f in findings] + [
        {"rule_id": "DRIFT", "severity": d.severity, "title": d.kind,
         "message": f"{d.path}: {d.before!r} -> {d.after!r}", "server": d.server,
         "pointer": d.path, "remediation": "更新基线或撤销该变更", "threat": "policy drift"}
        for d in diffs
    ]


def render_text(findings, diffs, exit_code: int) -> str:
    head = f"mcplint {__version__} — {len(findings)} findings"
    if diffs:
        head += f", {len(diffs)} drift rows"
    lines = [head, ""]
    for f in findings:
        lines.append(f"{f.severity.upper():5}  {f.rule_id}  {f.server:12} "
                     f"{f.pointer:38} {f.title}")
        lines.append(f"        {f.message}")
        if f.remediation:
            lines.append(f"        fix: {f.remediation}")
    for d in diffs:
        lines.append(f"DRIFT   {d.kind:24} {d.server:12} {d.path}  "
                     f"{d.before!r} -> {d.after!r}")
    lines += ["", f"exit code: {exit_code}"]
    return "\n".join(lines) + "\n"


def render_coverage(files, servers, findings) -> str:
    """The honest table: what this run consumed, and what it therefore could not judge."""
    unknown = [f for f in findings if getattr(f, "unknown", False)]
    rows = [("config", "server", "transport", "modeled", "unmodeled")]
    for s in servers:
        rows.append((Path(s.source).name if s.source else "<inline>", s.name, s.transport,
                     ",".join(s.modeled_fields()) or "-", ",".join(s.unmodeled) or "-"))
    widths = [max(len(str(r[i])) for r in rows) for i in range(5)]
    out = [f"mcplint {__version__} coverage — {len(files)} config(s), {len(servers)} server(s)", ""]
    for i, row in enumerate(rows):
        out.append("  ".join(str(c).ljust(w) for c, w in zip(row, widths)))
        if i == 0:
            out.append("  ".join("-" * w for w in widths))
    total = sum(len(s.unmodeled) for s in servers)
    out += ["",
            f"unmodeled fields: {total} — rules depending on them report unknown, not pass",
            f"unknown findings: {len(unknown)}",
            "gate: --unknown error (default) fails the build on unknown",
            ]
    return "\n".join(out) + "\n"


def render_ndjson(findings, diffs) -> str:
    return "\n".join(json.dumps(r, ensure_ascii=False) for r in _rows(findings, diffs)) + "\n"


def render_json(findings, diffs, exit_code: int) -> str:
    return json.dumps({"schema_version": 1, "tool": "mcplint", "version": __version__,
                       "exit_code": exit_code, "findings": [f.as_dict() for f in findings],
                       "diff": [d.as_dict() for d in diffs]},
                      indent=2, ensure_ascii=False) + "\n"


_CSS = """
:root{color-scheme:light dark}body{font:14px/1.6 ui-monospace,SFMono-Regular,Menlo,monospace;
margin:2rem auto;max-width:1100px;padding:0 1rem}
h1{font-size:1.2rem}table{border-collapse:collapse;width:100%}th,td{border:1px solid #8886;
padding:.5rem;text-align:left;vertical-align:top}th{background:#8882}
.error{color:#c0392b;font-weight:700}.warn{color:#b7791f}.info{color:#2b6cb0}
input,select{padding:.4rem;margin:.5rem 0}code{word-break:break-all}footer{margin-top:2rem;opacity:.7}
"""

_JS = """
function flt(){var q=document.getElementById('q').value.toLowerCase(),
 s=document.getElementById('sev').value, rs=document.querySelectorAll('tbody tr');
 rs.forEach(function(r){var t=r.textContent.toLowerCase(),
 sev=r.getAttribute('data-sev');r.style.display=(t.indexOf(q)>=0&&(!s||sev===s))?'':'none';});}
"""

def render_html(findings, diffs, exit_code: int) -> str:
    rows = _rows(findings, diffs)
    body = []
    for r in rows:
        sev = html.escape(r["severity"])
        body.append(
            f'<tr data-sev="{sev}"><td class="{sev}">{sev.upper()}</td>'
            f'<td>{html.escape(r["rule_id"])}</td><td>{html.escape(r["server"])}</td>'
            f'<td><code>{html.escape(r["pointer"])}</code></td>'
            f'<td>{html.escape(r["title"])}<br><small>{html.escape(r["message"])}</small></td>'
            f'<td>{html.escape(r.get("remediation", ""))}</td></tr>')
    return (
        "<!doctype html><html lang=\"zh\"><meta charset=\"utf-8\">"
        "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">"
        f"<title>mcplint report</title><style>{_CSS}</style>"
        f"<h1>mcplint {__version__} — exit code {exit_code}</h1>"
        "<input id=\"q\" oninput=\"flt()\" placeholder=\"filter findings\"> "
        "<select id=\"sev\" onchange=\"flt()\"><option value=\"\">all severities</option>"
        "<option value=\"error\">error</option><option value=\"warn\">warn</option>"
        "<option value=\"info\">info</option></select>"
        "<table><thead><tr><th>sev</th><th>rule</th><th>server</th><th>pointer</th>"
        "<th>finding</th><th>fix</th></tr></thead><tbody>"
        + "".join(body) + "</tbody></table>"
        "<footer>Local report. No network requests, no telemetry. "
        "unknown != safe.</footer>"
        f"<script>{_JS}</script></html>\n")
