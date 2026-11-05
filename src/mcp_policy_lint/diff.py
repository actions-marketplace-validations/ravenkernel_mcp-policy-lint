"""Structured drift: compare the *declared permission surface*, not text."""
from __future__ import annotations

from .model import DiffRow, Policy, ServerSpec, escape_pointer
from .policy import build_policy


def diff(current: list[ServerSpec], baseline: Policy) -> list[DiffRow]:
    cur = {s.name: s for s in current}
    base = baseline.servers
    rows: list[DiffRow] = []

    for name in sorted(set(cur) - set(base)):
        rows.append(DiffRow("server_added", name, f"/servers/{escape_pointer(name)}",
                            after="new server", severity="error"))
    for name in sorted(set(base) - set(cur)):
        rows.append(DiffRow("server_removed", name, f"/servers/{escape_pointer(name)}",
                            before="approved", after="absent", severity="error"))
    for name in sorted(set(cur) & set(base)):
        s, b = cur[name], base[name]
        live = build_policy([s]).servers[name]
        ptr = f"/servers/{escape_pointer(name)}"
        if live["fingerprint"] != b.get("fingerprint"):
            rows.append(DiffRow("fingerprint_changed", name, f"{ptr}/fingerprint",
                                b.get("fingerprint"), live["fingerprint"], "error"))
        for field in ("allowed_tools", "roots", "net_egress", "env_allowlist", "auto_approve"):
            before, after = b.get(field, []), live[field]
            added, removed = sorted(set(after) - set(before)), sorted(set(before) - set(after))
            if added:
                rows.append(DiffRow(f"{field}_added", name, f"{ptr}/{field}",
                                    after=added, severity="error"))
            if removed:
                rows.append(DiffRow(f"{field}_removed", name, f"{ptr}/{field}",
                                    before=removed, severity="warn"))
    return rows
