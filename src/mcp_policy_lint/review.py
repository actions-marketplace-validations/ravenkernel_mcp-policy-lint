"""Explicit approval: the only way a baseline moves, and it leaves a receipt."""
from __future__ import annotations

import getpass
import os
from datetime import datetime, timezone

from .diff import diff
from .model import DiffRow, Policy, ServerSpec, stable_hash
from .policy import build_policy


def whoami() -> str:
    """Best-effort identity, never a guess about intent. Override with --by."""
    for key in ("MCP_POLICY_LINT_BY", "GITHUB_ACTOR", "GIT_AUTHOR_NAME"):
        value = os.environ.get(key, "").strip()
        if value:
            return value
    try:
        return getpass.getuser() or "unknown"
    except Exception:      # a Windows box without a usable login name
        return "unknown"


def approve(servers: list[ServerSpec], base: Policy, reason: str,
            by: str | None = None, at: str | None = None) -> tuple[Policy, list[DiffRow]]:
    """Rewrite the baseline to match the config, recording why. No drift -> nothing to do."""
    reason = (reason or "").strip()
    if not reason:
        raise ValueError("approve needs a --reason: an approval without a why is not an audit trail")
    rows = diff(servers, base)
    if not rows:
        return base, []
    stamp = at or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    entry = {
        "id": stable_hash([stamp, by or whoami(), reason, [r.path for r in rows]])[:12],
        "at": stamp,
        "by": by or whoami(),
        "reason": reason,
        "changes": [{"kind": r.kind, "server": r.server, "path": r.path} for r in rows],
    }
    return build_policy(servers, approvals=[*base.approvals, entry]), rows
