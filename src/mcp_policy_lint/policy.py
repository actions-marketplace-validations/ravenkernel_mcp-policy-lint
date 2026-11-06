"""Policy baseline: what a team explicitly approved in a PR."""
from __future__ import annotations

from urllib.parse import urlparse

from .model import Policy, ServerSpec


def _egress(s: ServerSpec) -> list[str]:
    if not s.url:
        return []
    host = urlparse(s.url).netloc
    return [host] if host else []


def build_policy(servers: list[ServerSpec], approvals=None) -> Policy:
    out = {}
    for s in servers:
        out[s.name] = {
            "fingerprint": s.fingerprint(),
            "transport": s.transport,
            "allowed_tools": sorted(t.name for t in s.tools),
            "roots": sorted(s.roots),
            "net_egress": _egress(s),
            "env_allowlist": sorted(s.env),
            "auto_approve": sorted(s.auto_approve),
            "disabled": bool(s.disabled),
            "waivers": [],
        }
    return Policy(version=1, servers=out, approvals=list(approvals or []))


def load_policy(text: str) -> Policy:
    return Policy.from_json(text)
