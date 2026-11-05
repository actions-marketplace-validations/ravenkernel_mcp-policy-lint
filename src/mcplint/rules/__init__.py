"""Tiny registry. A rule is just: ServerSpec -> list[Finding]."""
from __future__ import annotations

from typing import Callable

from ..model import Finding, ServerSpec

Rule = Callable[[ServerSpec], list[Finding]]
REGISTRY: dict[str, Rule] = {}


def register(rule_id: str):
    def deco(fn: Rule) -> Rule:
        if rule_id in REGISTRY:
            raise ValueError(f"duplicate rule id: {rule_id}")
        REGISTRY[rule_id] = fn
        fn.rule_id = rule_id  # type: ignore[attr-defined]
        return fn
    return deco


def evaluate(servers: list[ServerSpec], enabled: set[str] | None = None) -> list[Finding]:
    out: list[Finding] = []
    for server in servers:
        for rule_id, fn in REGISTRY.items():
            if enabled is not None and rule_id not in enabled:
                continue
            out.extend(fn(server))
    order = {"error": 0, "warn": 1, "info": 2}
    out.sort(key=lambda f: (order.get(f.severity, 3), f.server, f.rule_id))
    return out


# Import builtins so registration happens on package import.
from . import builtin  # noqa: E402,F401

__all__ = ["register", "evaluate", "REGISTRY", "Rule"]
