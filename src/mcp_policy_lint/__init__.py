"""mcp-policy-lint — zero-dependency static policy linting for MCP client configs."""
from __future__ import annotations

__version__ = "0.2.0"

from .model import ServerSpec, ToolSpec, Finding, Policy, DiffRow  # noqa: F401

__all__ = ["__version__", "ServerSpec", "ToolSpec", "Finding", "Policy", "DiffRow"]
