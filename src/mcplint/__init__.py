"""mcplint — zero-dependency static policy linting for MCP client configs."""
from __future__ import annotations

__version__ = "0.1.1"

from .model import ServerSpec, ToolSpec, Finding, Policy, DiffRow  # noqa: F401

__all__ = ["__version__", "ServerSpec", "ToolSpec", "Finding", "Policy", "DiffRow"]
