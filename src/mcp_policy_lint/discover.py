"""Locate MCP client configs. Add new client paths here (good first issue)."""
from __future__ import annotations

import json
from pathlib import Path

CANDIDATE_NAMES = (
    "mcp.json",
    ".mcp.json",
    ".cursor/mcp.json",
    ".vscode/mcp.json",
    ".claude/mcp.json",
    "claude_desktop_config.json",
    ".config/claude/mcp.json",
)

SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__", "dist", "build"}


def discover(paths: list[str]) -> list[Path]:
    """Explicit files are used as-is; directories are searched for known names."""
    found: list[Path] = []
    for raw in paths:
        p = Path(raw).expanduser()
        if p.is_file():
            found.append(p)
        elif p.is_dir():
            for name in CANDIDATE_NAMES:
                candidate = p / name
                if candidate.is_file():
                    found.append(candidate)
            for child in sorted(p.rglob("*.json")):
                if any(part in SKIP_DIRS for part in child.relative_to(p).parts):
                    continue
                if child.name in {"mcp.json", ".mcp.json", "claude_desktop_config.json"}:
                    if child not in found:
                        found.append(child)
    # stable, de-duplicated
    seen, out = set(), []
    for p in found:
        key = str(p.resolve())
        if key not in seen:
            seen.add(key)
            out.append(p)
    return out


def load_config(path: Path) -> dict:
    """JSON only in the skeleton. JSON5/JSONC support belongs in normalize."""
    with path.open("r", encoding="utf-8-sig") as fh:
        data = json.load(fh)
    if not isinstance(data, dict):
        raise ValueError(f"{path}: top-level must be an object")
    return data
