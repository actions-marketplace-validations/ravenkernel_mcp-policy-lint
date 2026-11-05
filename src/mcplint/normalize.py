"""Normalize vendor config shapes into ServerSpec, preserving JSON Pointers.

Whatever this module does not model is reported as unknown, never dropped silently.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

from .model import ServerSpec, ToolSpec, Finding

# Fields that reach a ServerSpec field. Anything else in a server object is unmodeled.
MODELED_KEYS = frozenset({
    "command", "args", "env", "url", "serverUrl", "roots", "tools",
    "capabilities", "autoApprove", "disabled",
})

# Findings produced here rather than by a registered rule function.
STRUCTURAL_RULES = {
    "MCP000": "Unrecognized config shape",
    "MCP007": "Unknown capability",
    "MCP009": "Config field not modeled",
}

KNOWN_CAPABILITIES = frozenset({
    "tools", "resources", "prompts", "logging", "sampling", "roots", "elicitation",
})


def _servers_block(data: dict) -> tuple[dict, str]:
    for key in ("mcpServers", "servers"):
        if isinstance(data.get(key), dict):
            return data[key], "/" + key
    nested = data.get("mcp")
    if isinstance(nested, dict) and isinstance(nested.get("servers"), dict):
        return nested["servers"], "/mcp/servers"
    return {}, ""


def _tool(raw: Any, pointer: str) -> ToolSpec:
    raw = raw if isinstance(raw, dict) else {}
    annotations = {k: raw[k] for k in ("readOnlyHint", "destructiveHint", "idempotentHint",
                                       "openWorldHint") if k in raw}
    return ToolSpec(
        name=str(raw.get("name", "")),
        description=str(raw.get("description", "")),
        annotations=annotations,
        input_schema=raw.get("inputSchema") or raw.get("input_schema") or {},
        pointer=pointer,
    )


def normalize(data: dict, source: str = "") -> tuple[list[ServerSpec], list[Finding]]:
    block, base = _servers_block(data)
    servers: list[ServerSpec] = []
    notes: list[Finding] = []
    if not block:
        notes.append(Finding("MCP000", "error", "Unrecognized config shape",
                             "No mcpServers / servers / mcp.servers block found, so nothing in this file was checked: "
                             "the result is unknown, not pass",
                             "<config>", "/", "Add this client's top-level key in normalize._servers_block",
                             "unchecked configuration", unknown=True))
        return servers, notes

    for name, raw in block.items():
        ptr = f"{base}/{name}"
        raw = raw if isinstance(raw, dict) else {}
        tools_raw = raw.get("tools") or []
        tools = [_tool(t, f"{ptr}/tools/{i}") for i, t in enumerate(tools_raw)] \
            if isinstance(tools_raw, list) else []
        env = raw.get("env") if isinstance(raw.get("env"), dict) else {}
        roots = raw.get("roots") if isinstance(raw.get("roots"), list) else []
        caps = raw.get("capabilities") if isinstance(raw.get("capabilities"), dict) else {}
        approve = raw.get("autoApprove")
        # Unknown capability keys are surfaced, never silently trusted.
        for cap in sorted(set(caps) - KNOWN_CAPABILITIES):
            notes.append(Finding("MCP007", "warn", "Unknown capability",
                                 f"{name} declares an unrecognized capability: {cap}",
                                 str(name), f"{ptr}/capabilities/{cap}",
                                 "Confirm the client supports it, or drop the declaration",
                                 "unchecked capability", unknown=True))
        unmodeled = sorted(set(raw) - MODELED_KEYS)
        if unmodeled:
            notes.append(Finding("MCP009", "warn", "Config field not modeled",
                                 f"{name} has {len(unmodeled)} unmodeled field(s) "
                                 f"({', '.join(unmodeled)}); rules that depend on them report unknown, not pass",
                                 str(name), ptr,
                                 "Model the field in normalize.MODELED_KEYS, or tolerate it explicitly with --unknown",
                                 "unchecked permission surface", unknown=True))
        url_key = "url" if raw.get("url") else ("serverUrl" if raw.get("serverUrl") else "url")
        servers.append(ServerSpec(
            name=str(name),
            command=raw.get("command"),
            args=list(raw.get("args") or []),
            url=raw.get("url") or raw.get("serverUrl"),
            url_field=url_key,
            env={str(k): str(v) for k, v in env.items()},
            roots=[str(r) for r in roots],
            tools=tools,
            capabilities=caps,
            auto_approve=[str(a) for a in approve] if isinstance(approve, list) else [],
            disabled=bool(raw.get("disabled", False)),
            unmodeled=unmodeled,
            source=source,
            pointer=ptr,
        ))
    return servers, notes


def from_paths(paths: list[Path]) -> tuple[list[ServerSpec], list[Finding]]:
    from .discover import load_config
    servers, notes = [], []
    for p in paths:
        data = load_config(p)
        s, n = normalize(data, source=str(p))
        servers.extend(s)
        notes.extend(n)
    return servers, notes
