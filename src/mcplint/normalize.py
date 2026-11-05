"""Normalize vendor config shapes into ServerSpec, preserving JSON Pointers.

Anything this module cannot model — an unknown key, a known key of the wrong
type, a second server with the same name — becomes a finding, never a silent pass.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

from .model import Finding, ServerSpec, ToolSpec, escape_pointer

# Every field that reaches a ServerSpec, and the type it must have to be believed.
FIELD_TYPES = {
    "command": str,
    "args": list,
    "env": dict,
    "url": str,
    "serverUrl": str,
    "roots": list,
    "tools": list,
    "capabilities": dict,
    "autoApprove": list,
    "disabled": bool,
}
MODELED_KEYS = frozenset(FIELD_TYPES)

# Findings produced here rather than by a registered rule function.
STRUCTURAL_RULES = {
    "MCP000": "Unrecognized config shape",
    "MCP007": "Unknown capability",
    "MCP009": "Config field not modeled",
    "MCP011": "Duplicate server name",
}

KNOWN_CAPABILITIES = frozenset({
    "tools", "resources", "prompts", "logging", "sampling", "roots", "elicitation",
})


def _servers_block(data: dict) -> tuple[dict, str, bool]:
    """(servers block, its pointer, whether the file declares one at all).

    An empty block is a pass with zero servers; a missing block is MCP000.
    """
    for key in ("mcpServers", "servers"):
        if isinstance(data.get(key), dict):
            return data[key], "/" + key, True
    nested = data.get("mcp")
    if isinstance(nested, dict) and isinstance(nested.get("servers"), dict):
        return nested["servers"], "/mcp/servers", True
    return {}, "", False


def _tool(raw: Any, pointer: str) -> ToolSpec:
    raw = raw if isinstance(raw, dict) else {}
    annotations = {k: raw[k] for k in ("readOnlyHint", "destructiveHint", "idempotentHint",
                                       "openWorldHint") if k in raw}
    schema = raw.get("inputSchema") or raw.get("input_schema") or {}
    return ToolSpec(
        name=str(raw.get("name", "")),
        description=str(raw.get("description", "")),
        annotations=annotations,
        input_schema=schema if isinstance(schema, dict) else {},
        pointer=pointer,
    )


def _typed(raw: dict, key: str, kind, default):
    value = raw.get(key)
    return value if isinstance(value, kind) else default


def _text(raw: dict, key: str) -> str | None:
    value = raw.get(key)
    return value if isinstance(value, str) else None


def normalize(data: dict, source: str = "") -> tuple[list[ServerSpec], list[Finding]]:
    block, base, found = _servers_block(data)
    servers: list[ServerSpec] = []
    notes: list[Finding] = []
    if not found:
        notes.append(Finding("MCP000", "error", "Unrecognized config shape",
                             "No mcpServers / servers / mcp.servers block found, so nothing in this file was checked: "
                             "the result is unknown, not pass",
                             "<config>", "/", "Add this client's top-level key in normalize._servers_block",
                             "unchecked configuration", unknown=True))
        return servers, notes

    for name, raw in block.items():
        ptr = f"{base}/{escape_pointer(name)}"
        raw = raw if isinstance(raw, dict) else {}
        wrong = sorted(k for k, kind in FIELD_TYPES.items()
                       if k in raw and raw[k] is not None and not isinstance(raw[k], kind))
        extra = sorted(set(raw) - MODELED_KEYS - set(wrong))
        if wrong:
            notes.append(Finding("MCP009", "warn", "Config field not modeled",
                                 f"{name} declares {', '.join(wrong)} with an unexpected type; "
                                 "the value was dropped, so whatever it declared is unknown",
                                 str(name), ptr,
                                 "Fix the type in the config, or model the variant in normalize.FIELD_TYPES",
                                 "unchecked permission surface", unknown=True))
        if extra:
            notes.append(Finding("MCP009", "warn", "Config field not modeled",
                                 f"{name} has {len(extra)} unmodeled field(s) "
                                 f"({', '.join(extra)}); rules that depend on them report unknown, not pass",
                                 str(name), ptr,
                                 "Model the field in normalize.FIELD_TYPES, or tolerate it explicitly with --unknown",
                                 "unchecked permission surface", unknown=True))
        tools_raw = _typed(raw, "tools", list, [])
        env = _typed(raw, "env", dict, {})
        caps = _typed(raw, "capabilities", dict, {})
        approve = _typed(raw, "autoApprove", list, [])
        url, server_url = _text(raw, "url"), _text(raw, "serverUrl")
        # Unknown capability keys are surfaced, never silently trusted.
        for cap in sorted(set(caps) - KNOWN_CAPABILITIES):
            notes.append(Finding("MCP007", "warn", "Unknown capability",
                                 f"{name} declares an unrecognized capability: {cap}",
                                 str(name), f"{ptr}/capabilities/{escape_pointer(cap)}",
                                 "Confirm the client supports it, or drop the declaration",
                                 "unchecked capability", unknown=True))
        servers.append(ServerSpec(
            name=str(name),
            command=_text(raw, "command"),
            args=[str(a) for a in _typed(raw, "args", list, [])],
            url=url or server_url,
            url_field="url" if url else ("serverUrl" if server_url else "url"),
            env={str(k): str(v) for k, v in env.items()},
            roots=[str(r) for r in _typed(raw, "roots", list, [])],
            tools=[_tool(t, f"{ptr}/tools/{i}") for i, t in enumerate(tools_raw)],
            capabilities=caps,
            auto_approve=[str(a) for a in approve],
            disabled=raw.get("disabled") is True,
            unmodeled=sorted(set(wrong) | set(extra)),
            source=source,
            pointer=ptr,
        ))
    return servers, notes


def from_paths(paths: list[Path]) -> tuple[list[ServerSpec], list[Finding]]:
    from .discover import load_config
    servers, notes = [], []
    seen: dict[str, str] = {}
    for p in paths:
        data = load_config(p)
        found, file_notes = normalize(data, source=str(p))
        for s in found:
            first = seen.get(s.name)
            if first is None:
                seen[s.name] = str(p)
            else:
                # A baseline is keyed by server name, so a duplicate makes drift undefined.
                file_notes.append(Finding("MCP011", "error", "Duplicate server name",
                                          f"{s.name} is declared in both {first} and {p}; a baseline can approve only "
                                          "one of them, so the drift result is undefined",
                                          s.name, s.pointer,
                                          "Rename one server, or scan the files separately with different baselines",
                                          "ambiguous baseline"))
        servers.extend(found)
        notes.extend(file_notes)
    return servers, notes
