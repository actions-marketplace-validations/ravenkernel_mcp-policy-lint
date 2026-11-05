"""Built-in rules. Add one function per rule — the good-first-issue surface."""
from __future__ import annotations

import re
from urllib.parse import urlparse

from ..model import Finding, ServerSpec, escape_pointer
from . import register

SHELLS = {"sh", "bash", "zsh", "dash", "cmd", "cmd.exe", "powershell", "pwsh"}
# What makes an argument after -c a command string rather than a plain value.
SHELL_META = re.compile(r"[;&|$\x60<>(){}\n]")
SENSITIVE_ENV = re.compile(r"(TOKEN|SECRET|PASSWORD|PASSWD|API_?KEY|PRIVATE_?KEY|CREDENTIAL)", re.I)
PLACEHOLDER = re.compile(r"^(\$\{?\w+\}?|<[^>]+>|xxx+|placeholder|changeme|your[_-]?\w*)$", re.I)
WRITE_WORDS = re.compile(r"(delete|remove|rm\b|drop|overwrite|write|create|update|send|publish|execute)", re.I)
HOME_PATH = re.compile(r"^(/home/|/Users/|~|\$HOME|C:\\Users\\)", re.I)
LOOPBACK = {"localhost", "127.0.0.1", "::1", "0.0.0.0"}


def _f(rule_id, sev, title, msg, s: ServerSpec, ptr, fix, threat="") -> Finding:
    return Finding(rule_id, sev, title, msg, s.name, ptr or s.pointer, fix, threat)


def _carries_command(args: list[str]) -> bool:
    """-c only matters when the next argument is itself a command string.

    Without this, every `git -c key=value`, `docker run -c 512` and
    `npx pkg -c` becomes a false alarm, and a noisy gate gets deleted, not fixed.
    """
    for i, arg in enumerate(args[:-1]):
        if arg in ("-c", "/c") and SHELL_META.search(args[i + 1]):
            return True
    return False


@register("MCP001")
def shell_command(s: ServerSpec) -> list[Finding]:
    cmd = (s.command or "").strip()
    if cmd in SHELLS or _carries_command(s.args):
        return [_f("MCP001", "error", "stdio command can start a shell",
                   f"{s.name} runs its arguments through {cmd or '?'}, so it can execute arbitrary commands", s,
                   f"{s.pointer}/command", "Call a concrete executable directly instead of assembling a command with -c",
                   "arbitrary command execution")]
    return []


@register("MCP002")
def sensitive_env(s: ServerSpec) -> list[Finding]:
    out = []
    for k, v in s.env.items():
        if SENSITIVE_ENV.search(k) and not PLACEHOLDER.match(v.strip()):
            out.append(_f("MCP002", "error", "Likely real credential in config",
                          f"{k} is not a placeholder; it can leak through logs or travel with the repository", s,
                          f"{s.pointer}/env/{escape_pointer(k)}", "Reference an environment variable or a secret manager; never put the value in mcp.json",
                          "credential leakage"))
    return out


@register("MCP003")
def plaintext_remote(s: ServerSpec) -> list[Finding]:
    if not s.url or urlparse(s.url).scheme != "http":
        return []
    host = (urlparse(s.url).hostname or "").lower()
    if host in LOOPBACK:
        return [_f("MCP003", "warn", "Plaintext HTTP to a loopback address",
                   f"{s.url} is reachable only from this host, but it is still plaintext; forwarding the port or tunnelling makes it unacceptable", s,
                   f"{s.pointer}/{s.url_field}", "Acceptable for local development; switch to https as soon as the port is forwarded or the server moves",
                   "local plaintext transport")]
    return [_f("MCP003", "error", "Plaintext HTTP to a remote endpoint",
               f"{s.url} has no TLS, so tool descriptions and responses can be altered in transit", s,
               f"{s.pointer}/{s.url_field}", "Use https:// and confirm the authentication settings",
               "transport tampering")]


@register("MCP004")
def roots_outside_repo(s: ServerSpec) -> list[Finding]:
    out = []
    for i, r in enumerate(s.roots):
        segments = r.replace("\\", "/").split("/")
        if HOME_PATH.match(r) or r.strip() in {"/", "C:\\"} or ".." in segments:
            out.append(_f("MCP004", "error", "root outside the repository boundary",
                          f"root {r} points at a home directory or escapes the repository", s,
                          f"{s.pointer}/roots/{i}", "Narrow roots to the current project directory",
                          "unbounded file access"))
    return out


@register("MCP005")
def annotation_conflict(s: ServerSpec) -> list[Finding]:
    out = []
    for t in s.tools:
        readonly = t.annotations.get("readOnlyHint") is True
        destruct = t.annotations.get("destructiveHint") is False
        text = f"{t.name} {t.description}"
        if (readonly or destruct) and WRITE_WORDS.search(text):
            out.append(_f("MCP005", "warn", "Tool annotation contradicts its name or description",
                          f"{t.name} claims read-only or non-destructive, but its description contains write verbs", s,
                          t.pointer, "Fix the annotation or the name; a client may skip confirmation because of it",
                          "consent bypass"))
    return out


@register("MCP006")
def empty_schema(s: ServerSpec) -> list[Finding]:
    out = []
    for t in s.tools:
        schema = t.input_schema
        # JSON Schema does not require "type"; constraints are what make input checkable.
        constrained = bool(schema.get("properties") or schema.get("required")
                           or schema.get("additionalProperties") is False)
        if not constrained:
            out.append(_f("MCP006", "warn", "Tool input has no constraints",
                          f"{t.name} has an empty inputSchema or no properties, so argument boundaries cannot be checked", s,
                          t.pointer, "Complete the JSON Schema: declare required fields and enums",
                          "unbounded input"))
    return out


@register("MCP008")
def undeclared_transport(s: ServerSpec) -> list[Finding]:
    if s.transport == "unknown":
        return [Finding("MCP008", "warn", "Transport not declared",
                        f"{s.name} has neither command nor url, so its permission surface cannot be inferred", s.name,
                        s.pointer, "Add command or url; unknown does not mean safe",
                        "undetermined permission surface", unknown=True)]
    return []


@register("MCP010")
def pre_approved_tools(s: ServerSpec) -> list[Finding]:
    if s.auto_approve:
        listed = ", ".join(sorted(s.auto_approve))
        return [_f("MCP010", "warn", "Pre-approved tools skip confirmation",
                   f"{s.name} auto-approves {len(s.auto_approve)} tool(s): {listed}. "
                   "That list is part of the baseline, so adding one triggers drift", s,
                   f"{s.pointer}/autoApprove",
                   "Keep only read-only tools that genuinely need auto-approval; move the rest out of the list",
                   "consent bypass")]
    return []
