"""The only data contract in the project. Pure dataclasses, stdlib only."""
from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from typing import Any


def _clean(obj: Any) -> Any:
    if isinstance(obj, dict):
        return {k: _clean(v) for k, v in sorted(obj.items())}
    if isinstance(obj, (list, tuple)):
        return [_clean(v) for v in obj]
    return obj


def stable_hash(obj: Any) -> str:
    blob = json.dumps(_clean(obj), sort_keys=True, ensure_ascii=False, default=str)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()[:16]


def escape_pointer(token: Any) -> str:
    """RFC 6901: ~ becomes ~0 and / becomes ~1, so a pointer stays unambiguous."""
    return str(token).replace("~", "~0").replace("/", "~1")


def unescape_pointer(token: str) -> str:
    return token.replace("~1", "/").replace("~0", "~")


@dataclass
class ToolSpec:
    name: str
    description: str = ""
    annotations: dict[str, Any] = field(default_factory=dict)
    input_schema: dict[str, Any] = field(default_factory=dict)
    pointer: str = ""


@dataclass
class ServerSpec:
    name: str
    command: str | None = None
    args: list[str] = field(default_factory=list)
    url: str | None = None
    url_field: str = "url"          # raw key that supplied url (url vs Windsurf serverUrl)
    env: dict[str, str] = field(default_factory=dict)
    roots: list[str] = field(default_factory=list)
    tools: list[ToolSpec] = field(default_factory=list)
    capabilities: dict[str, Any] = field(default_factory=dict)
    auto_approve: list[str] = field(default_factory=list)
    disabled: bool = False
    unmodeled: list[str] = field(default_factory=list)   # raw keys this tool cannot interpret
    source: str = ""
    pointer: str = ""

    @property
    def transport(self) -> str:
        if self.command:
            return "stdio"
        if self.url:
            return "remote"
        return "unknown"

    def modeled_fields(self) -> list[str]:
        """Which declared fields actually reached a check. The rest are unknown."""
        out = []
        for name, value in (("command", self.command), ("args", self.args), ("url", self.url),
                            ("env", self.env), ("roots", self.roots), ("tools", self.tools),
                            ("capabilities", self.capabilities),
                            ("autoApprove", self.auto_approve), ("disabled", self.disabled)):
            if value:
                out.append(name)
        return out

    def fingerprint(self) -> str:
        """Identity of the declared permission surface, not of the raw file.

        `unmodeled` stays out: it describes this tool's coverage, not the server.
        `auto_approve` and `disabled` are in: both change who may act without asking.
        """
        return stable_hash({
            "command": self.command,
            "args": self.args,
            "url": self.url,
            "roots": sorted(self.roots),
            "tools": sorted(t.name for t in self.tools),
            "env_keys": sorted(self.env),
            "capabilities": self.capabilities,
            "auto_approve": sorted(self.auto_approve),
            "disabled": self.disabled,
        })

    def as_dict(self) -> dict:
        return asdict(self)


@dataclass
class Finding:
    rule_id: str
    severity: str          # error | warn | info
    title: str
    message: str
    server: str
    pointer: str
    remediation: str = ""
    threat: str = ""
    unknown: bool = False   # the rule could not judge; severity is decided by --unknown

    def as_dict(self) -> dict:
        return asdict(self)


@dataclass
class DiffRow:
    kind: str              # server_added | server_removed | fingerprint_changed | ...
    server: str
    path: str
    before: Any = None
    after: Any = None
    severity: str = "error"

    def as_dict(self) -> dict:
        return asdict(self)


@dataclass
class Policy:
    version: int = 1
    servers: dict[str, dict[str, Any]] = field(default_factory=dict)

    def as_dict(self) -> dict:
        return {"version": self.version, "servers": _clean(self.servers)}

    def to_json(self) -> str:
        return json.dumps(self.as_dict(), indent=2, ensure_ascii=False) + "\n"

    @classmethod
    def from_json(cls, text: str) -> "Policy":
        data = json.loads(text)
        if not isinstance(data, dict) or not isinstance(data.get("servers"), dict):
            raise ValueError("policy file needs a top-level 'servers' object")
        version = data.get("version", 1)
        if version != 1:
            raise ValueError(f"unsupported policy version: {version}")
        return cls(version=version, servers=data["servers"])
