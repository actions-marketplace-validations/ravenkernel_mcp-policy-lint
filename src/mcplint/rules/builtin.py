"""Built-in rules. Add one function per rule — the good-first-issue surface."""
from __future__ import annotations

import re
from urllib.parse import urlparse

from ..model import Finding, ServerSpec
from . import register

SHELLS = {"sh", "bash", "zsh", "dash", "cmd", "cmd.exe", "powershell", "pwsh"}
SENSITIVE_ENV = re.compile(r"(TOKEN|SECRET|PASSWORD|PASSWD|API_?KEY|PRIVATE_?KEY|CREDENTIAL)", re.I)
PLACEHOLDER = re.compile(r"^(\$\{?\w+\}?|<[^>]+>|xxx+|placeholder|changeme|your[_-]?\w*)$", re.I)
WRITE_WORDS = re.compile(r"(delete|remove|rm\b|drop|overwrite|write|create|update|send|publish|execute)", re.I)
HOME_PATH = re.compile(r"^(/home/|/Users/|~|\$HOME|C:\\Users\\)", re.I)
LOOPBACK = {"localhost", "127.0.0.1", "::1", "0.0.0.0"}


def _f(rule_id, sev, title, msg, s: ServerSpec, ptr, fix, threat="") -> Finding:
    return Finding(rule_id, sev, title, msg, s.name, ptr or s.pointer, fix, threat)


@register("MCP001")
def shell_command(s: ServerSpec) -> list[Finding]:
    cmd = (s.command or "").strip()
    if cmd in SHELLS or "-c" in s.args or "/c" in s.args:
        return [_f("MCP001", "error", "stdio 命令可启动 shell",
                   f"{s.name} 使用 {cmd or '?'} 执行参数，可运行任意命令", s,
                   f"{s.pointer}/command", "改为直接调用具体可执行文件，避免 -c 拼装",
                   "arbitrary command execution")]
    return []


@register("MCP002")
def sensitive_env(s: ServerSpec) -> list[Finding]:
    out = []
    for k, v in s.env.items():
        if SENSITIVE_ENV.search(k) and not PLACEHOLDER.match(v.strip()):
            out.append(_f("MCP002", "error", "配置内疑似真实凭证",
                          f"{k} 不是占位符，可能被写入日志或随仓库泄露", s,
                          f"{s.pointer}/env/{k}", "改用环境变量引用或密钥管理，不要把值写进 mcp.json",
                          "credential leakage"))
    return out


@register("MCP003")
def plaintext_remote(s: ServerSpec) -> list[Finding]:
    if not s.url or urlparse(s.url).scheme != "http":
        return []
    host = (urlparse(s.url).hostname or "").lower()
    if host in LOOPBACK:
        return [_f("MCP003", "warn", "回环地址使用明文 HTTP",
                   f"{s.url} 只在本机可访问，但仍是明文；跨主机或隧道转发则不可接受", s,
                   f"{s.pointer}/{s.url_field}", "本地开发可接受；一旦转发端口或部署到其他主机必须改 https",
                   "local plaintext transport")]
    return [_f("MCP003", "error", "远程端点使用明文 HTTP",
               f"{s.url} 未启用 TLS，工具描述与返回值可被中间人篡改", s,
               f"{s.pointer}/{s.url_field}", "改用 https://，并确认鉴权配置",
               "transport tampering")]


@register("MCP004")
def roots_outside_repo(s: ServerSpec) -> list[Finding]:
    out = []
    for i, r in enumerate(s.roots):
        if HOME_PATH.match(r) or r.strip() in {"/", "C:\\"} or ".." in r:
            out.append(_f("MCP004", "error", "root 越出仓库边界",
                          f"root {r} 指向用户主目录或路径逃逸", s,
                          f"{s.pointer}/roots/{i}", "把 roots 收窄到当前项目目录",
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
            out.append(_f("MCP005", "warn", "工具注解与名称/描述矛盾",
                          f"{t.name} 声明只读/非破坏性，但描述包含写操作词", s,
                          t.pointer, "修正注解或改名；客户端可能据此跳过二次确认",
                          "consent bypass"))
    return out


@register("MCP006")
def empty_schema(s: ServerSpec) -> list[Finding]:
    out = []
    for t in s.tools:
        schema = t.input_schema
        if not schema or not schema.get("type") or not schema.get("properties"):
            out.append(_f("MCP006", "warn", "工具入参无约束",
                          f"{t.name} 的 inputSchema 为空或缺少 properties，参数边界不可检查", s,
                          t.pointer, "补全 JSON Schema，声明必填字段与枚举",
                          "unbounded input"))
    return out


@register("MCP008")
def undeclared_transport(s: ServerSpec) -> list[Finding]:
    if s.transport == "unknown":
        return [Finding("MCP008", "warn", "未声明 transport",
                        f"{s.name} 既无 command 也无 url，无法推断权限边界", s.name,
                        s.pointer, "补充 command 或 url；unknown 不等于 safe",
                        "undetermined permission surface", unknown=True)]
    return []


@register("MCP010")
def pre_approved_tools(s: ServerSpec) -> list[Finding]:
    if s.auto_approve:
        listed = ", ".join(sorted(s.auto_approve))
        return [_f("MCP010", "warn", "预批准工具跳过二次确认",
                   f"{s.name} 对 {len(s.auto_approve)} 个工具免确认（{listed}）；"
                   "该清单已进入基线，新增一项会触发漂移", s,
                   f"{s.pointer}/autoApprove",
                   "只保留确实需要免确认的只读工具；其余移出清单",
                   "consent bypass")]
    return []
