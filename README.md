# mcplint

**在你运行任何 MCP server 之前，把 `mcp.json` 翻译成可读、可测试、可阻止 PR 的权限策略。** 本地、零依赖、无需模型 key、无需 Docker。

```bash
pip install -e .              # 或用 PYTHONPATH=src python -m mcplint ...
mcplint demo                  # 30 秒，无网络、无 API key、无 Docker
```

```
mcplint demo — 2 servers scanned, 6 findings
no network, no API key, no Docker
(vs sample baseline: 3 drift rows — run `mcplint diff` to inspect)

ERROR  MCP003  remote       /mcpServers/remote/url         远程端点使用明文 HTTP
ERROR  MCP001  shell        /mcpServers/shell/command      stdio 命令可启动 shell
ERROR  MCP002  shell        /mcpServers/shell/env/AWS_SECRET_ACCESS_KEY 配置内疑似真实凭证
ERROR  MCP004  shell        /mcpServers/shell/roots/0      root 越出仓库边界
WARN   MCP005  shell        /mcpServers/shell/tools/0      工具注解与名称/描述矛盾
WARN   MCP006  shell        /mcpServers/shell/tools/0      工具入参无约束
exit code: 1

mcplint coverage — 1 config(s), 2 server(s)
config           server  transport  modeled                       unmodeled
---------------  ------  ---------  ----------------------------  ---------
unsafe.mcp.json  shell   stdio      command,args,env,roots,tools  -        
unsafe.mcp.json  remote  remote     url                           -        
unmodeled fields: 0 — rules depending on them report unknown, not pass
```

## 三步工作流

```bash
# 1. 生成已批准的策略基线（提交进仓库）
mcplint init examples/safe.mcp.json --out policy.lock.json

# 2. 扫描任意客户端配置
mcplint scan examples/unsafe.mcp.json --format ndjson

# 3. CI 门禁：策略漂移或发现项 → 非零退出码
mcplint check examples/unsafe.mcp.json --baseline policy.lock.json --strict
```

`scan` 输出 `text / ndjson / json / html`，`--html-out report.html` 生成单文件报告（无外部资源，`file://` 直接打开）。`diff` 单独输出 add / remove / modify 表。

## unknown 是要付账的

工具看不懂的东西一律报成 `unknown`，而不是悄悄算作通过。三类都算账：整个文件形态不认识（MCP000）、字段没有建模（MCP009）、transport 无法推断（MCP008）。

```bash
mcplint check mcp.json                  # 默认 --unknown error：看不懂就失败
mcplint check mcp.json --unknown warn   # 降级为 warn（仍受 --strict 约束）
mcplint check mcp.json --unknown ignore # 显式声明"看不懂也无所谓"
mcplint coverage mcp.json               # 本次到底消费了哪些字段
```

`coverage` 是唯一会主动承认自己没看懂什么的命令：它列出每个 server 已建模的字段、未建模的字段，以及由此产生的 unknown 结论。

## 它不是什么

| 不做 | 谁在做 |
| --- | --- |
| 不运行 MCP server、不做容器沙箱 | ToolHive |
| 不扫描 server 源码里的恶意内容 | mcp-scanner |
| 不做流量网关、RBAC、JWT | agentgateway |
| 不接 LLM 当 judge、不判断 prompt injection | — |
| 不自动改配置、不自动批准 | — |

它只回答三件事：配置**声明**了什么权限、是否违反**最小权限基线**、这次 PR **改了什么**。`unknown` 不等于 `safe`，所有结论都带 JSON Pointer 证据位置。

## 退出码

| code | 含义 |
| --- | --- |
| 0 | 通过 |
| 1 | 存在 error（含被判定为 error 的 unknown；`--strict` 时 warn 也算） |
| 2 | 与策略基线发生漂移 / schema 不兼容 |
| 3 | 用法或配置错误（文件不存在、基线损坏） |

优先级 `3 > 2 > 1 > 0`，与 `sys.exit()` 直接对接 GitHub Actions。

## 加一条规则只要一个函数

```python
from mcplint.rules import register
from mcplint.model import Finding

@register("MCP100")
def no_root_ssh(server):
    if any(".ssh" in r for r in server.roots):
        return [Finding("MCP100", "error", "root 指向 .ssh",
                        f"{server.name} 暴露 SSH 目录", server.name,
                        server.pointer + "/roots", "缩小 roots 到仓库目录")]
    return []
```

规则注册表、策略格式、报告渲染、配置发现都是独立模块，见 [框架说明.md](框架说明.md)。

## 状态

0.1.0：可运行端到端，内置 9 条规则（MCP001-006 / 008 / 009 / 010），CLI 与库均可测。

配置格式兼容性目前覆盖 `mcpServers` / `servers` / `mcp.servers` 三种顶层形态，以及 Claude Desktop / Cursor / VS Code / Cline / Windsurf 的常见字段。**没覆盖的部分不会假装通过**：未建模字段一律产出 MCP009，由 `--unknown`（默认 error）决定它是否阻断合并；`mcplint coverage` 打印完整的字段消费表。

不含沙箱、网关与 prompt injection 检测——那是运行时层的活。不宣称 "secure by default"。
