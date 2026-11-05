# mcplint

[![ci](https://github.com/ravenkernel/mcplint/actions/workflows/ci.yml/badge.svg)](https://github.com/ravenkernel/mcplint/actions/workflows/ci.yml) [![license](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](https://github.com/ravenkernel/mcplint/blob/main/LICENSE) [![PyPI](https://img.shields.io/pypi/v/mcp-policy-lint.svg)](https://pypi.org/project/mcp-policy-lint/)

[English](README.md) | **简体中文**

**在你运行任何 MCP server 之前，把 `mcp.json` 翻译成可读、可测试、可阻止 PR 的权限策略。** 本地、零依赖、无需模型 key、无需 Docker。

```bash
pip install mcp-policy-lint   # PyPI 上的发行名，命令仍然是 mcplint
mcplint demo                  # 30 秒，无网络、无 API key、无 Docker
# 从源码用：pip install -e .
```

```
mcplint demo — 2 servers scanned, 6 findings
no network, no API key, no Docker
(vs sample baseline: 3 drift rows — run `mcplint diff` to inspect)

mcplint 0.1.2 — 6 findings

ERROR  MCP003  remote       /mcpServers/remote/url                 Plaintext HTTP to a remote endpoint
        http://api.example.com/mcp has no TLS, so tool descriptions and responses can be altered in transit
        fix: Use https:// and confirm the authentication settings
ERROR  MCP001  shell        /mcpServers/shell/command              stdio command can start a shell
        shell runs its arguments through sh, so it can execute arbitrary commands
        fix: Call a concrete executable directly instead of assembling a command with -c
ERROR  MCP002  shell        /mcpServers/shell/env/AWS_SECRET_ACCESS_KEY Likely real credential in config
        AWS_SECRET_ACCESS_KEY is not a placeholder; it can leak through logs or travel with the repository
        fix: Reference an environment variable or a secret manager; never put the value in mcp.json
ERROR  MCP004  shell        /mcpServers/shell/roots/0              root outside the repository boundary
        root /home/me points at a home directory or escapes the repository
        fix: Narrow roots to the current project directory
WARN   MCP005  shell        /mcpServers/shell/tools/0              Tool annotation contradicts its name or description
        delete_everything claims read-only or non-destructive, but its description contains write verbs
        fix: Fix the annotation or the name; a client may skip confirmation because of it
WARN   MCP006  shell        /mcpServers/shell/tools/0              Tool input has no constraints
        delete_everything has an empty inputSchema or no properties, so argument boundaries cannot be checked
        fix: Complete the JSON Schema: declare required fields and enums

exit code: 1
mcplint 0.1.2 coverage — 1 config(s), 2 server(s)

config           server  transport  modeled                       unmodeled
---------------  ------  ---------  ----------------------------  ---------
unsafe.mcp.json  shell   stdio      command,args,env,roots,tools  -
unsafe.mcp.json  remote  remote     url                           -

unmodeled fields: 0 — rules depending on them report unknown, not pass
unknown findings: 0
gate: --unknown error (default) fails the build on unknown
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

## 自己验证，不用信我

`scripts/gate_selftest.py` 把「什么输入该拿什么退出码」写成了表，10 个 fixture + 1 个漂移用例，零依赖、不需要安装：

```bash
python scripts/gate_selftest.py
```

```
fixture                         argv                         want  got
safe.json                       (default)                       0    0  ok
unknown-shape.json              (default)                       1    1  ok
unmodeled-transport.json        (default)                       1    1  ok
unmodeled-transport.json        --unknown warn                  0    0  ok
unmodeled-transport.json        --unknown ignore                0    0  ok
windsurf-serverurl-http.json    (default)                       1    1  ok
cline-autoapprove.json          (default)                       0    0  ok
cline-autoapprove.json          --strict                        1    1  ok
cline-autoapprove-secret.json   (default)                       1    1  ok
localhost-http.json             (default)                       0    0  ok
cline-autoapprove-plus.json     (drift)                         2    2  ok

11/11 cases match
```

这张表就是本文档的全部主张：看不懂的配置会失败（1），基线能被漂移检测抓到（2），本地明文 HTTP 不误报（0）。改任何一条规则的严重级别，这张表会先红。

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

规则注册表、策略格式、报告渲染、配置发现都是独立模块，见 [ARCHITECTURE.zh-CN.md](https://github.com/ravenkernel/mcplint/blob/main/ARCHITECTURE.zh-CN.md)。

## 作为 GitHub Action 使用

```yaml
- uses: ravenkernel/mcplint@v1
  with:
    path: .                       # 文件或目录
    baseline: policy.lock.json    # 可选；不填时只报 findings
    unknown: error                # error（默认）| warn | ignore
    strict: false
```

Action 会安装 `mcp-policy-lint`、运行 `mcplint check`，并用 mcplint 自己的退出码决定这个 job 通过还是失败——和你在本地看到的 `0/1/2/3` 完全一致。除了你要它写出的基线文件，它不写任何东西，也从不改配置文件。

| 输入 | 默认 | 作用 |
|---|---|---|
| `path` | `.` | 要检查的配置文件或目录 |
| `baseline` | 空 | 开启针对 `policy.lock.json` 的漂移检测 |
| `unknown` | `error` | 无法建模的字段要付的代价 |
| `strict` | `false` | 警告升级为失败 |
| `extra-args` | 空 | 追加到 `mcplint check` 后面 |
| `version` | `>=0.1.2,<0.2` | 安装时的 pip 版本要求 |

## 状态

0.1.2：可运行端到端，内置 9 条规则（MCP001-006 / 008 / 009 / 010），CLI 与库均可测。自 0.1.1 起 lint 输出为英文（0.1.0 规则相同，输出为中文）。0.1.2 是第一个 PyPI 版本，把我手工撞出来的崩溃与误报变成了测试：字段类型不对是 MCP009 而不是异常，名字含 `/` 的 server 产出合法 pointer（`a~1b`），同名 server 报 MCP011，`git -c user.name=x` 不再当作 shell，`--rule` 编号或参数打错是退出码 3 而不是静默通过。

配置格式兼容性目前覆盖 `mcpServers` / `servers` / `mcp.servers` 三种顶层形态，以及 Claude Desktop / Cursor / VS Code / Cline / Windsurf 的常见字段。**没覆盖的部分不会假装通过**：未建模字段一律产出 MCP009，由 `--unknown`（默认 error）决定它是否阻断合并；`mcplint coverage` 打印完整的字段消费表。

不含沙箱、网关与 prompt injection 检测——那是运行时层的活。不宣称 "secure by default"。
