# mcp-policy-lint 架构说明

[English](ARCHITECTURE.md) | **简体中文**

## 这页是写给谁看的

只想把工具跑起来,[README.zh-CN.md](README.zh-CN.md) 就够了。这页回答下一个问题:*这条 finding 为什么出现,退出码又是怎么来的?* 工具给出的每个结论,都能顺着下面六个阶段追回到你配置文件里的某几个字节。

## 一份配置文件的旅程

```
mcp-policy-lint scan .            discover   决定读哪些文件
                          normalize  dict -> [ServerSpec] + 结构类 finding
                          rules      ServerSpec -> [Finding]
mcp-policy-lint diff / check      policy     基线:谁被批准过,它的指纹是什么
                          diff       当前权限面 vs 已批准权限面
mcp-policy-lint approve           review     唯一会写基线的命令,并把理由记下来
mcp-policy-lint coverage          report     text / ndjson / json / sarif / 单文件 HTML
-- 退出 --                exitcode   findings + drift + --strict -> 0 / 1 / 2 / 3
```

## 逐阶段说明(用使用者的话讲)

1. **discover** —— 你给它文件或目录;它递归目录、跳过常见的噪音目录(`SKIP_DIRS`),只留下它认识的文件名(`CANDIDATE_NAMES` 里的那些)。不下载、不执行任何东西。
2. **normalize** —— 各家客户端把同一件事写得不一样(`mcpServers` 还是 `servers`,`url` 还是 `serverUrl`,`type` 有时干脆没有)。这一层把每种文件折成一个 `ServerSpec`,并记住每个字段来自哪个 JSON Pointer。折不进去的东西不会被丢掉,而是变成一条*结构类 finding*:认不出的形态(`POL000`)、不认识的 capability(`POL007`)、没有建模的字段(`POL009`)、重复定义的 server 名(`POL011`)。
3. **rules** —— 八条注册规则只读 `ServerSpec`,从不碰原始 JSON;所以规则不会因为没见过某种配置形态而崩。`mcp-policy-lint rules` 会把全部编号打出来,含结构类那四条。
4. **policy** —— `mcp-policy-lint init` 写基线:每个 server 存一个指纹,加上它的权限面(`allowed_tools`、`roots`、`net_egress`、`env_allowlist`、`auto_approve`、`disabled`,以及用于接受既有 finding 的 `waivers`)。env 只存变量名,永不存值。
5. **diff** —— `mcp-policy-lint diff` 做结构化比对,不是文本 diff:server 新增或消失、指纹变化、某一维度多一条或少一条。
6. **approve** —— 漂移是故意的时候,`mcp-policy-lint approve --reason "..."` 会重写基线,并把一条审计记录(`id`、`at`、`by`、`reason`、`changes`)追加进去。下一次 `check` 通过,而复核者能在同一份 diff 里看到是谁、为什么移动了基线。
7. **report 与退出码** —— 报告负责把 finding 排版(`text`、`json`、`ndjson`、`sarif`、HTML);SARIF 结果里带规则编号、映射后的级别、配置文件、作为 `logicalLocation` 的 JSON Pointer,以及稳定的 `partialFingerprint`。退出码负责给 CI 一个答案。

## 退出码才是产品本身

| 码 | 含义 | 典型原因 |
| --- | --- | --- |
| 0 | 通过 | 没有要报的 |
| 1 | 有 finding 未通过 | 某条规则以 `error` 命中(包括 `unknown`,`unknown` 默认按 `error` 计价) |
| 2 | 策略漂移 | server、权限或指纹与基线不同 |
| 3 | 用法或配置错误 | 路径不存在、JSON 坏了、策略文件坏了、`--rule` 写了不存在的编号、参数拼错 |

优先级 `3 > 2 > 1 > 0`:输入坏了压过策略坏了,策略坏了压过发现项。`--strict` 把 `warn` 升级为失败。`--unknown warn|ignore` 是唯一能让「没建模的字段」便宜一点的办法 —— 没有哪个开关能让它在不被说明的情况下凭空消失。

## 每一层向你保证什么

| 阶段 | 你可以依赖 | 它拒绝掩盖的失败 |
| --- | --- | --- |
| discover | 不联网、不起子进程 | 你传了但没人读的配置(形态认不出则报 `POL000`) |
| normalize | 每条 finding 都带可解析的 JSON Pointer | 类型不对就被静默丢掉的字段(`POL009`) |
| rules | 规则永远看不到原始 JSON | 判不了就标 `unknown`,不当作通过 |
| policy | 只存名字和指纹,不存值 | 会泄漏密钥的基线 |
| diff | 权限面增加是 error,移除是 warn | 淹没重点的文本 diff |
| report | HTML 自包含,JSON/NDJSON 可机读 | 需要联网才能渲染的报告 |

## 数据契约

```python
ServerSpec(name, command, args, url, url_field, env, roots, tools, capabilities,
           auto_approve, disabled, unmodeled, source, pointer)
ToolSpec(name, description, annotations, input_schema, pointer)
Finding(rule_id, severity, title, message, server, pointer,
        remediation, threat, unknown=False)
Policy(version=1, servers={name: {fingerprint, transport, allowed_tools, roots,
                                  net_egress, env_allowlist, auto_approve,
                                  disabled, waivers}}, approvals=[...])
DiffRow(kind, server, path, before, after, severity)
```

`pointer` 一律是 RFC 6901 JSON Pointer(名为 `a/b` 的 server 会写成 `/mcpServers/a~1b/command`),所以你能用手里任何 JSON Pointer 工具直接定位。

## 加功能该改哪里

| 模块 | 职责 | 扩展时的第一站 |
| --- | --- | --- |
| `discover.py` | 显式路径、目录递归、已知客户端文件名 | `CANDIDATE_NAMES` |
| `normalize.py` | 各家形态折成统一 `ServerSpec`;结构类 finding | `FIELD_TYPES`(漏了哪个键,哪个键就变成 `POL009`) |
| `model.py` | 全部数据类、`fingerprint()`、pointer 转义 | 加 dataclass 字段,不改函数签名 |
| `rules/__init__.py` | `@register` 注册表与 `evaluate()` | 不动 |
| `rules/builtin.py` | 八条内置规则 | 一条规则一个函数,good first issue 的入口 |
| `policy.py` | 基线 JSON 与指纹 | 新权限维度 + schema 版本号迁移 |
| `diff.py` | 结构化比对 | 新 `DiffRow.kind` 及其严重级别 |
| `review.py` | 显式批准:必须给理由,并追加凭证 | 一条批准记录里放什么 |
| `report.py` | 六种渲染器,含 SARIF 2.1.0 与自包含 HTML | 新 `render_*` |
| `cli.py` | 八个子命令,只做编排 | 新 `cmd_*` |
| `fixtures/gate` + `scripts/gate_selftest.py` | 退出码契约以数据形式存放 | 新 fixture 及其期望码 |

## 自骨架起守住的三条约束

1. **零运行时依赖**:`dependencies = []`,CLI 用 `argparse`,测试用 `unittest`,HTML 报告手写内联 CSS。任何新增依赖都得先证明核心路径不需要它。
2. **unknown 不等于安全**:解析器不认识的 capability 或字段会变成 finding,绝不静默通过 —— 自 0.1.0 起它还要付退出码,`--unknown error` 是默认值。`mcp-policy-lint coverage` 会按文件、按 server 打出「读进去了什么、没读进去什么」。
3. **只读**:不执行 server、不 fetch 远程 capability、不改你的配置。唯一的写动作是你用 `--out` 指定的报告与基线;而基线只经 `approve --reason` 移动,且留下凭证。

## 明确不做的层次

运行时隔离、源码恶意检测、prompt injection 扫描、网络代理、LLM judge、SaaS、dashboard、自动修复。这些要么已有强项目占着(ToolHive、mcp-scanner、agentgateway),要么会破坏这个工具的心智:三十秒上手、零安装摩擦、结论可追溯。
