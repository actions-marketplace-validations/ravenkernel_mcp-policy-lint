# mcplint

[![ci](https://github.com/ravenkernel/mcplint/actions/workflows/ci.yml/badge.svg)](https://github.com/ravenkernel/mcplint/actions/workflows/ci.yml) [![license](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](https://github.com/ravenkernel/mcplint/blob/main/LICENSE) [![PyPI](https://img.shields.io/pypi/v/mcp-policy-lint.svg)](https://pypi.org/project/mcp-policy-lint/)

**English** | [简体中文](README.zh-CN.md)

Turn `mcp.json` into a readable, testable, PR-blocking permission policy — **before** you run any MCP server. Local, zero dependencies, no model key, no Docker.

```bash
pip install mcp-policy-lint   # the PyPI distribution; the command is mcplint
mcplint demo                  # 30 seconds, no network, no API key, no Docker
# from a checkout instead: pip install -e .
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

## Three-step workflow

```bash
# 1. Record an approved baseline (commit it)
mcplint init examples/safe.mcp.json --out policy.lock.json

# 2. Scan any client config
mcplint scan examples/unsafe.mcp.json --format ndjson

# 3. CI gate: drift or findings -> non-zero exit code
mcplint check examples/unsafe.mcp.json --baseline policy.lock.json --strict
```

`scan` renders `text / ndjson / json / html`; `--html-out report.html` writes a single self-contained file (no external assets, opens straight from `file://`). `diff` prints an add / remove / modify table on its own.

## Unknowns cost an exit code

Anything the tool cannot understand is reported as `unknown`, never quietly counted as a pass. Three cases all pay: an unrecognized file shape (`MCP000`), a field that is not modeled (`MCP009`), a transport that cannot be inferred (`MCP008`).

```bash
mcplint check mcp.json                  # default --unknown error: fail rather than guess
mcplint check mcp.json --unknown warn   # downgrade to warn (still gated by --strict)
mcplint check mcp.json --unknown ignore # say explicitly that you do not care
mcplint coverage mcp.json               # which fields this run actually consumed
```

`coverage` is the one command that volunteers what it failed to understand: per server, the fields it modeled, the fields it did not, and the unknown findings that follow from them.

## Verify it yourself, do not take my word

`scripts/gate_selftest.py` writes down which input must produce which exit code — 10 fixtures plus one drift case, zero dependencies, no install:

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

That table is the whole claim of this document: a config it cannot read fails (1), a baseline drift is caught (2), and plaintext HTTP on localhost is not a false positive (0). Change the severity of any rule and this table goes red first.

## What it is not

| does not | who does |
| --- | --- |
| run MCP servers, sandbox them | ToolHive |
| scan server source for malware | mcp-scanner |
| proxy traffic, RBAC, JWT | agentgateway |
| use an LLM as judge, judge prompt injection | — |
| edit configs, auto-approve anything | — |

It answers three questions only: what permissions does the config **declare**, does that violate a **least-privilege baseline**, and what did **this PR change**. `unknown` is not `safe`, and every finding carries its JSON Pointer.

## Exit codes

| code | meaning |
| --- | --- |
| 0 | pass |
| 1 | at least one error (including an unknown treated as error; warnings too under `--strict`) |
| 2 | drift from the policy baseline / incompatible schema |
| 3 | usage or config error (missing file, corrupt baseline) |

Priority is `3 > 2 > 1 > 0`, designed to be passed straight to `sys.exit()` in GitHub Actions.

## Adding a rule is one function

```python
from mcplint.rules import register
from mcplint.model import Finding

@register("MCP100")
def no_root_ssh(server):
    if any(".ssh" in r for r in server.roots):
        return [Finding("MCP100", "error", "root points at .ssh",
                        f"{server.name} exposes the SSH directory", server.name,
                        server.pointer + "/roots", "narrow roots to the repository")]
    return []
```

The rule registry, policy format, report renderers and config discovery are independent modules — see [ARCHITECTURE.md](https://github.com/ravenkernel/mcplint/blob/main/ARCHITECTURE.md).

## Use it as a GitHub Action

```yaml
- uses: ravenkernel/mcplint@v1
  with:
    path: .                       # file or directory
    baseline: policy.lock.json    # optional; omit to only report findings
    unknown: error                # error (default) | warn | ignore
    strict: false
```

The action installs `mcp-policy-lint`, runs `mcplint check`, and fails the job with mcplint own exit code — the same `0/1/2/3` you see locally. It writes nothing but the baseline you ask for, and it never edits a config file.

| input | default | effect |
|---|---|---|
| `path` | `.` | config file or directory to check |
| `baseline` | empty | turns on drift detection against `policy.lock.json` |
| `unknown` | `error` | price of a field mcplint cannot model |
| `strict` | `false` | warnings become failures |
| `extra-args` | empty | appended to `mcplint check` |
| `version` | `>=0.1.2,<0.2` | pip requirement for the package |

## Status

0.1.2: runs end to end, 9 built-in rules (`MCP001-006`, `MCP008`, `MCP009`, `MCP010`), covered by tests at both the CLI and library level. Lint messages are English as of 0.1.1 (0.1.0 shipped the same rules with Chinese messages). 0.1.2 is the first PyPI release, and it turns the crashes and false positives I found by hand into tests: a field with the wrong type is `MCP009` instead of an exception, a server name containing `/` produces a valid pointer (`a~1b`), two servers with the same name are `MCP011`, `git -c user.name=x` is not read as a shell, and a mistyped `--rule` id or flag exits 3 instead of passing silently.

Config compatibility currently covers three top-level shapes (`mcpServers` / `servers` / `mcp.servers`) and the common fields of Claude Desktop, Cursor, VS Code, Cline and Windsurf. **What is not covered is never reported as a pass**: an unmodeled field always produces `MCP009`, and `--unknown` (error by default) decides whether it blocks the merge; `mcplint coverage` prints the full field-consumption table.

No sandbox, no gateway, no prompt-injection detection — those belong to the runtime layer. No claim of "secure by default".
