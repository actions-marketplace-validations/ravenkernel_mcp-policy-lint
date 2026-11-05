# mcp-policy-lint

[![ci](https://github.com/ravenkernel/mcp-policy-lint/actions/workflows/ci.yml/badge.svg)](https://github.com/ravenkernel/mcp-policy-lint/actions/workflows/ci.yml) [![license](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](https://github.com/ravenkernel/mcp-policy-lint/blob/main/LICENSE) [![PyPI](https://img.shields.io/pypi/v/mcp-policy-lint.svg)](https://pypi.org/project/mcp-policy-lint/)

**English** | [简体中文](README.zh-CN.md)

Turn `mcp.json` into a readable, testable, PR-blocking permission policy — **before** you run any MCP server. Local, zero dependencies, no model key, no Docker.

```bash
pip install mcp-policy-lint   # installs the mcp-policy-lint command
mcp-policy-lint demo                  # 30 seconds, no network, no API key, no Docker
# from a checkout instead: pip install -e .
```

```
mcp-policy-lint demo — 2 servers scanned, 6 findings
no network, no API key, no Docker
(vs sample baseline: 3 drift rows — run `mcp-policy-lint diff` to inspect)

mcp-policy-lint 0.2.0 — 6 findings

ERROR  POL003  remote       /mcpServers/remote/url                 Plaintext HTTP to a remote endpoint
        http://api.example.com/mcp has no TLS, so tool descriptions and responses can be altered in transit
        fix: Use https:// and confirm the authentication settings
ERROR  POL001  shell        /mcpServers/shell/command              stdio command can start a shell
        shell runs its arguments through sh, so it can execute arbitrary commands
        fix: Call a concrete executable directly instead of assembling a command with -c
ERROR  POL002  shell        /mcpServers/shell/env/AWS_SECRET_ACCESS_KEY Likely real credential in config
        AWS_SECRET_ACCESS_KEY is not a placeholder; it can leak through logs or travel with the repository
        fix: Reference an environment variable or a secret manager; never put the value in mcp.json
ERROR  POL004  shell        /mcpServers/shell/roots/0              root outside the repository boundary
        root /home/me points at a home directory or escapes the repository
        fix: Narrow roots to the current project directory
WARN   POL005  shell        /mcpServers/shell/tools/0              Tool annotation contradicts its name or description
        delete_everything claims read-only or non-destructive, but its description contains write verbs
        fix: Fix the annotation or the name; a client may skip confirmation because of it
WARN   POL006  shell        /mcpServers/shell/tools/0              Tool input has no constraints
        delete_everything has an empty inputSchema or no properties, so argument boundaries cannot be checked
        fix: Complete the JSON Schema: declare required fields and enums

exit code: 1
mcp-policy-lint 0.2.0 coverage — 1 config(s), 2 server(s)

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
mcp-policy-lint init examples/safe.mcp.json --out policy.lock.json

# 2. Scan any client config
mcp-policy-lint scan examples/unsafe.mcp.json --format ndjson

# 3. CI gate: drift or findings -> non-zero exit code
mcp-policy-lint check examples/unsafe.mcp.json --baseline policy.lock.json --strict
```

`scan` renders `text / ndjson / json / html`; `--html-out report.html` writes a single self-contained file (no external assets, opens straight from `file://`). `diff` prints an add / remove / modify table on its own.

## Unknowns cost an exit code

Anything the tool cannot understand is reported as `unknown`, never quietly counted as a pass. Three cases all pay: an unrecognized file shape (`POL000`), a field that is not modeled (`POL009`), a transport that cannot be inferred (`POL008`).

```bash
mcp-policy-lint check mcp.json                  # default --unknown error: fail rather than guess
mcp-policy-lint check mcp.json --unknown warn   # downgrade to warn (still gated by --strict)
mcp-policy-lint check mcp.json --unknown ignore # say explicitly that you do not care
mcp-policy-lint coverage mcp.json               # which fields this run actually consumed
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
from mcp_policy_lint.rules import register
from mcp_policy_lint.model import Finding

@register("POL100")
def no_root_ssh(server):
    if any(".ssh" in r for r in server.roots):
        return [Finding("POL100", "error", "root points at .ssh",
                        f"{server.name} exposes the SSH directory", server.name,
                        server.pointer + "/roots", "narrow roots to the repository")]
    return []
```

The rule registry, policy format, report renderers and config discovery are independent modules — see [ARCHITECTURE.md](https://github.com/ravenkernel/mcp-policy-lint/blob/main/ARCHITECTURE.md).

## Use it as a GitHub Action

```yaml
- uses: ravenkernel/mcp-policy-lint@v1
  with:
    path: .                       # file or directory
    baseline: policy.lock.json    # optional; omit to only report findings
    unknown: error                # error (default) | warn | ignore
    strict: false
```

The action installs `mcp-policy-lint`, runs `mcp-policy-lint check`, and fails the job with its own exit code — the same `0/1/2/3` you see locally. It writes nothing but the baseline you ask for, and it never edits a config file.

| input | default | effect |
|---|---|---|
| `path` | `.` | config file or directory to check |
| `baseline` | empty | turns on drift detection against `policy.lock.json` |
| `unknown` | `error` | price of a field mcp-policy-lint cannot model |
| `strict` | `false` | warnings become failures |
| `extra-args` | empty | appended to `mcp-policy-lint check` |
| `version` | `>=0.2.0,<0.3` | pip requirement for the package |

## Status

0.2.0 is a rename: the command, the import package, the repository and the action are all `mcp-policy-lint` now, and rule ids moved from `MCP001` to `POL001`. Nothing about behaviour changed — same rules, same exit codes. The reason is discoverability: `mcplint` was already a crowded name, and ids like `MCP009` mean something else entirely in a neighbouring scanner. 0.1.3 ships the GitHub Action above and nothing else — same rules, same exit codes — so the PyPI page documents the way most teams will actually run it. 0.1.2: runs end to end, 9 built-in rules (`POL001-006`, `POL008`, `POL009`, `POL010`), covered by tests at both the CLI and library level. Lint messages are English as of 0.1.1 (0.1.0 shipped the same rules with Chinese messages). 0.1.2 is the first PyPI release, and it turns the crashes and false positives I found by hand into tests: a field with the wrong type is `POL009` instead of an exception, a server name containing `/` produces a valid pointer (`a~1b`), two servers with the same name are `POL011`, `git -c user.name=x` is not read as a shell, and a mistyped `--rule` id or flag exits 3 instead of passing silently.

Config compatibility currently covers three top-level shapes (`mcpServers` / `servers` / `mcp.servers`) and the common fields of Claude Desktop, Cursor, VS Code, Cline and Windsurf. **What is not covered is never reported as a pass**: an unmodeled field always produces `POL009`, and `--unknown` (error by default) decides whether it blocks the merge; `mcp-policy-lint coverage` prints the full field-consumption table.

No sandbox, no gateway, no prompt-injection detection — those belong to the runtime layer. No claim of "secure by default".
