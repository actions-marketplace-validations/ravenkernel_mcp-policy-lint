# mcp-policy-lint architecture

**English** | [简体中文](ARCHITECTURE.zh-CN.md)

## What this page is for

If you only want to run mcp-policy-lint, the [README](README.md) is enough. This page answers the
next question: *why did this finding appear, and where did my exit code come from?* Every
conclusion the tool prints can be traced through the six stages below back to a byte in
your config file.

## The path of one config file

```
mcp-policy-lint scan .            discover   which files are read
                          normalize  dict -> [ServerSpec] + structural findings
                          rules      ServerSpec -> [Finding]
mcp-policy-lint diff / check      policy     baseline: what was approved, and its fingerprint
                          diff       current permission surface vs approved one
mcp-policy-lint coverage          report     text / ndjson / json / single-file HTML
-- exit --                exitcode   findings + drift + --strict -> 0 / 1 / 2 / 3
```

## Stage by stage, in user terms

1. **discover** — you pass files or directories; the tool walks directories, skips the
   usual noise (`SKIP_DIRS`), and keeps only filenames it recognizes in `CANDIDATE_NAMES`.
   Nothing is downloaded, nothing is executed.
2. **normalize** — every client writes the same idea differently (`mcpServers` vs
   `servers`, `url` vs `serverUrl`, `type` sometimes absent). This stage folds each file
   into one `ServerSpec`, remembering for every field the JSON Pointer it came from. Whatever
   it cannot fold becomes a *structural finding* instead of being dropped: an unrecognized
   shape (`POL000`), an unknown capability (`POL007`), a field it does not model
   (`POL009`), or a server name defined twice (`POL011`).
3. **rules** — eight registered rules read `ServerSpec` only. They never touch raw JSON,
   which is why a rule cannot crash on a config shape it has not seen. `mcp-policy-lint rules`
   prints the whole list, structural findings included.
4. **policy** — `mcp-policy-lint init` writes a baseline: per server, a fingerprint plus the
   permission surface (`allowed_tools`, `roots`, `net_egress`, `env_allowlist`,
   `auto_approve`, `disabled`, and `waivers` for accepted findings). Values of env vars are
   never stored, only their names.
5. **diff** — `mcp-policy-lint diff` compares the current surface against the baseline
   structurally, never as a text diff. A server appears or disappears, the fingerprint
   changes, or one dimension gains or loses an entry.
6. **report and exit code** — the report formats the findings; the exit code decides for
   CI.

## The exit code is the product

| code | meaning | typical cause |
| --- | --- | --- |
| 0 | pass | nothing to report |
| 1 | findings failed | a rule fired at `error` (including `unknown`, which costs `error` by default) |
| 2 | policy drift | a server, a permission or a fingerprint differs from the baseline |
| 3 | usage or config error | bad path, bad JSON, bad policy file, unknown `--rule`, typo in a flag |

Precedence is `3 > 2 > 1 > 0`: a broken input outranks a broken policy, which outranks a
finding. `--strict` promotes `warn` to a failure. `--unknown warn|ignore` is the only way
to make an unmodeled field cost less — there is no flag that makes it cost nothing and stay
invisible without saying so.

## What each stage guarantees

| stage | you can rely on | the failure it refuses to hide |
| --- | --- | --- |
| discover | no network, no subprocess | a config you passed but nobody read (`POL000` if its shape is unknown) |
| normalize | every finding carries a resolvable JSON Pointer | a field silently dropped because its type was wrong (`POL009`) |
| rules | a rule never sees raw JSON | a rule that cannot judge is marked `unknown`, not passed |
| policy | values are not stored, only names and fingerprints | a baseline that would leak secrets |
| diff | a change in the permission surface is an error; a removal is a warning | a textual diff that drowns the one line that matters |
| report | self-contained HTML, machine-readable JSON/NDJSON | a report that needs a network to render |

## Data contracts

```python
ServerSpec(name, command, args, url, url_field, env, roots, tools, capabilities,
           auto_approve, disabled, unmodeled, source, pointer)
ToolSpec(name, description, annotations, input_schema, pointer)
Finding(rule_id, severity, title, message, server, pointer,
        remediation, threat, unknown=False)
Policy(version=1, servers={name: {fingerprint, transport, allowed_tools, roots,
                                  net_egress, env_allowlist, auto_approve,
                                  disabled, waivers}})
DiffRow(kind, server, path, before, after, severity)
```

`pointer` is always an RFC 6901 JSON Pointer (`/mcpServers/a~1b/command` for a server
named `a/b`), so a finding resolves with any JSON Pointer tool you already have.

## Where to change things

| module | responsibility | first place to look when extending |
| --- | --- | --- |
| `discover.py` | explicit paths, directory recursion, known client filenames | `CANDIDATE_NAMES` |
| `normalize.py` | per-client shapes into one `ServerSpec`; structural findings | `FIELD_TYPES` (a key missing here becomes `POL009`) |
| `model.py` | all dataclasses, `fingerprint()`, pointer escaping | add a dataclass field, no signature changes |
| `rules/__init__.py` | the `@register` registry and `evaluate()` | leave alone |
| `rules/builtin.py` | the eight built-in rules | one function per rule, the good-first-issue surface |
| `policy.py` | baseline JSON and fingerprints | a new permission dimension plus a schema version bump |
| `diff.py` | structural comparison | a new `DiffRow.kind` and its severity |
| `report.py` | five renderers, self-contained HTML | a new `render_*` |
| `cli.py` | seven subcommands, orchestration only | a new `cmd_*` |
| `fixtures/gate` + `scripts/gate_selftest.py` | the exit-code contract as data | a new fixture with its expected code |

## Three constraints held since the skeleton

1. **Zero runtime dependencies**: `dependencies = []`, `argparse` for the CLI, `unittest`
   for tests, hand-written inline CSS for the HTML report. Anything extra has to prove the
   core path does not need it.
2. **unknown is not safe**: a capability or field the parser does not understand becomes a
   finding, never a silent pass — and since 0.1.0 it also costs an exit code, with
   `--unknown error` as the default. `mcp-policy-lint coverage` prints what was consumed and what
   was not, per file and per server.
3. **Read-only**: never executes a server, never fetches remote capabilities, never edits
   your config. The only writes are the report and the baseline you name with `--out`.

## Deliberately out of scope

Runtime isolation, source-code malware detection, prompt-injection scanning, network proxy,
LLM judge, SaaS, dashboard, auto-remediation. Either a strong project already owns that
layer (ToolHive, mcp-scanner, agentgateway), or adding it would break the promise: thirty
seconds, no install friction, a verdict you can trace.
