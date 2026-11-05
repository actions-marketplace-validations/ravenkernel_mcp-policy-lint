# mcplint architecture

**English** | [简体中文](ARCHITECTURE.zh-CN.md)

## One-line architecture

**discover → normalize → rules → policy → report → exit code.** Six layers, all pure-function stdlib modules: no global state, no network, no plugin-loader magic.

```
CLI (argparse)
  ├─ discover.py   paths → [file paths]          (multi-client config discovery)
  ├─ normalize.py  dict → [ServerSpec]           (per-client formats, with JSON Pointers)
  ├─ rules/        ServerSpec → [Finding]        (registry-based rule engine)
  ├─ policy.py     [ServerSpec] → Policy         (baseline creation / fingerprints)
  ├─ diff.py       Policy vs Current → [DiffRow] (drift detection)
  ├─ report.py     Findings + Diff → text/ndjson/json/single-file HTML
  └─ exitcode.py   Findings + Diff + strict → 0/1/2/3
```

## Module responsibilities and extension points

| module | responsibility | where to change when adding a feature |
| --- | --- | --- |
| `discover.py` | explicit path / directory recursion / well-known client filenames | add one entry to `CANDIDATE_NAMES` |
| `normalize.py` | parse `mcpServers` / `servers` / `mcp.servers` into a uniform `ServerSpec` | add a `_parse_*` branch |
| `model.py` | every dataclass plus `fingerprint()`; the only data contract | new field = new dataclass field, no signature changes |
| `rules/__init__.py` | the `@register` registry and `evaluate()` | leave alone |
| `rules/builtin.py` | built-in rules, each depending only on `ServerSpec` | one function per rule — the good-first-issue surface |
| `policy.py` | baseline JSON: fingerprint / allowed_tools / roots / net_egress / env_allowlist / waivers | new policy dimension = new field plus a schema version bump |
| `diff.py` | structural diff, never a textual JSON diff | new dimension = a new `DiffRow.kind` |
| `report.py` | four renderers, self-contained HTML | new format = a new `render_*` |
| `cli.py` | six subcommands, orchestration only | new subcommand = a new `cmd_*` |

## Core data contracts

```python
ServerSpec(name, command, args, url, env, roots, tools, capabilities, source, pointer,
           transport, url_field, auto_approve, disabled, unmodeled)
ToolSpec(name, description, annotations, input_schema, pointer)
Finding(rule_id, severity, title, message, server, pointer, remediation, threat, unknown=False)
Policy(version=1, servers={name: {fingerprint, allowed_tools, roots,
                                  net_egress, env_allowlist, auto_approve,
                                  disabled, waivers}})
DiffRow(kind, server, path, before, after, severity)
```

`pointer` is always a JSON Pointer (e.g. `/mcpServers/shell/env`), so every conclusion can be traced back to the exact bytes in the config. That is the difference between trustworthy and merely plausible.

## Three design constraints, held from the skeleton onward

1. **Zero runtime dependencies**: `dependencies = []`, `argparse` for the CLI, `unittest` for tests, hand-written inline CSS/JS for the HTML report. Any extra must prove the core path does not need it.
2. **unknown ≠ safe**: a capability or field the parser does not understand becomes a finding, never a silent pass. Since 0.1.0 an unknown also costs an exit code: `--unknown error` is the default, and `mcplint coverage` prints what was and was not consumed.
3. **Read-only**: never executes a server, never fetches remote capabilities, never writes user config. The only writes are the report and the baseline named by `--out`.

## Working order from skeleton to 0.1.0

1. `python -m mcplint demo` runs end to end
2. collect real client configs → extend `discover.py` / `normalize.py`
3. grow rules from 7 to 15+, each with a failure fixture and a false-positive sample
4. give `policy.py` waiver semantics and schema migration
5. GitHub Action (calls `scan` / `check` only, zero telemetry)
6. five good first issues: a new client path / a new rule / policy schema migration / HTML accessibility / rule test fixtures

What actually shipped in 0.1.0: steps 1–2, nine rules (four of the original seven were made stricter or demoted — see the rule severities in `src/mcplint/rules/builtin.py`), `autoApprove` and `disabled` in the baseline, the `coverage` subcommand, and CI that runs a table of expected exit codes on four Python versions. Step 5 is still open.

## Layers deliberately out of scope

Runtime isolation, source-code malware detection, network proxy, LLM judge, SaaS, dashboard, auto-remediation. Either a strong project already owns them, or they would break the product promise: 30 seconds, zero install friction.
