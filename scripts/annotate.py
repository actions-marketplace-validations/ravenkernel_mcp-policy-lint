"""Turn a --format json report into GitHub workflow annotations. Stdlib only, no network."""
from __future__ import annotations

import json
import sys
from pathlib import Path

LEVEL = {"error": "error", "warn": "warning", "info": "notice"}


def esc(text) -> str:
    return str(text).replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def prop(text) -> str:
    return esc(text).replace(":", "%3A").replace(",", "%2C")


def relpath(value: str) -> str:
    """Repository-relative POSIX path: annotations must match the files in the diff."""
    if not value:
        return ""
    path = Path(value)
    try:
        return path.resolve().relative_to(Path.cwd().resolve()).as_posix()
    except (ValueError, OSError):
        return path.as_posix()


def command(level: str, file: str, title: str, message: str) -> str:
    where = f"file={prop(file)},line=1," if file else ""
    return f"::{level} {where}title={prop(title)}::{esc(message)}"


def main(path: str) -> int:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    sources = data.get("sources", {})
    out = []
    for f in data.get("findings", []):
        level = LEVEL.get(f.get("severity", ""), "notice")
        text = f"{f.get('title', '')}: {f.get('message', '')}"
        if f.get("remediation"):
            text += f" Fix: {f['remediation']}"
        out.append(command(level, relpath(sources.get(f.get("server", ""), "")),
                           f"{f.get('rule_id', '')} {f.get('server', '')}".strip(), text))
    for d in data.get("diff", []):
        text = f"{d.get('kind')} at {d.get('path')}: {d.get('before')!r} -> {d.get('after')!r}"
        out.append(command(LEVEL.get(d.get("severity", ""), "notice"),
                           relpath(sources.get(d.get("server", ""), "")),
                           f"DRIFT {d.get('server', '')}".strip(), text))
    if out:
        print("\n".join(out))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
