#!/usr/bin/env python3
"""Fail if the stable `aitp` surface names a type from a pre-1.0 crate.

  check-stable-deps.py [SNAPSHOT]   default crates/aitp/public-api.stable.txt

Every path in the snapshot starts with a crate name. A path whose crate
is not `aitp` or the standard library (`core`, `alloc`, `std`) must name
a crate that `aitp` depends on, directly or not, and every version of
that crate in the dependency graph must be 1.0.0 or later. A 0.x crate
can break its API in any minor release, which would force a breaking
release of `aitp` (STABILITY.md). The graph comes from `cargo metadata`.
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SNAPSHOT = ROOT / "crates" / "aitp" / "public-api.stable.txt"
OWN = {"aitp", "core", "alloc", "std"}
PATH = re.compile(r"(?<![\w:])([a-z_][a-z0-9_]*)::[A-Za-z_]")


def crate_versions() -> dict[str, set[str]]:
    """Every crate `aitp` reaches through normal dependencies, by the name
    used in paths, with each version in the graph."""
    meta = json.loads(subprocess.run(
        ["cargo", "metadata", "--format-version", "1", "--locked"],
        cwd=ROOT, capture_output=True, text=True, check=True).stdout)
    packages = {p["id"]: p for p in meta["packages"]}
    nodes = {n["id"]: n for n in meta["resolve"]["nodes"]}
    root = next(p["id"] for p in meta["packages"]
                if p["name"] == "aitp" and p["source"] is None)
    seen, todo = set(), [root]
    while todo:
        pid = todo.pop()
        if pid in seen:
            continue
        seen.add(pid)
        for dep in nodes[pid]["deps"]:
            if any(k["kind"] is None for k in dep["dep_kinds"]):
                todo.append(dep["pkg"])
    out: dict[str, set[str]] = defaultdict(set)
    for pid in seen - {root}:
        p = packages[pid]
        names = {p["name"].replace("-", "_")}
        names |= {t["name"].replace("-", "_") for t in p["targets"] if "lib" in t["kind"]}
        for name in names:
            out[name].add(p["version"])
    return out


def problems(lines: list[str], versions: dict[str, set[str]]) -> list[str]:
    found: dict[str, str] = {}
    for line in lines:
        for crate in PATH.findall(line):
            if crate in OWN or crate in found:
                continue
            vs = versions.get(crate)
            if vs is None:
                found[crate] = f"{crate}: not a dependency of aitp: {line}"
            elif any(v.split(".")[0] == "0" for v in vs):
                found[crate] = f"{crate} {', '.join(sorted(vs))} is pre-1.0: {line}"
    return [found[c] for c in sorted(found)]


def main() -> int:
    snapshot = Path(sys.argv[1]) if len(sys.argv) > 1 else SNAPSHOT
    lines = [l for l in snapshot.read_text().splitlines()
             if l and not (l.startswith("#") and not l.startswith("#["))]
    found = problems(lines, crate_versions())
    for p in found:
        print(f"::error::the stable aitp surface names a type from {p}")
    print(f"{len(found)} pre-1.0 crate(s) in the stable aitp surface")
    return 1 if found else 0


if __name__ == "__main__":
    sys.exit(main())
