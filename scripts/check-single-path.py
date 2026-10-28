#!/usr/bin/env python3
"""Fail if an item in the stable `aitp` surface has more than one public path.

  check-single-path.py [STABLE [EXPERIMENTAL]]
      default crates/aitp/public-api.{stable,experimental}.txt

Every item has one canonical path (STABILITY.md, "Public paths").
cargo-public-api prints an item once for each path it can be reached
at: a `pub use` re-export, a glob, or a `pub mod` leaf whose items the
parent also re-exports each add a line that repeats the definition
under a second path. A type's fields, variants and impls are printed
under one of those paths only; a trait's methods under each of them.

So an item is keyed by its definition line with its module path
removed: the declaration keyword, the item's name and everything after
the path (generics, signature, type). Module-level items with the same
key are one item at several paths when one path's members and impls
(with the path written as `Self`) are a subset of the other's, which
covers both cases above and every fn, const, static and type alias
(which have no members). Two types that each have members the other
lacks are distinct types that share a name. Only items whose parent is
a module (`pub mod` in the snapshot) are compared, so methods and
associated items are not.

The stable snapshot is checked, then the stable snapshot with each
section of the experimental one (what an unstable feature adds). Reads
the committed snapshots; needs no toolchain.
"""

from __future__ import annotations

import importlib.util
import re
import sys
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
STABLE = ROOT / "crates" / "aitp" / "public-api.stable.txt"
EXPERIMENTAL = ROOT / "crates" / "aitp" / "public-api.experimental.txt"

_spec = importlib.util.spec_from_file_location(
    "public_api", Path(__file__).resolve().parent / "public-api.py")
_public_api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_public_api)
primary_path = _public_api.primary_path
body = _public_api.body
DEFINING = _public_api.DEFINING

KIND = re.compile(r"\b(fn|struct|enum|trait|mod|const|static|type|union|macro) $")


def items(lines: list[str]) -> list[tuple[str, str, str]]:
    """(kind, path, key) for every module-level item a line defines."""
    modules = {primary_path(l) for l in lines if l.startswith("pub mod ")}
    out = []
    for l in lines:
        m = DEFINING.match(l)
        if not m:
            continue
        kind = KIND.search(m.group(0)).group(1)
        if kind == "mod":
            continue
        path = primary_path(l)
        parent, _, name = path.rpartition("::")
        if parent not in modules:
            continue
        rest = l[m.end():]
        # `rest` starts with the path, generics and all; drop the module part.
        key = m.group(0) + rest[len(parent) + 2:]
        out.append((kind, path, key))
    return out


def fingerprints(lines: list[str], paths: set[str]) -> dict[str, frozenset[str]]:
    """Each path's members and the impls on it, with the path itself
    replaced by `Self`, so the same item prints the same set at each
    path it has."""
    out: dict[str, set[str]] = {p: set() for p in paths}
    for l in lines:
        p = primary_path(l)
        owner = p if l.startswith("impl") else p.rpartition("::")[0]
        if owner in out:
            out[owner].add(re.sub(re.escape(owner) + r"(?![A-Za-z0-9_])", "Self", l))
    return {p: frozenset(v) for p, v in out.items()}


def duplicates(lines: list[str]) -> list[list[str]]:
    """Each item reachable at more than one path, as its sorted paths.

    Paths whose definition lines share a key are one item when one path's
    members are a subset of the other's: cargo-public-api prints a
    re-exported type's impls under one path only (the other has none),
    and a re-exported trait's methods under every path (the sets are
    equal). Two types that each have members the other lacks are two
    distinct types."""
    groups: dict[str, list[str]] = defaultdict(list)
    for _kind, path, key in items(lines):
        groups[key].append(path)
    fps = fingerprints(lines, {p for g in groups.values() if len(g) > 1 for p in g})
    out = []
    for group in groups.values():
        if len(group) < 2:
            continue
        parent = {p: p for p in group}

        def find(p: str) -> str:
            while parent[p] != p:
                p = parent[p]
            return p

        for i, a in enumerate(group):
            for b in group[i + 1:]:
                if fps[a] <= fps[b] or fps[b] <= fps[a]:
                    parent[find(a)] = find(b)
        components: dict[str, list[str]] = defaultdict(list)
        for p in group:
            components[find(p)].append(p)
        out.extend(sorted(c) for c in components.values() if len(c) > 1)
    return sorted(out)


def sections(text: str) -> dict[str, list[str]]:
    """The experimental snapshot's lines, by `## feature` section."""
    out: dict[str, list[str]] = {}
    current = None
    for l in text.splitlines():
        if l.startswith("## "):
            current = out.setdefault(l[3:].strip(), [])
        elif current is not None and l and not (l.startswith("#") and not l.startswith("#[")):
            current.append(l)
    return out


def main() -> int:
    stable_path = Path(sys.argv[1]) if len(sys.argv) > 1 else STABLE
    experimental_path = Path(sys.argv[2]) if len(sys.argv) > 2 else EXPERIMENTAL
    stable = body(stable_path.read_text())
    surfaces = [("stable", stable)]
    if experimental_path.exists():
        surfaces += [(f"stable + {name}", stable + lines)
                     for name, lines in sections(experimental_path.read_text()).items()]
    seen: set[tuple[str, ...]] = set()
    found = 0
    for name, lines in surfaces:
        for paths in duplicates(lines):
            if tuple(paths) in seen:
                continue
            seen.add(tuple(paths))
            found += 1
            print(f"::error::{name}: one item, {len(paths)} public paths: {', '.join(paths)}")
    if found:
        print(f"{found} item(s) with more than one public path; keep the canonical "
              "path (STABILITY.md, \"Public paths\") and remove the others")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
