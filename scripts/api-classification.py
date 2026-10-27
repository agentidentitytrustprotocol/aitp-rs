#!/usr/bin/env python3
"""The shape of every public struct and enum in the stable `aitp` surface.

  generate   rewrite the table in docs/api-classification.md, keeping
             the reasons already written there
  check      fail if a stable type is missing from the table, listed
             under the wrong class, or exhaustive without a reason

Each type is in one class:

  non_exhaustive   `#[non_exhaustive]`: a new field or variant is not a break
  private fields   a struct with a private field: callers cannot build it
                   with a literal, so a new field is not a break
  exhaustive       callers can match or build it in full, so any new field
                   or variant is a break. Each needs a reason.

The types come from the rustdoc JSON of `aitp` built with the stable
features (scripts/public-api.py), at the shortest public path of each.
Needs the pinned nightly (Makefile).
"""

from __future__ import annotations

import importlib.util
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DOC = ROOT / "docs" / "api-classification.md"
# The table is everything after this heading, which ends the file. No
# HTML comment markers: the website's MDX build rejects them.
HEADING = "## Types\n"
CLASSES = ("non_exhaustive", "private fields", "exhaustive")

_spec = importlib.util.spec_from_file_location("public_api", ROOT / "scripts" / "public-api.py")
public_api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(public_api)


def rustdoc_json(target_dir: Path) -> dict:
    cmd = ["cargo", f"+{public_api.NIGHTLY}", "rustdoc", "-q", "-p", "aitp", "--lib",
           "--no-default-features", "--features", ",".join(public_api.STABLE_FEATURES),
           "--", "-Z", "unstable-options", "--output-format", "json", "-A", "warnings"]
    env = {**os.environ, "CARGO_TERM_COLOR": "never", "CARGO_TARGET_DIR": str(target_dir)}
    res = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True, env=env)
    if res.returncode != 0:
        sys.stderr.write(res.stderr)
        sys.exit(f"failed: {' '.join(cmd)}")
    return json.loads((target_dir / "doc" / "aitp.json").read_text())


def kind_of(item: dict) -> str:
    return next(iter(item["inner"]))


def public_paths(doc: dict) -> dict[str, list[str]]:
    """Every public path of each local struct and enum, by item id."""
    index = doc["index"]
    out: dict[str, list[str]] = {}

    def walk(module_id: str, prefix: list[str], seen: frozenset) -> None:
        if module_id in seen:
            return
        seen = seen | {module_id}
        for child in index[module_id]["inner"]["module"]["items"]:
            item = index.get(str(child))
            if item is None or item.get("visibility") != "public" and kind_of(item) != "use":
                continue
            kind = kind_of(item)
            if kind == "use":
                use = item["inner"]["use"]
                target = index.get(str(use["id"])) if use["id"] is not None else None
                if target is None or target["crate_id"] != 0:
                    continue
                if use["is_glob"]:
                    if kind_of(target) == "module":
                        walk(str(use["id"]), prefix, seen)
                    continue
                name, kind, child = use["name"], kind_of(target), use["id"]
            else:
                name = item["name"]
            if kind == "module":
                walk(str(child), prefix + [name], seen)
            elif kind in ("struct", "enum"):
                out.setdefault(str(child), []).append("::".join(prefix + [name]))

    walk(str(doc["root"]), ["aitp"], frozenset())
    return out


def shape(item: dict) -> tuple[str, str]:
    """(kind, class) of a struct or enum."""
    kind = kind_of(item)
    if "non_exhaustive" in item["attrs"]:
        return kind, "non_exhaustive"
    if kind == "struct":
        k = item["inner"]["struct"]["kind"]
        stripped = (isinstance(k, dict) and (
            k.get("plain", {}).get("has_stripped_fields")
            or None in k.get("tuple", [0])))
        if stripped:
            return kind, "private fields"
    return kind, "exhaustive"


def preferred(paths: list[str]) -> str:
    return min(paths, key=lambda p: (p.startswith("aitp::prelude::"), p.count("::"), p))


def current(target_dir: Path) -> dict[str, tuple[str, str]]:
    doc = rustdoc_json(target_dir)
    out = {}
    for item_id, paths in public_paths(doc).items():
        out[preferred(paths)] = shape(doc["index"][item_id])
    return out


ROW = re.compile(r"^\| `(?P<path>[^`]+)` \| (?P<kind>\w+) \| (?P<cls>[^|]+?) \| (?P<reason>.*?) \|$")


def read_table() -> dict[str, tuple[str, str, str]]:
    rows = {}
    text = DOC.read_text()
    body = text[text.index(HEADING) + len(HEADING):]
    for line in body.splitlines():
        m = ROW.match(line.strip())
        if m:
            rows[m["path"]] = (m["kind"], m["cls"].strip(), m["reason"].strip())
    return rows


def render(types: dict[str, tuple[str, str]], reasons: dict[str, str]) -> str:
    lines = ["| Type | Kind | Class | Why exhaustive |", "|---|---|---|---|"]
    for path in sorted(types):
        kind, cls = types[path]
        reason = reasons.get(path, "") if cls == "exhaustive" else ""
        lines.append(f"| `{path}` | {kind} | {cls} | {reason} |")
    return "\n".join(lines)


def problems(types: dict[str, tuple[str, str]], rows: dict[str, tuple[str, str, str]]) -> list[str]:
    out = []
    for path, (kind, cls) in sorted(types.items()):
        row = rows.get(path)
        if row is None:
            out.append(f"{path}: unclassified ({kind}, {cls})")
        elif row[1] != cls:
            out.append(f"{path}: listed as {row[1]}, is {cls}")
        elif cls == "exhaustive" and not row[2]:
            out.append(f"{path}: exhaustive with no reason")
    out += [f"{path}: listed but not a stable type" for path in sorted(set(rows) - set(types))]
    return out


def main() -> int:
    if len(sys.argv) != 2 or sys.argv[1] not in ("generate", "check"):
        sys.exit(__doc__)
    with tempfile.TemporaryDirectory() as tmp:
        types = current(Path(os.environ.get("API_CLASSIFICATION_TARGET_DIR", tmp)))
    rows = read_table()
    if sys.argv[1] == "generate":
        text = DOC.read_text()
        reasons = {p: r[2] for p, r in rows.items()}
        table = render(types, reasons)
        start = text.index(HEADING) + len(HEADING)
        DOC.write_text(text[:start] + "\n" + table + "\n")
        rows = read_table()
    found = problems(types, rows)
    for p in found:
        print(f"::error::{p}")
    counts = {c: sum(1 for _, cls in types.values() if cls == c) for c in CLASSES}
    print(f"{len(types)} stable types: " + ", ".join(f"{n} {c}" for c, n in counts.items())
          + f"; {len(found)} problem(s)")
    return 1 if found else 0


if __name__ == "__main__":
    sys.exit(main())
