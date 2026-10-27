#!/usr/bin/env python3
"""Fail if a default binding build exposes an experimental symbol.

  check-binding-surface.py static
      aitp.pyi, index.d.ts and index.js must not declare a DENY name.
  check-binding-surface.py runtime --python [PYTHON]
      the installed `aitp` module and `aitp.AitpAgent` must have no DENY
      name. PYTHON defaults to this interpreter.
  check-binding-surface.py runtime --node [ADDON ...]
      each native addon, loaded directly, and its `AitpAgent.prototype`
      must have no DENY name. ADDON defaults to every
      bindings/aitp-node/aitp.*.node.

The experimental symbols are behind the bindings' `experimental-*` Cargo
features, which the default build leaves off (STABILITY.md). The static
mode matches identifiers only: comments and string literals are ignored.
The Node runtime mode loads the `.node` file, not `index.js`, because
`index.js` re-exports by name and would hide an export it does not list.
"""

from __future__ import annotations

import glob
import io
import json
import re
import subprocess
import sys
import tokenize
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PY_STUB = ROOT / "bindings" / "aitp-py" / "aitp.pyi"
NODE_DIR = ROOT / "bindings" / "aitp-node"
NODE_FILES = [NODE_DIR / "index.d.ts", NODE_DIR / "index.js"]

DENY = [
    # Python
    "build_renewal_request",
    "process_renewal_request",
    "SessionBundleBuilder",
    "verify_session_bundle",
    "verify_delegation_multihop",
    # Node
    "buildRenewalRequest",
    "processRenewalRequest",
    "verifySessionBundle",
    "verifyDelegationMultihop",
    "JsBundleOutcome",
    "SessionBundleBuilderJs",
]

JS_COMMENT = re.compile(r"/\*.*?\*/|//[^\n]*", re.S)
JS_STRING = re.compile(r"'(?:\\.|[^'\\\n])*'|\"(?:\\.|[^\"\\\n])*\"|`(?:\\.|[^`\\])*`")
IDENT = re.compile(r"[A-Za-z_$][A-Za-z0-9_$]*")


def python_identifiers(source: str) -> set[str]:
    toks = tokenize.generate_tokens(io.StringIO(source).readline)
    return {t.string for t in toks if t.type == tokenize.NAME}


def js_identifiers(source: str) -> set[str]:
    return set(IDENT.findall(JS_STRING.sub("", JS_COMMENT.sub("", source))))


def denied(names) -> list[str]:
    return sorted(set(names) & set(DENY))


def static_problems(py_stub: Path = PY_STUB, node_files=NODE_FILES) -> list[str]:
    out = [f"{py_stub.name}: {n}" for n in denied(python_identifiers(py_stub.read_text()))]
    for f in node_files:
        out += [f"{f.name}: {n}" for n in denied(js_identifiers(f.read_text()))]
    return out


PY_PROBE = "import json, aitp; print(json.dumps(dir(aitp) + dir(aitp.AitpAgent)))"
NODE_PROBE = (
    "const m = require(process.argv[1]);"
    "const n = Object.keys(m);"
    "if (m.AitpAgent) n.push(...Object.getOwnPropertyNames(m.AitpAgent.prototype));"
    "console.log(JSON.stringify(n));"
)


def probe(cmd: list[str]) -> list[str]:
    return json.loads(subprocess.run(cmd, check=True, capture_output=True, text=True).stdout)


def runtime_problems(args: list[str]) -> list[str]:
    if not args or args[0] not in ("--python", "--node"):
        raise SystemExit("runtime needs --python [PYTHON] or --node [ADDON ...]")
    if args[0] == "--python":
        python = args[1] if len(args) > 1 else sys.executable
        return [f"aitp: {n}" for n in denied(probe([python, "-c", PY_PROBE]))]
    addons = args[1:] or sorted(glob.glob(str(NODE_DIR / "aitp.*.node")))
    if not addons:
        raise SystemExit(f"no aitp.*.node in {NODE_DIR}")
    out = []
    for addon in addons:
        path = str(Path(addon).resolve())
        out += [f"{Path(addon).name}: {n}" for n in denied(probe(["node", "-e", NODE_PROBE, path]))]
    return out


def main(argv: list[str]) -> int:
    if not argv or argv[0] not in ("static", "runtime"):
        print(__doc__, file=sys.stderr)
        return 2
    found = static_problems() if argv[0] == "static" else runtime_problems(argv[1:])
    for p in found:
        print(f"::error::the default binding build exposes an experimental symbol, {p}")
    print(f"{len(found)} experimental symbol(s) in the default binding surface")
    return 1 if found else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
