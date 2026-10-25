#!/usr/bin/env python3
"""Seed the fuzz corpora from the spec's conformance fixtures (RSP.1, #312).

Walks every fixture under SPEC/schemas/conformance and writes the JSON
each fuzz target parses to OUT/<target>/<fixture-id>-<n>:

  handshake_payload_decode  the `payload` of every mutual_* envelope
  oidc_verify               every `oidc` identity descriptor, and its proof
  session_bundle_verify     every `session_bundle` value, wrapped and bare
  pinned_admission          every identity_presentation envelope

Placeholders (`__VALID_ENVELOPE_SIG__`, `__JWS_TCT__`...) are left as they
are: the seeds give libFuzzer the shape of a valid input, and mutation
does the rest. Targets with no seeds source (svid_verify, tct_verify...)
start from an empty corpus, as before.

Usage:  python3 scripts/fuzz-seed-corpus.py SPEC_DIR OUT_DIR
"""

from __future__ import annotations

import glob
import json
import os
import sys

MUTUAL = {"mutual_hello", "mutual_hello_ack", "mutual_commit", "mutual_commit_ack"}


def seeds(node, out: dict[str, list[bytes]]) -> None:
    if isinstance(node, dict):
        mt = node.get("message_type")
        if mt in MUTUAL and isinstance(node.get("payload"), dict):
            out["handshake_payload_decode"].append(dump(node["payload"]))
        if mt == "identity_presentation":
            out["pinned_admission"].append(dump(node))
        if node.get("type") == "oidc":
            out["oidc_verify"].append(dump(node))
            if isinstance(node.get("proof"), str):
                out["oidc_verify"].append(node["proof"].encode())
        if set(node) == {"session_bundle"} and isinstance(node["session_bundle"], dict):
            out["session_bundle_verify"].append(dump(node))
            out["session_bundle_verify"].append(dump(node["session_bundle"]))
        for v in node.values():
            seeds(v, out)
    elif isinstance(node, list):
        for v in node:
            seeds(v, out)


def dump(v) -> bytes:
    return json.dumps(v, separators=(",", ":")).encode()


def main() -> int:
    if len(sys.argv) != 3:
        print(__doc__, file=sys.stderr)
        return 2
    spec, out_dir = sys.argv[1:]
    fixtures = sorted(glob.glob(os.path.join(spec, "schemas", "conformance", "*.json")))
    if not fixtures:
        print(f"no fixtures under {spec}/schemas/conformance", file=sys.stderr)
        return 1
    totals = {}
    for path in fixtures:
        with open(path) as f:
            fixture = json.load(f)
        found = {t: [] for t in ("handshake_payload_decode", "oidc_verify",
                                 "session_bundle_verify", "pinned_admission")}
        seeds(fixture.get("input", {}), found)
        for target, blobs in found.items():
            os.makedirs(os.path.join(out_dir, target), exist_ok=True)
            for n, blob in enumerate(dict.fromkeys(blobs)):
                with open(os.path.join(out_dir, target, f"{fixture['id']}-{n}"), "wb") as f:
                    f.write(blob)
                totals[target] = totals.get(target, 0) + 1
    for target in sorted(totals):
        print(f"{target}: {totals[target]} seeds")
    return 0


if __name__ == "__main__":
    sys.exit(main())
