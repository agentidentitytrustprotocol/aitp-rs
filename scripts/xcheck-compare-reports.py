#!/usr/bin/env python3
"""Compare two conformance reports fixture by fixture (RS3.2, #303).

The `xcheck` and `xcheck-ts` jobs run the same pinned fixtures through
`aitp-conformance` twice: once against `aitp-rs-adapter`, once against an
independent verifier's adapter (`aitp-verifier-py`, `aitp-verifier-ts`).
This fails unless

  * the verifier's `AITP v0.3` gate passed, and
  * every fixture has the same outcome in both reports, except the ones
    named with `--known-divergence`.

A known divergence must still diverge: when the verifier fixes one, the
entry fails the job until it is removed, so the list can only shrink.

Usage:  python3 scripts/xcheck-compare-reports.py RS_REPORT VERIFIER_REPORT \\
            [--verifier NAME] [--known-divergence ID ...]
"""

from __future__ import annotations

import argparse
import json
import sys

GATE = "AITP v0.3"


def outcomes(report: dict) -> dict[str, str]:
    return {r["id"]: r["outcome"] for r in report["results"]}


def compare(rs: dict, py: dict, known: set[str],
            name: str = "aitp-verifier-py") -> list[str]:
    """Returns one line per problem; empty means the job passes."""
    problems = []
    gates = {g["name"]: g["passed"] for g in py["gates"]}
    if not gates.get(GATE):
        problems.append(f"{name}: the {GATE!r} gate did not pass ({gates})")
    a, b = outcomes(rs), outcomes(py)
    for fid in sorted(a.keys() | b.keys()):
        ra, rb = a.get(fid, "absent"), b.get(fid, "absent")
        if ra != rb and fid not in known:
            problems.append(f"{fid}: aitp-rs {ra}, {name} {rb}")
        elif ra == rb and fid in known:
            problems.append(
                f"{fid}: listed as a known divergence but both report {ra}; "
                "remove it from --known-divergence"
            )
    return problems


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("rs_report")
    ap.add_argument("py_report", metavar="verifier_report")
    ap.add_argument("--verifier", default="aitp-verifier-py", metavar="NAME",
                    help="name used in messages (default: aitp-verifier-py)")
    ap.add_argument("--known-divergence", action="append", default=[], metavar="ID")
    args = ap.parse_args()
    with open(args.rs_report) as f:
        rs = json.load(f)
    with open(args.py_report) as f:
        py = json.load(f)
    problems = compare(rs, py, set(args.known_divergence), args.verifier)
    for p in problems:
        print(f"::error::{p}")
    totals = py["totals"]
    print(args.verifier, py["implementation"].get("version"), "totals:", totals)
    print(f"{len(outcomes(rs))} fixtures compared, "
          f"{len(args.known_divergence)} known divergence(s), {len(problems)} problem(s)")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
