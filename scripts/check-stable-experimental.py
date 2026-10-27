#!/usr/bin/env python3
"""Fail if the stable `aitp` surface names a Draft or Proposed mechanism.

  check-stable-experimental.py [SNAPSHOT]   default crates/aitp/public-api.stable.txt

Those mechanisms live in `aitp-experimental` (STABILITY.md). Each
identifier in the snapshot is split into words (at `_` and at case
changes, compared in lower case), and a line fails when an identifier
holds one of the WORDS entries as consecutive words, or when the line
holds one of the PATHS entries as a whole path segment pair. A line in
ALLOW passes as a whole.

WORDS, by RFC:
  - RFC-AITP-0013 (TCT renewal, Draft): renew, renewal
  - RFC-AITP-0010 (Session Trust Bundles, Draft): bundle
  - RFC-AITP-0002 §6 (SPIFFE, registry status Proposed): spiffe
  - RFC-AITP-0011 (multi-hop delegation, Draft): chain hash, hop limit,
    max delegation hops, hop revocation check, extending
PATHS, RFC-AITP-0011: DelegationClaims::chain, DelegationClaims::jti,
  Authority::Prior

`MultihopNotSupported` is the core RFC-AITP-0006 code and is not listed.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SNAPSHOT = ROOT / "crates" / "aitp" / "public-api.stable.txt"

WORDS: list[tuple[str, ...]] = [
    ("renew",),
    ("renewal",),
    ("bundle",),
    ("spiffe",),
    ("chain", "hash"),
    ("hop", "limit"),
    ("max", "delegation", "hops"),
    ("hop", "revocation", "check"),
    ("extending",),
]
PATHS = ["DelegationClaims::chain", "DelegationClaims::jti", "Authority::Prior"]

# Each entry: the exact snapshot line and why it may stay.
ALLOW = {
    # RFC-AITP-0002 §6.1 wire vocabulary of the identity registry.
    "pub aitp::handshake::IdentityKind::Spiffe": "identity type wire name",
    "pub aitp::handshake::identity::IdentityKind::Spiffe": "identity type wire name",
    "pub aitp::manifest::IdentityHintKind::Spiffe": "identity hint wire name",
    "pub aitp::manifest::types::IdentityHintKind::Spiffe": "identity hint wire name",
}

IDENT = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
WORD = re.compile(r"[A-Z]+(?![a-z])|[A-Z]?[a-z]+|[0-9]+")
PATH_RES = [re.compile(r"(?<![A-Za-z0-9_])" + re.escape(p) + r"(?![A-Za-z0-9_])")
            for p in PATHS]


def words(ident: str) -> list[str]:
    return [w.lower() for part in ident.split("_") for w in WORD.findall(part)]


def holds(seq: list[str], entry: tuple[str, ...]) -> bool:
    n = len(entry)
    return any(tuple(seq[i:i + n]) == entry for i in range(len(seq) - n + 1))


def reason(line: str) -> str | None:
    """The deny-list entry `line` matches, or None."""
    if line in ALLOW:
        return None
    for ident in IDENT.findall(line):
        seq = words(ident)
        for entry in WORDS:
            if holds(seq, entry):
                return " ".join(entry)
    for path, rx in zip(PATHS, PATH_RES):
        if rx.search(line):
            return path
    return None


def problems(lines: list[str]) -> list[str]:
    out = []
    for line in lines:
        hit = reason(line)
        if hit is not None:
            out.append(f"{hit!r}: {line}")
    return out


def main() -> int:
    snapshot = Path(sys.argv[1]) if len(sys.argv) > 1 else SNAPSHOT
    lines = [l for l in snapshot.read_text().splitlines()
             if l and not (l.startswith("#") and not l.startswith("#["))]
    found = problems(lines)
    for p in found:
        print(f"::error::the stable aitp surface names an experimental mechanism, {p}")
    print(f"{len(found)} experimental item(s) in the stable aitp surface")
    return 1 if found else 0


if __name__ == "__main__":
    sys.exit(main())
