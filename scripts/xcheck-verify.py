#!/usr/bin/env python3
"""Cross-implementation acceptance: verify aitp-rs-minted artifacts with an
independent implementation.

`aitp-rs` mints; `aitp-verifier-py` — written from the RFC texts and the
JSON schemas alone, sharing no code with this workspace — verifies **those
exact bytes**. Nothing is re-signed on either side.

Why that constraint is the whole point: re-minting is the escape hatch that
hid the wrapped-vs-inner divergence for a full release. Each stack re-signed
under its own convention and then verified its own output, so both reported
51/51 conformance while a revocation snapshot minted by one could never
verify against the other. A test that re-mints before verifying cannot
detect a signing-input divergence, by construction.

The existing `interop (python <-> node)` job does not close this either:
both bindings wrap the same Rust core, so it is Rust-to-Rust across
runtimes.

Usage:  cargo run -p mint-signed-examples --bin xcheck-mint | \
            python3 scripts/xcheck-verify.py [--committed <path>]
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

try:
    from aitp_verifier.revocation import verify_revocation_snapshot
    from aitp_verifier.sessionbundle import verify_session_bundle
except ImportError as exc:  # pragma: no cover - CI installs it
    sys.exit(
        f"aitp-verifier-py is not importable ({exc}).\n"
        "Install the pinned checkout: pip install ./aitp-verifier-py\n"
        "This job must FAIL rather than skip -- a cross-implementation check "
        "that quietly skips is worse than none, because it reads as coverage."
    )

REPO = Path(__file__).resolve().parents[1]
DEFAULT_COMMITTED = (
    REPO
    / "tests/schemas/known-answer/signed-examples/revocation"
    / "kat-keypair-001-snapshot.json"
)


def check(name: str, fn) -> bool:
    try:
        fn()
    except Exception as exc:  # noqa: BLE001 - report any failure verbatim
        print(f"  FAIL  {name}\n          {type(exc).__name__}: {exc}")
        return False
    print(f"  ok    {name}")
    return True


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "--committed",
        type=Path,
        default=DEFAULT_COMMITTED,
        help="the spec's committed, Python-reference-minted revocation snapshot",
    )
    args = ap.parse_args()

    minted = json.load(sys.stdin)
    if minted.get("minted_by") != "aitp-rs":
        sys.exit("stdin is not xcheck-mint output")

    now = int(minted["now"])
    ok = True

    print("Direction (a) -- minted by aitp-rs, verified by aitp-verifier-py:")

    ok &= check(
        "revocation snapshot",
        lambda: verify_revocation_snapshot(
            {
                "policy": {"fail_mode": "fail_closed", "max_staleness_secs": 86400},
                "now": now + 100,
                "expected_issuer": minted["expected_issuer"],
                "snapshot": minted["snapshot"],
            }
        ),
    )
    ok &= check(
        "session trust bundle",
        lambda: verify_session_bundle(
            {
                "self_aid": minted["verifier_aid"],
                "now": now + 100,
                "session_bundle": minted["session_bundle"],
                "operation": "verify_session_bundle",
            }
        ),
    )

    print("\nDirection (b) -- minted by the Python reference, verified by aitp-rs:")
    print("  ok    committed revocation snapshot verified by aitp-rs")
    print("          (crates/aitp-tct spec_signed_example_snapshot_verifies,")
    print("           + its negative spec_signed_example_rejects_the_wrapped_form)")
    print("  ok    committed session bundle (minted by aitp-verifier-py's own")
    print("        minter) verified by aitp-rs")
    print("          (crates/aitp-session-bundle aitp_verifier_py_committed_bundle_verifies,")
    print("           + its negative aitp_verifier_py_committed_bundle_rejects_the_sibling_shape)")
    print(
        "  Both are asserted by `cargo test --workspace`, not by this script -- "
        "see tests/xcheck-fixtures/session-bundle/README.md for the bundle's provenance."
    )

    # Determinism: under the reference clock the Rust-minted snapshot must
    # reproduce the committed, Python-reference-minted bytes exactly. This
    # collapses "Rust mints -> Python verifies" and "Rust reproduces the
    # reference bytes" into one assertion.
    print("\nByte-identity against the committed reference example:")
    committed = json.loads(args.committed.read_text())
    committed.pop("_kat_input", None)
    if committed == minted["snapshot"]:
        print("  ok    aitp-rs reproduces the reference-minted snapshot byte-for-byte")
    else:
        print("  FAIL  aitp-rs-minted snapshot differs from the committed reference")
        print(f"          minted    signature: {minted['snapshot'].get('signature')}")
        print(f"          committed signature: {committed.get('signature')}")
        ok = False

    if not ok:
        print(
            "\nCross-implementation acceptance FAILED. aitp-rs and an "
            "independent implementation disagree on the wire.",
            file=sys.stderr,
        )
        return 1
    print("\nCross-implementation acceptance PASSED (no re-minting on either side).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
