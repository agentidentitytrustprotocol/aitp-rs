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

OIDC identity binding (RFC-AITP-0002) gets the same treatment below. It was
the one identity-binding profile with *zero* cross-implementation coverage
of any kind before this was added -- discovered while investigating a
fail-open bug in `aitp-verifier-py`'s OIDC verifier
(agentidentitytrustprotocol/aitp-verifier-py#14): a JWT whose issuer key
could not be resolved used to verify successfully instead of failing
closed. The fix added EdDSA/ES256/RS256 issuer-key support, an
alg-confusion guard, and stricter claim checks -- none of which had ever
run against bytes `aitp-rs` actually emits on the wire. The vectors below
mint real, validly signed `aitp-rs` JWTs (EdDSA and ES256; see
`tools/mint-signed-examples/src/bin/xcheck_mint.rs` for why RS256 is out of
scope) and reuse that exact token/key material for two negatives: an
unresolvable issuer key, and a header `alg` rewritten to a different
key-type than what actually signed it.

Usage:  cargo run -p mint-signed-examples --bin xcheck-mint | \
            python3 scripts/xcheck-verify.py [--committed <path>]
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

try:
    from aitp_verifier.b64 import b64url_decode, b64url_encode
    from aitp_verifier.errors import AitpError
    from aitp_verifier.identity import verify_identity
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


def check_rejects(name: str, fn) -> bool:
    """Like `check`, but success means `fn()` raised `AitpError`."""
    try:
        fn()
    except AitpError as exc:
        print(f"  ok    {name}\n          rejected as {exc.code}")
        return True
    except Exception as exc:  # noqa: BLE001 - report any failure verbatim
        print(f"  FAIL  {name}\n          unexpected {type(exc).__name__}: {exc}")
        return False
    print(f"  FAIL  {name}\n          accepted a proof that must be rejected")
    return False


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

    # OIDC identity binding (RFC-AITP-0002). Each vector is the minimal
    # identity-descriptor + envelope shape `verify_oidc`'s own unit tests
    # build, not a full MUTUAL_HELLO envelope -- see xcheck_mint.rs for why.
    oidc = minted["oidc_identity"]
    oidc_now = int(oidc["now"]) + 100
    for alg_label in ("eddsa", "es256"):
        vec = oidc[alg_label]
        identity = {"type": "oidc", "issuer": vec["issuer"], "subject": vec["subject"], "proof": vec["proof"]}
        envelope = vec["envelope"]
        self_aid = vec["self_aid"]
        trust_anchors = [vec["issuer"]]

        ok &= check(
            f"oidc identity binding ({alg_label})",
            lambda identity=identity, envelope=envelope, self_aid=self_aid, trust_anchors=trust_anchors, vec=vec: verify_identity(
                identity,
                envelope,
                self_aid,
                trust_anchors=trust_anchors,
                trust_store=None,
                issuer_keys={vec["issuer"]: vec["issuer_jwk"]},
                now=oidc_now,
            ),
        )

        # Negative (a): withhold the issuer key entirely (simulating an
        # unresolvable key) -- reusing the identical valid token. This
        # is the exact fail-open bug aitp-verifier-py#14 fixed: a
        # well-formed, correctly signed JWT MUST NOT verify when its
        # issuer key cannot be resolved.
        #
        # We deliberately assert only that *some* AitpError is raised,
        # not a specific code. aitp-verifier-py maps this to the
        # retryable KEY_RESOLUTION_FAILED; aitp-rs's identity_oidc.rs
        # currently maps the same condition to the non-retryable
        # IDENTITY_FAILED (tracked, not yet fixed, as
        # agentidentitytrustprotocol/aitp-rs#126). Asserting the specific
        # code here would assert a cross-repo fact the two
        # implementations don't yet agree on -- which would read as
        # coverage of something it doesn't actually cover, the same
        # trap this script's module docstring warns about for a quietly
        # skipped check.
        ok &= check_rejects(
            f"oidc identity binding ({alg_label}) -- withheld issuer key is rejected",
            lambda identity=identity, envelope=envelope, self_aid=self_aid, trust_anchors=trust_anchors: verify_identity(
                identity,
                envelope,
                self_aid,
                trust_anchors=trust_anchors,
                trust_store=None,
                issuer_keys={},
                now=oidc_now,
            ),
        )

        # Negative (b): alg-confusion. Same token, same signature, but
        # the header's `alg` is rewritten to a different (still
        # allow-listed) algorithm than the key that actually signed it.
        # The resolved key's *structural* algorithm must be pinned
        # against the header, never trusted from the header alone.
        header_b64, payload_b64, sig_b64 = vec["proof"].split(".")
        header = json.loads(b64url_decode(header_b64))
        header["alg"] = "ES256" if alg_label == "eddsa" else "EdDSA"
        confused_header_b64 = b64url_encode(json.dumps(header, separators=(",", ":")).encode())
        confused_identity = dict(identity, proof=f"{confused_header_b64}.{payload_b64}.{sig_b64}")
        ok &= check_rejects(
            f"oidc identity binding ({alg_label}) -- alg-confusion header rewrite is rejected",
            lambda confused_identity=confused_identity, envelope=envelope, self_aid=self_aid, trust_anchors=trust_anchors, vec=vec: verify_identity(
                confused_identity,
                envelope,
                self_aid,
                trust_anchors=trust_anchors,
                trust_store=None,
                issuer_keys={vec["issuer"]: vec["issuer_jwk"]},
                now=oidc_now,
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
