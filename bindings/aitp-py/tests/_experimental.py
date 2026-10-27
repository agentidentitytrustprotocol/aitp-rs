"""Which experimental features this build has.

The default build has none. The experimental CI job builds with
`--features experimental` and sets `AITP_EXPECT_EXPERIMENTAL=1`; then a
missing feature fails the importing test module instead of skipping its
tests.
"""

import os

import aitp

EXPECT = os.environ.get("AITP_EXPECT_EXPERIMENTAL") == "1"


def _present(ok: bool, feature: str) -> bool:
    if EXPECT and not ok:
        raise RuntimeError(f"AITP_EXPECT_EXPERIMENTAL=1 but this build lacks {feature}")
    return ok


HAS_RENEWAL = _present(hasattr(aitp.AitpAgent, "build_renewal_request"), "experimental-renewal")
HAS_BUNDLE = _present(hasattr(aitp, "SessionBundleBuilder"), "experimental-session-bundle")
HAS_MULTIHOP = _present(
    hasattr(aitp, "verify_delegation_multihop"), "experimental-multihop-delegation"
)
