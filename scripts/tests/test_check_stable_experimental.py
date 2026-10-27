"""Self-test for scripts/check-stable-experimental.py (stdlib unittest).

Run from the repo root:  python3 -m unittest discover -s scripts/tests
"""

import importlib.util
import os
import unittest

_SCRIPTS = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_spec = importlib.util.spec_from_file_location(
    "check_stable_experimental", os.path.join(_SCRIPTS, "check-stable-experimental.py"))
mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(mod)

SNAPSHOT = os.path.join(os.path.dirname(_SCRIPTS), "crates", "aitp", "public-api.stable.txt")


def snapshot_lines():
    with open(SNAPSHOT) as f:
        return [l for l in f.read().splitlines()
                if l and not (l.startswith("#") and not l.startswith("#["))]


class Problems(unittest.TestCase):
    def test_the_committed_snapshot_passes(self):
        self.assertEqual(mod.problems(snapshot_lines()), [])

    def test_each_injected_line_fails(self):
        for line in [
            "pub aitp::core::ErrorCode::BundleExpired",
            "pub aitp::core::ErrorCode::SessionBundleInvalid",
            "pub aitp::core::ErrorCode::DelegationHopLimitExceeded",
            "pub aitp::core::ErrorCode::DelegationChainHashMismatch",
            "pub mod aitp::session_bundle",
            "pub mod aitp::transport::renew_uri",
            "pub fn aitp::facade::renew_tct()",
            "pub aitp::tct::TctError::RenewalReplayed",
            "pub struct aitp::handshake::SpiffeBundleStore",
            "pub fn aitp::handshake::verify_spiffe()",
            "pub aitp::delegation::DelegationClaims::chain: core::option::Option<u8>",
            "pub aitp::delegation::DelegationClaims::jti: core::option::Option<u8>",
            "pub fn aitp::delegation::compute_chain_hash()",
            "pub const aitp::delegation::DEFAULT_MAX_DELEGATION_HOPS: usize",
            "pub type aitp::delegation::HopRevocationCheck<'a> = u8",
            "pub fn aitp::delegation::DelegationBuilder::extending()",
            "pub aitp::delegation::Authority::Prior",
        ]:
            with self.subTest(line=line):
                self.assertEqual(len(mod.problems(snapshot_lines() + [line])), 1)

    def test_allow_listed_lines_pass(self):
        self.assertEqual(mod.problems(list(mod.ALLOW)), [])

    def test_core_multihop_code_passes(self):
        lines = ["pub aitp::core::ErrorCode::DelegationMultihopNotSupported",
                 "pub aitp::delegation::DelegationError::MultihopNotSupported",
                 "pub aitp::handshake::IdentityDescriptor::svid_type: u8",
                 "pub aitp::delegation::DelegationClaims::chainless: u8"]
        self.assertEqual(mod.problems(lines), [])

    def test_words_split_on_case_and_underscores(self):
        self.assertEqual(mod.words("SessionBundleInvalid"), ["session", "bundle", "invalid"])
        self.assertEqual(mod.words("DEFAULT_MAX_DELEGATION_HOPS"),
                         ["default", "max", "delegation", "hops"])


if __name__ == "__main__":
    unittest.main()
