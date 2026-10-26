"""Self-test for scripts/public-api.py (stdlib unittest).

Run from the repo root:  python3 -m unittest discover -s scripts/tests
"""

import importlib.util
import os
import unittest

_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                     "public-api.py")
_spec = importlib.util.spec_from_file_location("public_api", _PATH)
mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(mod)

BASE = [
    "pub struct aitp::tct::TctClaims",
    "pub aitp::tct::TctClaims::exp: aitp::core::Timestamp",
    "#[non_exhaustive] pub struct aitp::tct::TctVerifyContext<'a>",
    "pub aitp::tct::TctVerifyContext::now: aitp::core::Timestamp",
    "pub enum aitp::crypto::JwsAlgorithm",
    "pub aitp::crypto::JwsAlgorithm::EdDsa",
    "#[non_exhaustive] pub enum aitp::tct::TctError",
    "pub aitp::tct::TctError::Expired",
    "pub enum aitp::delegation::Outcome",
    "pub aitp::delegation::Outcome::Clear",
    "pub aitp::delegation::Outcome::Clear::active: usize",
    "impl aitp::tct::TctClaims",
    "pub fn aitp::tct::TctClaims::is_expired(&self, aitp::core::Timestamp) -> bool",
    "pub use aitp::tct::TctClaims",
]


class PrimaryPath(unittest.TestCase):
    def test_kinds(self):
        cases = {
            "pub struct aitp_tct::types::TctClaims": "aitp_tct::types::TctClaims",
            "#[non_exhaustive] pub enum aitp_tct::TctError": "aitp_tct::TctError",
            "pub aitp_tct::TctClaims::exp: aitp_core::time::Timestamp": "aitp_tct::TctClaims::exp",
            "pub aitp_x::E::V(alloc::string::String)": "aitp_x::E::V",
            "pub const fn aitp_x::f() -> u8": "aitp_x::f",
            "pub const aitp_x::N: &str": "aitp_x::N",
            "pub async fn aitp_tct::TctBuilder<'a, (dyn aitp_crypto::A + 'a)>::issue(self)":
                "aitp_tct::TctBuilder::issue",
            "impl<'a, S: ?core::marker::Sized> aitp_tct::builder::TctBuilder<'a, S>":
                "aitp_tct::builder::TctBuilder",
            "impl core::fmt::Debug for aitp_tct::AttestationVerifyContext<'_>":
                "aitp_tct::AttestationVerifyContext",
            "pub use aitp::tct::TctClaims": "aitp::tct::TctClaims",
        }
        for line, want in cases.items():
            self.assertEqual(mod.primary_path(line), want, line)

    def test_rewrite_maps_the_longest_known_prefix(self):
        mapping = {"aitp_tct::types::TctClaims": "aitp::tct::TctClaims",
                   "aitp_core::time::Timestamp": "aitp::core::Timestamp"}
        line = "pub aitp_tct::types::TctClaims::exp: aitp_core::time::Timestamp"
        self.assertEqual(mod.rewrite(line, mapping), "pub aitp::tct::TctClaims::exp: aitp::core::Timestamp")
        self.assertEqual(mod.rewrite("pub aitp_core::Other", mapping), "pub aitp_core::Other")


class Breaks(unittest.TestCase):
    def test_identical_and_additive_pass(self):
        head = BASE + [
            "pub fn aitp::tct::TctClaims::is_fresh(&self) -> bool",
            "pub aitp::tct::TctVerifyContext::leeway: i64",
            "pub aitp::tct::TctError::Revoked",
            "pub struct aitp::tct::New",
            "pub aitp::tct::New::x: u8",
        ]
        self.assertEqual(mod.find_breaks(BASE, BASE), [])
        self.assertEqual(mod.find_breaks(BASE, head), [])

    def test_a_removed_reexport_breaks(self):
        head = [l for l in BASE if l != "pub use aitp::tct::TctClaims"]
        self.assertEqual(mod.find_breaks(BASE, head), ["removed or changed: pub use aitp::tct::TctClaims"])

    def test_a_changed_field_type_breaks(self):
        head = [l.replace("exp: aitp::core::Timestamp", "exp: i64") for l in BASE]
        self.assertEqual(mod.find_breaks(BASE, head),
                         ["removed or changed: pub aitp::tct::TctClaims::exp: aitp::core::Timestamp"])

    def test_a_field_added_to_an_exhaustive_struct_breaks(self):
        problems = mod.find_breaks(BASE, BASE + ["pub aitp::tct::TctClaims::nbf: u64"])
        self.assertEqual(len(problems), 1)
        self.assertIn("exhaustive struct aitp::tct::TctClaims", problems[0])

    def test_a_variant_added_to_an_exhaustive_enum_breaks(self):
        problems = mod.find_breaks(BASE, BASE + ["pub aitp::crypto::JwsAlgorithm::Es256"])
        self.assertEqual(len(problems), 1)
        self.assertIn("exhaustive enum aitp::crypto::JwsAlgorithm", problems[0])

    def test_a_field_added_to_a_variant_of_an_exhaustive_enum_breaks(self):
        problems = mod.find_breaks(BASE, BASE + ["pub aitp::delegation::Outcome::Clear::dropped: usize"])
        self.assertEqual(len(problems), 1)
        self.assertIn("exhaustive enum aitp::delegation::Outcome", problems[0])

    def test_making_a_type_non_exhaustive_breaks(self):
        head = [l.replace("pub enum aitp::crypto::JwsAlgorithm", "#[non_exhaustive] pub enum aitp::crypto::JwsAlgorithm")
                for l in BASE]
        self.assertEqual(mod.find_breaks(BASE, head),
                         ["removed or changed: pub enum aitp::crypto::JwsAlgorithm"])

    def test_header_comments_are_ignored(self):
        self.assertEqual(mod.body("# generated\npub struct aitp::X\n\n"), ["pub struct aitp::X"])


if __name__ == "__main__":
    unittest.main()
