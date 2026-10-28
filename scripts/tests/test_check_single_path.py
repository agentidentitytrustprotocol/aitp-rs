"""Self-test for scripts/check-single-path.py (stdlib unittest).

Run from the repo root:  python3 -m unittest discover -s scripts/tests
"""

import importlib.util
import os
import unittest

_SCRIPTS = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_spec = importlib.util.spec_from_file_location(
    "check_single_path", os.path.join(_SCRIPTS, "check-single-path.py"))
mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(mod)

MODULES = [
    "pub mod aitp",
    "pub mod aitp::tct",
    "pub mod aitp::tct::verifier",
    "pub mod aitp::core",
    "pub mod aitp::handshake",
]


class Duplicates(unittest.TestCase):
    def test_one_path_each_passes(self):
        lines = MODULES + [
            "pub struct aitp::tct::TctClaims",
            "impl core::marker::Send for aitp::tct::TctClaims",
            "pub aitp::tct::TctClaims::exp: aitp::core::Timestamp",
            "pub fn aitp::tct::verify_tct(&str) -> bool",
        ]
        self.assertEqual(mod.duplicates(lines), [])

    def test_a_re_exported_struct_is_caught(self):
        # cargo-public-api prints the impls and fields under one path and
        # only the definition under the re-export.
        lines = MODULES + [
            "pub struct aitp::tct::TctVerifyContext<'a>",
            "pub struct aitp::tct::verifier::TctVerifyContext<'a>",
            "impl core::marker::Send for aitp::tct::verifier::TctVerifyContext<'_>",
            "pub aitp::tct::verifier::TctVerifyContext::now: aitp::core::Timestamp",
        ]
        self.assertEqual(mod.duplicates(lines), [
            ["aitp::tct::TctVerifyContext", "aitp::tct::verifier::TctVerifyContext"]])

    def test_a_re_exported_enum_is_caught(self):
        lines = MODULES + [
            "#[non_exhaustive] pub enum aitp::tct::RevocationSource<'a>",
            "#[non_exhaustive] pub enum aitp::tct::verifier::RevocationSource<'a>",
            "pub aitp::tct::verifier::RevocationSource::FailOpen",
        ]
        self.assertEqual(len(mod.duplicates(lines)), 1)

    def test_a_re_exported_trait_is_caught(self):
        # A trait's methods are printed under every path it has.
        lines = MODULES + [
            "pub trait aitp::core::NonceStore: core::marker::Send",
            "pub trait aitp::handshake::NonceStore: core::marker::Send",
            "pub fn aitp::core::NonceStore::issue(&self) -> bool",
            "pub fn aitp::handshake::NonceStore::issue(&self) -> bool",
        ]
        self.assertEqual(mod.duplicates(lines), [
            ["aitp::core::NonceStore", "aitp::handshake::NonceStore"]])

    def test_a_fn_const_and_type_alias_at_two_paths_are_caught(self):
        lines = MODULES + [
            "pub fn aitp::tct::verify_tct(&str) -> bool",
            "pub fn aitp::tct::verifier::verify_tct(&str) -> bool",
            "pub const aitp::tct::DEFAULT_TCT_TTL: core::time::Duration",
            "pub const aitp::tct::verifier::DEFAULT_TCT_TTL: core::time::Duration",
            "pub type aitp::core::BoxError = alloc::boxed::Box<dyn core::error::Error>",
            "pub type aitp::handshake::BoxError = alloc::boxed::Box<dyn core::error::Error>",
        ]
        self.assertEqual(len(mod.duplicates(lines)), 3)

    def test_three_paths_are_one_finding(self):
        lines = MODULES + [
            "pub struct aitp::core::Aid",
            "pub struct aitp::tct::Aid",
            "pub struct aitp::handshake::Aid",
            "impl core::marker::Send for aitp::core::Aid",
        ]
        self.assertEqual(mod.duplicates(lines), [
            ["aitp::core::Aid", "aitp::handshake::Aid", "aitp::tct::Aid"]])

    def test_distinct_types_that_share_a_name_pass(self):
        lines = MODULES + [
            "pub enum aitp::tct::Error",
            "pub enum aitp::handshake::Error",
            "pub aitp::tct::Error::Expired",
            "pub aitp::handshake::Error::Refused",
        ]
        self.assertEqual(mod.duplicates(lines), [])

    def test_different_signatures_pass(self):
        lines = MODULES + [
            "pub fn aitp::tct::verify(&str) -> bool",
            "pub fn aitp::handshake::verify(&[u8]) -> bool",
            "pub const aitp::tct::MAX: usize",
            "pub const aitp::handshake::MAX: u32",
        ]
        self.assertEqual(mod.duplicates(lines), [])

    def test_methods_are_not_items(self):
        lines = MODULES + [
            "pub struct aitp::tct::A",
            "pub struct aitp::core::B",
            "pub fn aitp::tct::A::new() -> Self",
            "pub fn aitp::core::B::new() -> Self",
        ]
        self.assertEqual(mod.duplicates(lines), [])


class Sections(unittest.TestCase):
    def test_experimental_sections(self):
        text = "# header\n\n## a\npub fn aitp::x()\n\n## b\n#[non_exhaustive] pub enum aitp::E\n"
        self.assertEqual(mod.sections(text), {
            "a": ["pub fn aitp::x()"], "b": ["#[non_exhaustive] pub enum aitp::E"]})


class CommittedSnapshot(unittest.TestCase):
    def test_every_item_has_one_path(self):
        lines = mod.body(mod.STABLE.read_text())
        self.assertEqual(mod.duplicates(lines), [])
        for name, extra in mod.sections(mod.EXPERIMENTAL.read_text()).items():
            self.assertEqual(mod.duplicates(lines + extra), [], name)


if __name__ == "__main__":
    unittest.main()
