"""Self-test for scripts/check-stable-deps.py (stdlib unittest).

Run from the repo root:  python3 -m unittest discover -s scripts/tests
"""

import importlib.util
import os
import unittest

_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                     "check-stable-deps.py")
_spec = importlib.util.spec_from_file_location("check_stable_deps", _PATH)
mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(mod)

VERSIONS = {"url": {"2.5.8"}, "axum": {"0.8.9"}, "http": {"0.2.12", "1.5.0"}}


class Problems(unittest.TestCase):
    def test_std_and_1x_crates_pass(self):
        lines = ["pub fn aitp::x::f(&url::Url) -> core::option::Option<alloc::string::String>"]
        self.assertEqual(mod.problems(lines, VERSIONS), [])

    def test_a_pre_1_0_crate_fails(self):
        found = mod.problems(["pub fn aitp::x::r(self) -> axum::routing::Router"], VERSIONS)
        self.assertEqual(len(found), 1)
        self.assertTrue(found[0].startswith("axum 0.8.9 is pre-1.0"), found[0])

    def test_a_crate_with_a_0_x_version_anywhere_in_the_graph_fails(self):
        found = mod.problems(["pub fn aitp::x::h(&http::header::map::HeaderMap)"], VERSIONS)
        self.assertEqual(len(found), 1)

    def test_an_unknown_crate_fails(self):
        found = mod.problems(["pub fn aitp::x::t() -> tower::ServiceBuilder"], VERSIONS)
        self.assertEqual(len(found), 1)
        self.assertIn("not a dependency of aitp", found[0])

    def test_only_the_first_segment_is_a_crate(self):
        lines = ["pub enum aitp::transport::client::FetchError",
                 "impl core::ops::deref::Deref for aitp::core::CheckedJson"]
        self.assertEqual(mod.problems(lines, VERSIONS), [])

    def test_a_crate_is_reported_once(self):
        lines = ["pub fn aitp::a() -> axum::Router", "pub fn aitp::b() -> axum::Router"]
        self.assertEqual(len(mod.problems(lines, VERSIONS)), 1)


if __name__ == "__main__":
    unittest.main()
