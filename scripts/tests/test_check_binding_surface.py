"""Self-test for scripts/check-binding-surface.py (stdlib unittest).

Run from the repo root:  python3 -m unittest discover -s scripts/tests
"""

import importlib.util
import os
import tempfile
import unittest
from pathlib import Path

_SCRIPTS = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_spec = importlib.util.spec_from_file_location(
    "check_binding_surface", os.path.join(_SCRIPTS, "check-binding-surface.py"))
mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(mod)


class Static(unittest.TestCase):
    def test_the_committed_files_pass(self):
        self.assertEqual(mod.static_problems(), [])

    def _with_stub(self, extra):
        with tempfile.TemporaryDirectory() as d:
            stub = Path(d) / "aitp.pyi"
            stub.write_text(mod.PY_STUB.read_text() + extra)
            return mod.static_problems(py_stub=stub)

    def _with_dts(self, extra):
        with tempfile.TemporaryDirectory() as d:
            dts = Path(d) / "index.d.ts"
            dts.write_text(mod.NODE_FILES[0].read_text() + extra)
            return mod.static_problems(node_files=[dts])

    def test_an_appended_python_declaration_fails(self):
        self.assertEqual(
            self._with_stub("\ndef verify_delegation_multihop(token: str) -> None: ...\n"),
            ["aitp.pyi: verify_delegation_multihop"])

    def test_an_appended_method_fails(self):
        self.assertEqual(
            self._with_stub("\nclass X:\n    def build_renewal_request(self) -> str: ...\n"),
            ["aitp.pyi: build_renewal_request"])

    def test_a_python_comment_or_docstring_passes(self):
        self.assertEqual(
            self._with_stub('\n# SessionBundleBuilder\ndef f() -> None:\n'
                            '    """See verify_session_bundle."""\n'),
            [])

    def test_an_appended_node_declaration_fails(self):
        self.assertEqual(
            self._with_dts("\nexport declare function verifySessionBundle(a: string): void\n"),
            ["index.d.ts: verifySessionBundle"])

    def test_a_node_comment_passes(self):
        self.assertEqual(
            self._with_dts("\n/** `verifyDelegationMultihop` */\n// buildRenewalRequest\n"),
            [])

    def test_a_node_string_passes(self):
        self.assertEqual(self._with_dts("\nexport const k = 'JsBundleOutcome'\n"), [])


class Identifiers(unittest.TestCase):
    def test_denied_is_exact(self):
        self.assertEqual(mod.denied(["verify_session_bundle_x", "SessionBundleBuilder"]),
                         ["SessionBundleBuilder"])


if __name__ == "__main__":
    unittest.main()
